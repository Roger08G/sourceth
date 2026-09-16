from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from . import __version__
from .adapters.cast import CastAdapter, CastAdapterMetrics, CastCapabilities, DownloadAttempt
from .adapters.process import ProcessRunner, ProcessRunnerProtocol
from .config import NetworkConfig, SourcethConfig
from .errors import ConfigurationError, ErrorCode, OutputSafetyError, SourcethError
from .manifest import ManifestContext, build_manifest, serialize_manifest
from .models import (
    BlockObservation,
    CodeValidationStatus,
    ContractResult,
    ContractRole,
    Diagnostic,
    DownloadRequest,
    DownloadResult,
    FileDigest,
    OverallStatus,
    ProxyRelation,
    ProxyResolutionStatus,
    RunMetrics,
    SourceStatus,
    ValidatedAddress,
    ValidationMode,
)
from .proxy import ProxyResolutionResult, ProxyResolver, ResolvedContract
from .store import CacheHit, RevisionStore, RunWorkspace
from .validation import runtime_bytecode_keccak, validate_request


class CastClient(Protocol):
    """Superficie inyectable que utiliza el servicio."""

    @property
    def metrics(self) -> CastAdapterMetrics: ...

    def check_capabilities(
        self,
        commands: tuple[str, ...] = (),
        *,
        refresh: bool = False,
    ) -> CastCapabilities: ...

    def assert_chain_id(self, expected_chain_id: int | str) -> int: ...

    def observe_block(self, block: int | str = "latest") -> BlockObservation: ...

    def verify_block_unchanged(self, observation: BlockObservation) -> BlockObservation: ...

    def get_code(
        self,
        address: str,
        block: BlockObservation | int | str,
    ) -> str: ...

    def get_storage_at(
        self,
        address: str,
        slot: str | int,
        block: BlockObservation | int | str,
    ) -> str: ...

    def eth_call(
        self,
        address: str,
        calldata: str,
        block: BlockObservation | int | str,
    ) -> str: ...

    def download_source(
        self,
        address: str,
        chain_id: int | str,
        directory: str | Path,
        *,
        timeout: float | None = None,
    ) -> DownloadAttempt: ...


class StoreFactory(Protocol):
    def __call__(self, output_directory: Path, config: SourcethConfig) -> RevisionStore: ...


class ResolverFactory(Protocol):
    def __call__(
        self,
        adapter: CastClient,
        max_depth: int,
        max_addresses: int,
    ) -> ProxyResolver: ...


@dataclass(slots=True)
class _ContractWork:
    address: str
    checksum_address: str
    role: ContractRole
    runtime_bytecode: str | None
    code_status: CodeValidationStatus
    proxy_status: ProxyResolutionStatus
    warnings: list[Diagnostic]
    errors: list[Diagnostic]
    roles: tuple[ContractRole, ...] = ()


@dataclass(frozen=True, slots=True)
class _PendingCache:
    address: str
    source_directory: Path
    fetched_at: datetime
    runtime_hash: str | None


def _default_store(output_directory: Path, config: SourcethConfig) -> RevisionStore:
    return RevisionStore(output_directory, config.limits)


def _default_resolver(
    adapter: CastClient,
    max_depth: int,
    max_addresses: int,
) -> ProxyResolver:
    return ProxyResolver(adapter, max_depth=max_depth, max_addresses=max_addresses)


class SourceDownloader:
    """API pública para obtener una revisión de fuentes de una dirección."""

    def __init__(
        self,
        config: SourcethConfig,
        *,
        runner: ProcessRunnerProtocol | None = None,
        cast_adapter: CastClient | None = None,
        store_factory: StoreFactory = _default_store,
        resolver_factory: ResolverFactory = _default_resolver,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic
        self._store_factory = store_factory
        self._resolver_factory = resolver_factory
        if cast_adapter is not None:
            self._cast = cast_adapter
        else:
            process_runner = runner or ProcessRunner(
                timeout=config.process_timeout_seconds,
                max_stdout_bytes=config.limits.max_output_bytes,
                max_stderr_bytes=config.limits.max_output_bytes,
            )
            self._cast = CastAdapter.from_config(process_runner, config)

    def fetch(self, request: DownloadRequest) -> DownloadResult:
        """Ejecuta la solicitud o eleva un error tipado previo a la operación."""

        validated = validate_request(request)
        network = self._network(request.chain_id)
        self._require_credentials(request.validation_mode)
        started_at = self._now()
        started_monotonic = self._monotonic()
        durations: dict[str, float] = {}
        metrics_before = self._cast.metrics

        stage_started = self._monotonic()
        commands = ("rpc",) if request.validation_mode is ValidationMode.RPC else ()
        capabilities = self._cast.check_capabilities(commands, refresh=True)
        durations["capability_check"] = self._elapsed(stage_started)

        store = self._store_factory(request.output_path, self.config)
        workspace = store.create_workspace(request.chain_id, validated.canonical, now=started_at)
        published = False
        try:
            result = self._execute(
                request=request,
                validated=validated,
                provider=network.provider,
                provider_identity=network.provider_identity_sha256,
                provider_api_url=network.explorer_api_url,
                provider_browser_url=network.explorer_url,
                capabilities=capabilities,
                store=store,
                workspace=workspace,
                durations=durations,
                started_at=started_at,
                started_monotonic=started_monotonic,
                metrics_before=metrics_before,
            )
            published = True
            return result
        finally:
            if not published:
                store.discard(workspace)

    def _execute(
        self,
        *,
        request: DownloadRequest,
        validated: ValidatedAddress,
        provider: str,
        provider_identity: str,
        provider_api_url: str,
        provider_browser_url: str,
        capabilities: CastCapabilities,
        store: RevisionStore,
        workspace: RunWorkspace,
        durations: dict[str, float],
        started_at: datetime,
        started_monotonic: float,
        metrics_before: CastAdapterMetrics,
    ) -> DownloadResult:
        observed_chain_id: int | None = None
        observed_block: BlockObservation | None = None
        relations: tuple[ProxyRelation, ...] = ()
        global_warnings: list[Diagnostic] = []
        global_errors: list[Diagnostic] = []
        works: list[_ContractWork]
        validation_consistent = True

        if request.validation_mode is ValidationMode.EXPLORER:
            works = [
                _ContractWork(
                    address=validated.canonical,
                    checksum_address=validated.checksum,
                    role=ContractRole.ROOT,
                    runtime_bytecode=None,
                    code_status=CodeValidationStatus.SKIPPED,
                    proxy_status=ProxyResolutionStatus.NOT_REQUESTED,
                    warnings=(
                        [
                            Diagnostic(
                                code="CODE_VALIDATION_SKIPPED",
                                message="No se comprobó el bytecode: modo explorer_only.",
                            )
                        ]
                    ),
                    errors=[],
                )
            ]
        else:
            stage_started = self._monotonic()
            try:
                observed_chain_id = self._cast.assert_chain_id(request.chain_id)
                block_request = request.block if request.block is not None else "latest"
                observed_block = self._cast.observe_block(block_request)
                if request.follow_proxy:
                    resolution = self._resolver_factory(
                        self._cast,
                        request.max_depth or self.config.proxy_max_depth,
                        self.config.proxy_max_addresses,
                    ).resolve(validated.canonical, observed_block)
                    works = self._works_from_resolution(resolution)
                    relations = resolution.relations
                    if resolution.status in {
                        ProxyResolutionStatus.PARTIAL,
                        ProxyResolutionStatus.FAILED,
                        ProxyResolutionStatus.CYCLE,
                        ProxyResolutionStatus.LIMIT_REACHED,
                    }:
                        global_warnings.append(
                            Diagnostic(
                                code=resolution.status.value.upper(),
                                message="La resolución de proxy no pudo completarse por entero.",
                            )
                        )
                else:
                    works = [self._direct_rpc_work(validated, observed_block, global_errors)]
            except SourcethError as error:
                if error.code is ErrorCode.CHAIN_MISMATCH:
                    mismatch_chain_id = error.details.get("observed_chain_id")
                    if isinstance(mismatch_chain_id, int) and not isinstance(
                        mismatch_chain_id, bool
                    ):
                        observed_chain_id = mismatch_chain_id
                validation_consistent = False
                global_errors.append(self._diagnostic(error))
                works = [
                    _ContractWork(
                        address=validated.canonical,
                        checksum_address=validated.checksum,
                        role=ContractRole.ROOT,
                        runtime_bytecode=None,
                        code_status=(
                            CodeValidationStatus.NO_CODE
                            if error.code is ErrorCode.NO_CODE_AT_BLOCK
                            else CodeValidationStatus.FAILED
                        ),
                        proxy_status=(
                            ProxyResolutionStatus.FAILED
                            if request.follow_proxy
                            else ProxyResolutionStatus.NOT_REQUESTED
                        ),
                        warnings=[],
                        errors=[self._diagnostic(error)],
                    )
                ]
            durations["rpc_and_proxy"] = self._elapsed(stage_started)

        stage_started = self._monotonic()
        contract_results: list[ContractResult] = []
        pending_cache: list[_PendingCache] = []
        for work in works:
            contract, pending = self._process_contract(
                request=request,
                provider=provider,
                provider_identity=provider_identity,
                work=work,
                store=store,
                workspace=workspace,
            )
            contract_results.append(contract)
            if pending is not None:
                pending_cache.append(pending)
        durations["source_downloads"] = self._elapsed(stage_started)

        if observed_block is not None and validation_consistent:
            stage_started = self._monotonic()
            try:
                self._cast.verify_block_unchanged(observed_block)
            except SourcethError as error:
                validation_consistent = False
                global_errors.append(self._diagnostic(error))
            durations["block_consistency_check"] = self._elapsed(stage_started)

        if validation_consistent:
            for pending in pending_cache:
                try:
                    store.cache_store(
                        provider=provider,
                        provider_identity=provider_identity,
                        chain_id=request.chain_id,
                        address=pending.address,
                        source_directory=pending.source_directory,
                        provider_fetched_at=pending.fetched_at,
                        runtime_bytecode_keccak=pending.runtime_hash,
                    )
                except SourcethError as error:
                    global_warnings.append(
                        Diagnostic(
                            code=error.code.value,
                            message="La descarga es válida, pero no pudo guardarse en caché.",
                        )
                    )

        status = self._overall_status(
            contract_results,
            validation_consistent=validation_consistent,
            proxy_requested=request.follow_proxy,
        )
        completed_at = self._now()
        adapter_metrics = self._cast.metrics
        metrics = RunMetrics(
            cast_invocations=max(
                0,
                adapter_metrics.cast_invocations - metrics_before.cast_invocations,
            ),
            adapter_attempts=max(
                0,
                adapter_metrics.adapter_attempts - metrics_before.adapter_attempts,
            ),
            cache_downloads_avoided=sum(
                1 for contract in contract_results if contract.cache_reused
            ),
            files_stored=sum(len(contract.files) for contract in contract_results),
            bytes_stored=sum(
                file.size_bytes for contract in contract_results for file in contract.files
            ),
            stage_durations_seconds={
                **durations,
                "total_before_publication": max(0.0, self._monotonic() - started_monotonic),
            },
        )
        final_directory = workspace.final_directory
        result = DownloadResult(
            status=status,
            request=request,
            root_address=validated.canonical,
            checksum_address=validated.checksum,
            run_id=workspace.run_id,
            run_directory=final_directory,
            manifest_path=final_directory / "manifest.json",
            observed_chain_id=observed_chain_id,
            observed_block=observed_block,
            contracts=tuple(contract_results),
            relations=relations,
            metrics=metrics,
            warnings=tuple(global_warnings),
            errors=tuple(global_errors),
        )
        context = ManifestContext(
            tool_version=__version__,
            cast_version=capabilities.version,
            provider=provider,
            provider_identity_sha256=provider_identity,
            provider_api_url=provider_api_url,
            provider_browser_url=provider_browser_url,
            started_at=started_at,
            completed_at=completed_at,
            validation_skip_reason=(
                "explorer_only" if request.validation_mode is ValidationMode.EXPLORER else None
            ),
            effective_proxy_max_depth=(
                (request.max_depth or self.config.proxy_max_depth) if request.follow_proxy else None
            ),
            effective_proxy_max_addresses=(
                self.config.proxy_max_addresses if request.follow_proxy else None
            ),
        )
        manifest = build_manifest(result, context)
        store.publish(
            workspace,
            serialize_manifest(manifest),
            status,
            completed_at=completed_at,
        )
        return result

    def _direct_rpc_work(
        self,
        address: ValidatedAddress,
        block: BlockObservation,
        global_errors: list[Diagnostic],
    ) -> _ContractWork:
        try:
            runtime = self._cast.get_code(address.canonical, block)
            return _ContractWork(
                address=address.canonical,
                checksum_address=address.checksum,
                role=ContractRole.ROOT,
                runtime_bytecode=runtime,
                code_status=CodeValidationStatus.PRESENT,
                proxy_status=ProxyResolutionStatus.NOT_REQUESTED,
                warnings=[],
                errors=[],
            )
        except SourcethError as error:
            diagnostic = self._diagnostic(error)
            global_errors.append(diagnostic)
            return _ContractWork(
                address=address.canonical,
                checksum_address=address.checksum,
                role=ContractRole.ROOT,
                runtime_bytecode=None,
                code_status=(
                    CodeValidationStatus.NO_CODE
                    if error.code is ErrorCode.NO_CODE_AT_BLOCK
                    else CodeValidationStatus.FAILED
                ),
                proxy_status=ProxyResolutionStatus.NOT_REQUESTED,
                warnings=[],
                errors=[diagnostic],
            )

    def _works_from_resolution(
        self,
        resolution: ProxyResolutionResult,
    ) -> list[_ContractWork]:
        return [
            _ContractWork(
                address=contract.address,
                checksum_address=contract.checksum_address,
                role=contract.role,
                roles=contract.roles,
                runtime_bytecode=contract.runtime_bytecode,
                code_status=contract.code_validation_status,
                proxy_status=self._contract_proxy_status(contract, resolution),
                warnings=[
                    item for item in contract.diagnostics if self._is_warning_diagnostic(item)
                ],
                errors=[
                    item for item in contract.diagnostics if not self._is_warning_diagnostic(item)
                ],
            )
            for contract in resolution.contracts
        ]

    @staticmethod
    def _contract_proxy_status(
        contract: ResolvedContract,
        resolution: ProxyResolutionResult,
    ) -> ProxyResolutionStatus:
        codes = {item.code for item in contract.diagnostics}
        if ErrorCode.PROXY_CYCLE.value in codes:
            return ProxyResolutionStatus.CYCLE
        if ErrorCode.PROXY_LIMIT_REACHED.value in codes:
            return ProxyResolutionStatus.LIMIT_REACHED
        if contract.address == resolution.root_address and resolution.status in {
            ProxyResolutionStatus.PARTIAL,
            ProxyResolutionStatus.FAILED,
            ProxyResolutionStatus.CYCLE,
            ProxyResolutionStatus.LIMIT_REACHED,
        }:
            return resolution.status
        if any(not SourceDownloader._is_warning_diagnostic(item) for item in contract.diagnostics):
            return ProxyResolutionStatus.FAILED
        if any(relation.source_address == contract.address for relation in resolution.relations):
            return ProxyResolutionStatus.RESOLVED
        if "NO_SUPPORTED_PATTERN_DETECTED" in codes:
            return ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED
        if contract.code_validation_status is not CodeValidationStatus.PRESENT:
            return ProxyResolutionStatus.FAILED
        return ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED

    def _process_contract(
        self,
        *,
        request: DownloadRequest,
        provider: str,
        provider_identity: str,
        work: _ContractWork,
        store: RevisionStore,
        workspace: RunWorkspace,
    ) -> tuple[ContractResult, _PendingCache | None]:
        runtime_hash: str | None = None
        runtime_path: str | None = None
        if work.runtime_bytecode is not None:
            runtime_hash = runtime_bytecode_keccak(work.runtime_bytecode)
            runtime_path = store.write_runtime_bytecode(
                workspace,
                work.address,
                work.runtime_bytecode,
            )

        if work.code_status in {CodeValidationStatus.NO_CODE, CodeValidationStatus.FAILED}:
            return (
                ContractResult(
                    address=work.address,
                    checksum_address=work.checksum_address,
                    role=work.role,
                    roles=work.roles,
                    source_status=SourceStatus.NOT_ATTEMPTED,
                    code_validation_status=work.code_status,
                    proxy_resolution_status=work.proxy_status,
                    runtime_bytecode_keccak=runtime_hash,
                    runtime_bytecode_path=runtime_path,
                    warnings=tuple(work.warnings),
                    errors=tuple(work.errors),
                ),
                None,
            )

        source_directory = store.prepare_contract(workspace, work.address)
        cache_hit: CacheHit | None = None
        if not request.refresh:
            cache_hit = store.cache_lookup(
                provider=provider,
                provider_identity=provider_identity,
                chain_id=request.chain_id,
                address=work.address,
                ttl_seconds=self.config.cache_ttl_seconds,
                expected_runtime_bytecode_keccak=runtime_hash,
                now=self._now(),
            )
        if cache_hit is not None:
            try:
                files = store.cache_restore(cache_hit, source_directory)
            except OutputSafetyError as error:
                if error.code is not ErrorCode.INVALID_PROVIDER_OUTPUT:
                    raise
                source_directory = store.reset_contract_sources(workspace, work.address)
                work.warnings.append(self._diagnostic(error))
            else:
                return (
                    self._successful_contract(
                        work,
                        files,
                        workspace,
                        runtime_hash,
                        runtime_path,
                        SourceStatus.REUSED,
                        fetched_at=cache_hit.fetched_at,
                        cache_reused=True,
                        download_attempts=0,
                        download_duration_seconds=0.0,
                    ),
                    None,
                )

        attempts_before = self._cast.metrics.adapter_attempts
        download_started = self._monotonic()
        try:
            download_attempt = self._cast.download_source(
                work.checksum_address,
                request.chain_id,
                source_directory,
                timeout=request.timeout,
            )
            files = store.inspect_sources(source_directory)
            fetched_at = self._now()
            contract = self._successful_contract(
                work,
                files,
                workspace,
                runtime_hash,
                runtime_path,
                SourceStatus.DOWNLOADED,
                fetched_at=fetched_at,
                cache_reused=False,
                download_attempts=download_attempt.attempts,
                download_duration_seconds=download_attempt.duration_seconds,
            )
            return (
                contract,
                _PendingCache(
                    address=work.address,
                    source_directory=source_directory,
                    fetched_at=fetched_at,
                    runtime_hash=runtime_hash,
                ),
            )
        except SourcethError as error:
            store.reset_contract_sources(workspace, work.address)
            diagnostic = self._diagnostic(error)
            source_status = (
                SourceStatus.NOT_VERIFIED
                if error.code is ErrorCode.SOURCE_NOT_VERIFIED
                else SourceStatus.FAILED
            )
            return (
                ContractResult(
                    address=work.address,
                    checksum_address=work.checksum_address,
                    role=work.role,
                    roles=work.roles,
                    source_status=source_status,
                    code_validation_status=work.code_status,
                    proxy_resolution_status=work.proxy_status,
                    runtime_bytecode_keccak=runtime_hash,
                    runtime_bytecode_path=runtime_path,
                    download_attempts=max(
                        0,
                        self._cast.metrics.adapter_attempts - attempts_before,
                    ),
                    download_duration_seconds=self._elapsed(download_started),
                    warnings=tuple(work.warnings),
                    errors=(*work.errors, diagnostic),
                ),
                None,
            )

    @staticmethod
    def _successful_contract(
        work: _ContractWork,
        files: tuple[FileDigest, ...],
        workspace: RunWorkspace,
        runtime_hash: str | None,
        runtime_path: str | None,
        source_status: SourceStatus,
        *,
        fetched_at: datetime,
        cache_reused: bool,
        download_attempts: int,
        download_duration_seconds: float,
    ) -> ContractResult:
        prefixed_files = tuple(
            replace(
                file,
                relative_path=(
                    Path("contracts") / work.address / "sources" / Path(file.relative_path)
                ).as_posix(),
            )
            for file in files
        )
        del workspace  # El prefijo del manifiesto es estable e independiente de la ruta absoluta.
        return ContractResult(
            address=work.address,
            checksum_address=work.checksum_address,
            role=work.role,
            roles=work.roles,
            source_status=source_status,
            code_validation_status=work.code_status,
            proxy_resolution_status=work.proxy_status,
            runtime_bytecode_keccak=runtime_hash,
            runtime_bytecode_path=runtime_path,
            files=prefixed_files,
            cache_reused=cache_reused,
            provider_fetched_at=fetched_at,
            download_attempts=download_attempts,
            download_duration_seconds=download_duration_seconds,
            warnings=tuple(work.warnings),
            errors=tuple(work.errors),
        )

    @staticmethod
    def _overall_status(
        contracts: list[ContractResult],
        *,
        validation_consistent: bool,
        proxy_requested: bool,
    ) -> OverallStatus:
        successful = sum(
            item.source_status in {SourceStatus.DOWNLOADED, SourceStatus.REUSED}
            for item in contracts
        )
        eligible = sum(
            item.code_validation_status
            in {CodeValidationStatus.PRESENT, CodeValidationStatus.SKIPPED}
            for item in contracts
        )
        proxy_incomplete = proxy_requested and any(
            item.proxy_resolution_status
            in {
                ProxyResolutionStatus.PARTIAL,
                ProxyResolutionStatus.FAILED,
                ProxyResolutionStatus.CYCLE,
                ProxyResolutionStatus.LIMIT_REACHED,
            }
            for item in contracts
        )
        if (
            validation_consistent
            and not proxy_incomplete
            and eligible > 0
            and successful == eligible
        ):
            return OverallStatus.COMPLETE
        if successful > 0:
            return OverallStatus.PARTIAL
        return OverallStatus.FAILED

    def _network(self, chain_id: int) -> NetworkConfig:
        network = self.config.networks.get(chain_id)
        if network is None:
            raise SourcethError(
                ErrorCode.NETWORK_NOT_CONFIGURED,
                "La red solicitada no está registrada en Sourceth.",
                details={"chain_id": chain_id},
            )
        if network.provider.casefold() != "etherscan":
            raise SourcethError(
                ErrorCode.NETWORK_UNSUPPORTED,
                "Sourceth V1 solo admite el proveedor Etherscan configurado de forma explícita.",
                details={"chain_id": chain_id, "provider": network.provider},
            )
        return network

    def _require_credentials(self, mode: ValidationMode) -> None:
        if self.config.credentials.api_key is None:
            raise ConfigurationError(
                f"Falta {self.config.api_key_env}; configure la API key en .env o en el entorno."
            )
        if mode is ValidationMode.RPC and self.config.credentials.rpc_url is None:
            raise ConfigurationError(
                f"Falta {self.config.rpc_url_env}; configure la URL RPC en .env o en el entorno."
            )

    @staticmethod
    def _diagnostic(error: SourcethError) -> Diagnostic:
        return Diagnostic(
            code=error.code.value,
            message=error.message,
            details=error.details,
        )

    @staticmethod
    def _is_warning_diagnostic(value: Diagnostic) -> bool:
        return value.code in {
            "EIP1967_IMPLEMENTATION_SLOT_EMPTY",
            "EIP1967_BEACON_SLOT_EMPTY",
            "NO_SUPPORTED_PATTERN_DETECTED",
        }

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("clock debe devolver un datetime con zona horaria")
        return value.astimezone(UTC)

    def _elapsed(self, started: float) -> float:
        return max(0.0, self._monotonic() - started)


__all__ = ["CastClient", "SourceDownloader"]
