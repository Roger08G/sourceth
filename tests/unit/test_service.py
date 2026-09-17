"""Pruebas offline de orquestación, caché, proxies y revisiones."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest

from src.adapters.cast import CastAdapterMetrics, CastCapabilities, DownloadAttempt
from src.config import Credentials, NetworkConfig, SecretValue, SourcethConfig
from src.errors import ConfigurationError, DownloadError, ErrorCode, RpcError
from src.models import (
    BlockObservation,
    CodeValidationStatus,
    DownloadRequest,
    FileDigest,
    OverallStatus,
    ProxyResolutionStatus,
    SourceStatus,
)
from src.proxy import EIP1967_BEACON_SLOT, EIP1967_IMPLEMENTATION_SLOT
from src.service import SourceDownloader
from src.store import CacheHit, RevisionStore

ROOT = "0x" + ("1" * 40)
IMPLEMENTATION_A = "0x" + ("2" * 40)
IMPLEMENTATION_B = "0x" + ("3" * 40)
BLOCK = BlockObservation(21_000_000, "0x" + ("a" * 64))
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
ZERO_WORD = "0x" + ("0" * 64)


def _address_word(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


class FakeCast:
    """Doble completo del puerto Cast usado por el servicio."""

    def __init__(self) -> None:
        self.capability_commands: list[tuple[str, ...]] = []
        self.chain_calls: list[int] = []
        self.block_calls: list[int | str] = []
        self.verify_calls: list[BlockObservation] = []
        self.code_calls: list[tuple[str, BlockObservation | int | str]] = []
        self.storage_calls: list[tuple[str, str | int, BlockObservation | int | str]] = []
        self.eth_calls: list[tuple[str, str, BlockObservation | int | str]] = []
        self.download_calls: list[tuple[str, int, Path, float | None]] = []
        self.sources: dict[str, Mapping[str, bytes]] = {
            ROOT: {"Root.sol": b"contract Root {}\n"},
            IMPLEMENTATION_A: {"I.sol": b"contract Implementation {}\n"},
            IMPLEMENTATION_B: {"I2.sol": b"contract ImplementationV2 {}\n"},
        }
        self.download_errors: dict[str, DownloadError] = {}
        self.partial_files_before_error: dict[str, Mapping[str, bytes]] = {}
        self.code_errors: dict[str, RpcError] = {}
        self.storage_errors: dict[tuple[str, str | int], RpcError] = {}
        self.implementation_target: str | None = None
        self.block_changed = False
        self._attempts = 0

    @property
    def metrics(self) -> CastAdapterMetrics:
        return CastAdapterMetrics(
            cast_invocations=self._attempts,
            adapter_attempts=self._attempts,
            retries=0,
            process_duration_seconds=0,
            retry_sleep_seconds=0,
            invocations_by_operation={},
        )

    def check_capabilities(
        self,
        commands: tuple[str, ...] = (),
        *,
        refresh: bool = False,
    ) -> CastCapabilities:
        assert refresh
        self.capability_commands.append(commands)
        self._attempts += 2 + len(commands)
        return CastCapabilities("1.8.1", "cast 1.8.1 (fake)", ("source", *commands))

    def assert_chain_id(self, expected_chain_id: int | str) -> int:
        value = int(expected_chain_id)
        self.chain_calls.append(value)
        self._attempts += 1
        return value

    def observe_block(self, block: int | str = "latest") -> BlockObservation:
        self.block_calls.append(block)
        self._attempts += 1
        return BLOCK

    def verify_block_unchanged(self, observation: BlockObservation) -> BlockObservation:
        self.verify_calls.append(observation)
        self._attempts += 1
        if self.block_changed:
            raise RpcError(
                ErrorCode.BLOCK_CHANGED,
                "El bloque cambió durante la prueba.",
                details={"expected_hash": observation.hash, "observed_hash": "0x" + ("b" * 64)},
            )
        return observation

    def get_code(
        self,
        address: str,
        block: BlockObservation | int | str,
    ) -> str:
        self.code_calls.append((address, block))
        self._attempts += 1
        error = self.code_errors.get(address)
        if error is not None:
            raise error
        return "0x6000"

    def get_storage_at(
        self,
        address: str,
        slot: str | int,
        block: BlockObservation | int | str,
    ) -> str:
        self.storage_calls.append((address, slot, block))
        self._attempts += 1
        error = self.storage_errors.get((address, slot))
        if error is not None:
            raise error
        if (
            address == ROOT
            and slot == EIP1967_IMPLEMENTATION_SLOT
            and self.implementation_target is not None
        ):
            return _address_word(self.implementation_target)
        if slot in {EIP1967_IMPLEMENTATION_SLOT, EIP1967_BEACON_SLOT}:
            return ZERO_WORD
        raise AssertionError(f"slot inesperado: {slot}")

    def eth_call(
        self,
        address: str,
        calldata: str,
        block: BlockObservation | int | str,
    ) -> str:
        self.eth_calls.append((address, calldata, block))
        self._attempts += 1
        raise RpcError(ErrorCode.RPC_ERROR, "llamada no configurada")

    def download_source(
        self,
        address: str,
        chain_id: int | str,
        directory: str | Path,
        *,
        timeout: float | None = None,
    ) -> DownloadAttempt:
        destination = Path(directory)
        self.download_calls.append((address.lower(), int(chain_id), destination, timeout))
        self._attempts += 1
        for relative, payload in self.partial_files_before_error.get(address.lower(), {}).items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        error = self.download_errors.get(address.lower())
        if error is not None:
            raise error
        files = self.sources[address.lower()]
        for relative, payload in files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return DownloadAttempt(
            directory=destination,
            files=tuple(sorted(files)),
            file_count=len(files),
            total_bytes=sum(len(payload) for payload in files.values()),
            attempts=1,
            duration_seconds=0.25,
        )


def _config(
    output: Path,
    *,
    cache_ttl_seconds: int = 3600,
    network: NetworkConfig | None = None,
) -> SourcethConfig:
    return SourcethConfig(
        output_dir=output,
        cache_ttl_seconds=cache_ttl_seconds,
        credentials=Credentials(
            rpc_url=SecretValue("https://rpc.invalid/secret"),
            api_key=SecretValue("api-secret"),
        ),
        networks=MappingProxyType(
            {1: network or NetworkConfig(chain_id=1, name="ethereum-mainnet", provider="etherscan")}
        ),
    )


def _output(tmp_path: Path) -> Path:
    """Usa una raíz corta para que las pruebas respeten MAX_PATH en Windows."""

    suffix = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:12]
    return tmp_path.parent / f"d-{suffix}"


def _downloader(tmp_path: Path, cast: FakeCast) -> SourceDownloader:
    return SourceDownloader(
        _config(_output(tmp_path)),
        cast_adapter=cast,
        clock=lambda: NOW,
        monotonic=lambda: 1.0,
    )


def _cache_pointer(output: Path, config: SourcethConfig) -> Path:
    network = config.networks[1]
    store = RevisionStore(output, config.limits)
    return store._cache_key("etherscan", network.provider_identity_sha256, 1, ROOT) / "latest.json"


def test_direct_rpc_download_publishes_complete_revision_and_manifest(tmp_path: Path) -> None:
    cast = FakeCast()
    request = DownloadRequest(address=ROOT, output_dir=_output(tmp_path), timeout=7)

    result = _downloader(tmp_path, cast).fetch(request)

    assert result.status is OverallStatus.COMPLETE
    assert result.observed_chain_id == 1
    assert result.observed_block == BLOCK
    assert len(result.contracts) == 1
    contract = result.contracts[0]
    assert contract.source_status is SourceStatus.DOWNLOADED
    assert contract.code_validation_status is CodeValidationStatus.PRESENT
    assert contract.download_attempts == 1
    assert contract.download_duration_seconds == 0.25
    assert contract.runtime_bytecode_keccak is not None
    assert contract.files[0].relative_path == f"contracts/{ROOT}/sources/Root.sol"
    assert result.manifest_path is not None and result.manifest_path.is_file()
    assert result.run_directory is not None
    assert contract.runtime_bytecode_path == f"contracts/{ROOT}/runtime-bytecode.hex"
    assert cast.capability_commands == [("rpc",)]
    assert cast.block_calls == ["latest"]
    assert cast.verify_calls == [BLOCK]
    assert cast.download_calls[0][3] == 7


def test_chain_mismatch_preserves_observed_chain_id_in_result_and_manifest(
    tmp_path: Path,
) -> None:
    class MismatchedCast(FakeCast):
        def assert_chain_id(self, expected_chain_id: int | str) -> int:
            expected = int(expected_chain_id)
            self.chain_calls.append(expected)
            self._attempts += 1
            raise RpcError(
                ErrorCode.CHAIN_MISMATCH,
                "El RPC pertenece a otra red.",
                details={"expected_chain_id": expected, "observed_chain_id": 5},
            )

    result = _downloader(tmp_path, MismatchedCast()).fetch(
        DownloadRequest(address=ROOT, output_dir=_output(tmp_path))
    )

    assert result.status is OverallStatus.FAILED
    assert result.observed_chain_id == 5
    assert result.run_directory is not None
    manifest = json.loads((result.run_directory / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["input"]["chain_id_requested"] == 1
    assert manifest["input"]["chain_id_observed"] == 5


def test_explorer_mode_skips_all_rpc_and_records_skipped_validation(tmp_path: Path) -> None:
    cast = FakeCast()
    request = DownloadRequest(
        address=ROOT,
        output_dir=_output(tmp_path),
        validation="explorer",
    )

    result = _downloader(tmp_path, cast).fetch(request)

    assert result.status is OverallStatus.COMPLETE
    assert result.observed_chain_id is None
    assert result.observed_block is None
    assert result.contracts[0].code_validation_status is CodeValidationStatus.SKIPPED
    assert result.contracts[0].warnings[0].code == "CODE_VALIDATION_SKIPPED"
    assert cast.capability_commands == [()]
    assert not cast.chain_calls
    assert not cast.block_calls
    assert not cast.code_calls
    assert not cast.verify_calls


def test_valid_cache_is_reused_and_refresh_forces_new_revision(tmp_path: Path) -> None:
    cast = FakeCast()
    downloader = _downloader(tmp_path, cast)
    request = DownloadRequest(address=ROOT, output_dir=_output(tmp_path))

    first = downloader.fetch(request)
    second = downloader.fetch(request)
    refreshed = downloader.fetch(
        DownloadRequest(address=ROOT, output_dir=_output(tmp_path), refresh=True)
    )

    assert first.run_directory != second.run_directory != refreshed.run_directory
    assert first.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert second.contracts[0].source_status is SourceStatus.REUSED
    assert second.contracts[0].cache_reused
    assert second.contracts[0].provider_fetched_at == first.contracts[0].provider_fetched_at
    assert second.metrics.cache_downloads_avoided == 1
    assert first.metrics.cast_invocations == 8
    assert second.metrics.cast_invocations == 7
    assert refreshed.metrics.cast_invocations == 8
    assert first.metrics.adapter_attempts == 8
    assert second.metrics.adapter_attempts == 7
    assert refreshed.metrics.adapter_attempts == 8
    assert refreshed.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert len(cast.download_calls) == 2
    assert all(result.run_directory is not None for result in (first, second, refreshed))
    run_parent = first.run_directory.parent if first.run_directory is not None else Path()
    assert len([path for path in run_parent.iterdir() if path.is_dir()]) == 3


def test_cache_identity_includes_explicit_explorer_endpoints(tmp_path: Path) -> None:
    output = tmp_path.parent / f"d-{tmp_path.name[-8:]}"
    network_a = NetworkConfig(
        chain_id=1,
        name="ethereum-mainnet",
        provider="etherscan",
        explorer_api_url="https://api-a.example.invalid/tenant/FIRSTSECRET/v2",
        explorer_url="https://a.example.invalid/tenant/FIRSTSECRET",
    )
    network_b = NetworkConfig(
        chain_id=1,
        name="ethereum-mainnet",
        provider="etherscan",
        explorer_api_url="https://api-b.example.invalid/tenant/SUPERSECRET/v2",
        explorer_url="https://b.example.invalid/tenant/SUPERSECRET",
    )
    first_cast = FakeCast()
    first = SourceDownloader(
        _config(output, network=network_a),
        cast_adapter=first_cast,
        clock=lambda: NOW,
        monotonic=lambda: 1.0,
    ).fetch(DownloadRequest(address=ROOT, output_dir=output, validation="explorer"))
    assert first.contracts[0].source_status is SourceStatus.DOWNLOADED

    second_cast = FakeCast()
    second_cast.sources[ROOT] = {"Root.sol": b"contract FromSecondEndpoint {}\n"}
    second = SourceDownloader(
        _config(output, network=network_b),
        cast_adapter=second_cast,
        clock=lambda: NOW,
        monotonic=lambda: 1.0,
    ).fetch(DownloadRequest(address=ROOT, output_dir=output, validation="explorer"))

    assert second.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert len(second_cast.download_calls) == 1
    assert second.run_directory is not None
    assert (
        second.run_directory / "contracts" / ROOT / "sources" / "Root.sol"
    ).read_bytes() == b"contract FromSecondEndpoint {}\n"
    assert second.manifest_path is not None
    manifest_text = second.manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert "SUPERSECRET" not in manifest_text
    assert manifest["provider"] == {
        "api_origin": "https://api-b.example.invalid",
        "browser_origin": "https://b.example.invalid",
        "identity_sha256": network_b.provider_identity_sha256,
        "name": "etherscan",
        "secrets_persisted": False,
    }


def test_cache_change_between_lookup_and_restore_falls_back_to_provider(
    tmp_path: Path,
) -> None:
    class TamperingStore(RevisionStore):
        def cache_restore(
            self,
            hit: CacheHit,
            destination: Path,
        ) -> tuple[FileDigest, ...]:
            target = hit.entry_directory / "sources" / hit.files[0].relative_path
            original = target.read_bytes()
            target.write_bytes(b"X" + original[1:])
            return super().cache_restore(hit, destination)

    output = tmp_path.parent / f"d-{tmp_path.name[-8:]}"
    config = _config(output)
    cast = FakeCast()

    def store_factory(
        output_directory: Path,
        config: SourcethConfig,
    ) -> RevisionStore:
        return TamperingStore(output_directory, config.limits)

    downloader = SourceDownloader(
        config,
        cast_adapter=cast,
        store_factory=store_factory,
        clock=lambda: NOW,
        monotonic=lambda: 1.0,
    )
    request = DownloadRequest(address=ROOT, output_dir=output)
    downloader.fetch(request)
    cast.sources[ROOT] = {"Root.sol": b"contract Fresh {}\n"}

    second = downloader.fetch(request)

    assert second.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert not second.contracts[0].cache_reused
    assert second.metrics.cache_downloads_avoided == 0
    assert len(cast.download_calls) == 2
    assert second.contracts[0].warnings[0].code == ErrorCode.INVALID_PROVIDER_OUTPUT.value
    assert second.run_directory is not None
    assert (
        second.run_directory / "contracts" / ROOT / "sources" / "Root.sol"
    ).read_bytes() == b"contract Fresh {}\n"


def test_expired_or_corrupt_cache_is_not_reused(tmp_path: Path) -> None:
    cast = FakeCast()
    output = _output(tmp_path)
    config = _config(output, cache_ttl_seconds=1)
    downloader = SourceDownloader(
        config,
        cast_adapter=cast,
        clock=lambda: NOW,
        monotonic=lambda: 1.0,
    )
    request = DownloadRequest(address=ROOT, output_dir=output)
    downloader.fetch(request)
    cache_pointer = _cache_pointer(output, config)
    cache_pointer.write_text("not-json", encoding="utf-8")

    second = downloader.fetch(request)

    assert second.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert len(cast.download_calls) == 2


def test_block_change_after_download_publishes_partial_without_caching(tmp_path: Path) -> None:
    cast = FakeCast()
    cast.block_changed = True
    request = DownloadRequest(address=ROOT, output_dir=_output(tmp_path))

    result = _downloader(tmp_path, cast).fetch(request)

    assert result.status is OverallStatus.PARTIAL
    assert result.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert [error.code for error in result.errors] == [ErrorCode.BLOCK_CHANGED.value]
    assert result.run_directory is not None and result.run_directory.is_dir()
    cache_pointer = _cache_pointer(_output(tmp_path), _config(_output(tmp_path)))
    assert not cache_pointer.exists()


def test_no_code_is_failed_without_attempting_source_download(tmp_path: Path) -> None:
    cast = FakeCast()
    cast.code_errors[ROOT] = RpcError(ErrorCode.NO_CODE_AT_BLOCK, "sin código")

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(address=ROOT, output_dir=_output(tmp_path))
    )

    assert result.status is OverallStatus.FAILED
    assert result.contracts[0].source_status is SourceStatus.NOT_ATTEMPTED
    assert result.contracts[0].code_validation_status is CodeValidationStatus.NO_CODE
    assert not cast.download_calls


def test_proxy_implementation_is_downloaded_even_if_root_is_not_verified(
    tmp_path: Path,
) -> None:
    cast = FakeCast()
    cast.implementation_target = IMPLEMENTATION_A
    cast.download_errors[ROOT] = DownloadError(
        ErrorCode.SOURCE_NOT_VERIFIED,
        "fuentes del proxy no publicadas",
    )

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(
            address=ROOT,
            output_dir=_output(tmp_path),
            follow_proxy=True,
        )
    )

    assert result.status is OverallStatus.PARTIAL
    assert [contract.address for contract in result.contracts] == [ROOT, IMPLEMENTATION_A]
    by_address = {contract.address: contract for contract in result.contracts}
    assert by_address[ROOT].source_status is SourceStatus.NOT_VERIFIED
    assert by_address[ROOT].proxy_resolution_status is ProxyResolutionStatus.RESOLVED
    assert by_address[IMPLEMENTATION_A].source_status is SourceStatus.DOWNLOADED
    assert [call[0] for call in cast.download_calls] == [ROOT, IMPLEMENTATION_A]
    assert len(result.relations) == 1


def test_proxy_relations_are_resolved_again_even_when_sources_are_cached(
    tmp_path: Path,
) -> None:
    cast = FakeCast()
    cast.implementation_target = IMPLEMENTATION_A
    downloader = _downloader(tmp_path, cast)
    request = DownloadRequest(
        address=ROOT,
        output_dir=_output(tmp_path),
        follow_proxy=True,
    )

    first = downloader.fetch(request)
    cast.implementation_target = IMPLEMENTATION_B
    second = downloader.fetch(request)

    assert {contract.address for contract in first.contracts} == {ROOT, IMPLEMENTATION_A}
    assert {contract.address for contract in second.contracts} == {ROOT, IMPLEMENTATION_B}
    assert second.relations[0].target_address == IMPLEMENTATION_B
    second_by_address = {contract.address: contract for contract in second.contracts}
    assert second_by_address[ROOT].source_status is SourceStatus.REUSED
    assert second_by_address[IMPLEMENTATION_B].source_status is SourceStatus.DOWNLOADED
    assert [call[0] for call in cast.download_calls] == [ROOT, IMPLEMENTATION_A, IMPLEMENTATION_B]
    root_slot_reads = [
        call
        for call in cast.storage_calls
        if call[0] == ROOT and call[1] == EIP1967_IMPLEMENTATION_SLOT
    ]
    assert len(root_slot_reads) == 2


def test_source_failure_is_typed_in_contract_and_overall_failed(tmp_path: Path) -> None:
    cast = FakeCast()
    cast.download_errors[ROOT] = DownloadError(
        ErrorCode.API_KEY_INVALID,
        "credencial rechazada",
    )

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(address=ROOT, output_dir=_output(tmp_path))
    )

    assert result.status is OverallStatus.FAILED
    contract = result.contracts[0]
    assert contract.source_status is SourceStatus.FAILED
    assert [error.code for error in contract.errors] == [ErrorCode.API_KEY_INVALID.value]
    assert result.run_directory is not None and result.run_directory.is_dir()


def test_injected_cast_partial_files_are_removed_before_failed_revision_is_published(
    tmp_path: Path,
) -> None:
    cast = FakeCast()
    cast.partial_files_before_error[ROOT] = {
        "P.sol": b"contract Partial {",
    }
    cast.download_errors[ROOT] = DownloadError(
        ErrorCode.DOWNLOAD_FAILED,
        "el cliente inyectado falló después de escribir",
    )

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(address=ROOT, output_dir=_output(tmp_path))
    )

    assert result.status is OverallStatus.FAILED
    assert result.run_directory is not None
    inspection_root = (
        Path("\\\\?\\" + str(result.run_directory)) if os.name == "nt" else result.run_directory
    )
    sources = inspection_root / "contracts" / ROOT / "sources"
    assert sources.is_dir()
    assert list(sources.rglob("*")) == []
    assert result.contracts[0].files == ()


def test_partial_proxy_resolution_cannot_be_reported_as_complete(tmp_path: Path) -> None:
    cast = FakeCast()
    cast.implementation_target = IMPLEMENTATION_A
    cast.code_errors[IMPLEMENTATION_A] = RpcError(
        ErrorCode.NO_CODE_AT_BLOCK,
        "la implementación no contiene código",
    )

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(
            address=ROOT,
            output_dir=_output(tmp_path),
            follow_proxy=True,
        )
    )

    assert result.status is OverallStatus.PARTIAL
    by_address = {contract.address: contract for contract in result.contracts}
    assert by_address[ROOT].source_status is SourceStatus.DOWNLOADED
    assert by_address[ROOT].proxy_resolution_status is ProxyResolutionStatus.PARTIAL
    assert by_address[IMPLEMENTATION_A].source_status is SourceStatus.NOT_ATTEMPTED


def test_failed_proxy_resolution_cannot_be_reported_as_complete(tmp_path: Path) -> None:
    cast = FakeCast()
    cast.storage_errors[(ROOT, EIP1967_IMPLEMENTATION_SLOT)] = RpcError(
        ErrorCode.RPC_ERROR,
        "falló el slot de implementación",
    )

    result = _downloader(tmp_path, cast).fetch(
        DownloadRequest(
            address=ROOT,
            output_dir=_output(tmp_path),
            follow_proxy=True,
        )
    )

    assert result.status is OverallStatus.PARTIAL
    assert result.contracts[0].source_status is SourceStatus.DOWNLOADED
    assert result.contracts[0].proxy_resolution_status is ProxyResolutionStatus.FAILED
    assert result.warnings[0].code == ProxyResolutionStatus.FAILED.value.upper()


def test_service_rejects_missing_credentials_before_any_cast_call(tmp_path: Path) -> None:
    cast = FakeCast()
    config = SourcethConfig(output_dir=_output(tmp_path))
    downloader = SourceDownloader(config, cast_adapter=cast)

    with pytest.raises(ConfigurationError) as raised:
        downloader.fetch(DownloadRequest(address=ROOT, output_dir=_output(tmp_path)))

    assert getattr(raised.value, "code", None) is ErrorCode.INVALID_CONFIGURATION
    assert not cast.capability_commands


def test_service_rejects_invalid_runtime_request_types_before_any_cast_call(
    tmp_path: Path,
) -> None:
    cast = FakeCast()
    downloader = _downloader(tmp_path, cast)

    with pytest.raises(ConfigurationError) as raised:
        downloader.fetch(
            DownloadRequest(
                address=ROOT,
                output_dir=_output(tmp_path),
                max_depth=True,
            )
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION
    assert not cast.capability_commands
