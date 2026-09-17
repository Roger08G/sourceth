from __future__ import annotations

import json
import math
import os
import random
import re
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Protocol, cast

from src.adapters.egress import EgressGuardProtocol, ExplorerEgressGuard
from src.adapters.process import ProcessResult, ProcessRunnerProtocol
from src.config import (
    DEFAULT_EXPLORER_API_URL,
    DEFAULT_EXPLORER_URL,
    NetworkConfig,
    RetryPolicy,
    SecretValue,
    SourcethConfig,
)
from src.errors import (
    CastError,
    DownloadError,
    ErrorCode,
    ProcessExecutionError,
    RpcError,
    SourcethError,
    redact_text,
)
from src.models import BlockObservation
from src.validation import (
    validate_address,
    validate_block_hash,
    validate_chain_id,
    validate_portable_relative_path,
    validate_runtime_bytecode,
)

SecretInput = SecretValue | str
BlockReference = BlockObservation | int | str

_NO_COLOR_ENV: Final[Mapping[str, str]] = MappingProxyType({"NO_COLOR": "1"})
_HEX_DATA_RE = re.compile(r"0x[0-9a-fA-F]*\Z")
_HEX_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
_CAST_VERSION_RE = re.compile(r"(?im)^cast(?:\s+Version:)?\s+([^\s]+)")
_CAST_COMMIT_RE = re.compile(r"(?im)^Commit SHA:\s*([0-9a-f]{40})\s*$")
_REVIEWED_CAST_BUILDS: Final[Mapping[str, str]] = MappingProxyType(
    {"1.8.3": "cae51ad458f6abb64852b7709eb784352429825d"}
)
_ERROR_EXCERPT_LIMIT: Final = 1_000


class _OperationKind(StrEnum):
    CAPABILITY = "capability"
    RPC = "rpc"
    SOURCE = "source"


class _Eip1898Unsupported(RpcError):
    """Señal interna: el nodo rechazó inequívocamente una referencia por hash."""


class SourceContainmentPolicy(Protocol):
    """Política previa a cualquier escritura efectuada por ``cast source``."""

    def check(self, capabilities: CastCapabilities, destination: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class CastCapabilities:
    """Capacidades observadas de una instancia concreta de Cast."""

    version: str
    version_output: str
    checked_commands: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CastInvocation:
    """Registro saneado de una invocación; nunca contiene el entorno hijo."""

    operation: str
    argv: tuple[str, ...]
    attempt: int
    returncode: int | None
    duration_seconds: float
    succeeded: bool
    error_code: ErrorCode | None = None


@dataclass(frozen=True, slots=True)
class CastAdapterMetrics:
    """Instantánea inmutable de métricas del adaptador."""

    cast_invocations: int
    adapter_attempts: int
    retries: int
    process_duration_seconds: float
    retry_sleep_seconds: float
    invocations_by_operation: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "invocations_by_operation",
            MappingProxyType(dict(self.invocations_by_operation)),
        )


@dataclass(frozen=True, slots=True)
class DownloadAttempt:
    """Resultado local mínimo de una descarga a staging."""

    directory: Path
    files: tuple[str, ...]
    file_count: int
    total_bytes: int
    attempts: int
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class _CommandOutcome:
    result: ProcessResult
    attempts: int
    duration_seconds: float


class NativeSourceContainmentPolicy:
    """Política conservadora para la escritura nativa de ``cast source``.

    La revisión cubre builds exactas: cualquier otra se cierra también en POSIX.
    La implementación revisada elimina ``..`` y raíces POSIX, pero no
    demuestra contención de prefijos de unidad o UNC en Windows. Por ello una
    ejecución nativa de Windows se cierra por defecto. Una versión auditada puede
    habilitarse explícitamente o la política completa puede inyectarse en pruebas.
    """

    def __init__(
        self,
        *,
        platform: str | None = None,
        approved_windows_versions: Iterable[str] = (),
        additional_reviewed_versions: Iterable[str] = (),
    ) -> None:
        self._platform = sys.platform if platform is None else platform
        self._approved_windows_versions = frozenset(approved_windows_versions)
        self._additional_reviewed_versions = frozenset(additional_reviewed_versions)

    def check(self, capabilities: CastCapabilities, destination: Path) -> None:
        del destination  # La decisión por defecto depende de plataforma y versión.
        is_windows = self._platform.casefold().startswith("win")
        if is_windows and capabilities.version in self._approved_windows_versions:
            return

        expected_commit = _REVIEWED_CAST_BUILDS.get(capabilities.version)
        commit_match = _CAST_COMMIT_RE.search(capabilities.version_output)
        observed_commit = commit_match.group(1) if commit_match is not None else None
        reviewed = expected_commit is not None and observed_commit == expected_commit
        reviewed = reviewed or capabilities.version in self._additional_reviewed_versions
        if not reviewed:
            raise CastError(
                ErrorCode.CAST_UNSUPPORTED,
                "La build de Cast no pertenece a la allowlist revisada para escritura.",
                details={
                    "cast_version": capabilities.version,
                    "cast_commit": observed_commit,
                    "reviewed_versions": sorted(_REVIEWED_CAST_BUILDS),
                },
            )

        if not is_windows:
            return

        raise CastError(
            ErrorCode.UNSAFE_OUTPUT,
            "La descarga nativa con cast source no está contenida de forma demostrable "
            "en Windows. Use Linux/WSL o un contenedor con un único volumen escribible.",
            details={
                "platform": self._platform,
                "cast_version": capabilities.version,
                "reason": "windows_path_containment_not_proven",
            },
        )


class CastAdapter:
    """Fachada síncrona de las operaciones de Cast usadas por Sourceth."""

    def __init__(
        self,
        runner: ProcessRunnerProtocol,
        *,
        cast_path: str | os.PathLike[str] = "cast",
        api_key: SecretInput | None = None,
        rpc_url: SecretInput | None = None,
        retry_policy: RetryPolicy | None = None,
        process_timeout_seconds: float = 30.0,
        download_timeout_seconds: float = 120.0,
        containment_policy: SourceContainmentPolicy | None = None,
        prefer_block_hash: bool = True,
        max_source_files: int = 2_000,
        max_source_file_bytes: int = 10 * 1024 * 1024,
        max_source_total_bytes: int = 100 * 1024 * 1024,
        networks: Mapping[int, NetworkConfig] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        random_value: Callable[[], float] = random.random,
        egress_guard_factory: Callable[[str], EgressGuardProtocol] = ExplorerEgressGuard,
    ) -> None:
        self._runner = runner
        self._cast_path = os.fspath(cast_path)
        if not self._cast_path:
            raise ValueError("cast_path no puede estar vacío")
        self._api_key = api_key
        self._rpc_url = rpc_url
        self._retry_policy = self._validate_retry_policy(retry_policy or RetryPolicy())
        self._process_timeout = self._positive_number(
            process_timeout_seconds, "process_timeout_seconds"
        )
        self._download_timeout = self._positive_number(
            download_timeout_seconds, "download_timeout_seconds"
        )
        self._max_source_files = self._positive_integer(max_source_files, "max_source_files")
        self._max_source_file_bytes = self._positive_integer(
            max_source_file_bytes, "max_source_file_bytes"
        )
        self._max_source_total_bytes = self._positive_integer(
            max_source_total_bytes, "max_source_total_bytes"
        )
        self._networks = dict(
            networks
            or {
                1: NetworkConfig(
                    chain_id=1,
                    name="ethereum-mainnet",
                    provider="etherscan",
                    explorer_api_url=DEFAULT_EXPLORER_API_URL,
                    explorer_url=DEFAULT_EXPLORER_URL,
                )
            }
        )
        self._containment_policy = containment_policy or NativeSourceContainmentPolicy()
        self._prefer_block_hash = prefer_block_hash
        self._sleep = sleeper
        self._monotonic = monotonic
        self._random_value = random_value
        self._egress_guard_factory = egress_guard_factory

        self._version: tuple[str, str] | None = None
        self._help_cache: dict[str, str] = {}
        self._invocations: list[CastInvocation] = []
        self._invocations_by_operation: Counter[str] = Counter()
        self._adapter_attempts = 0
        self._retries = 0
        self._process_duration_seconds = 0.0
        self._retry_sleep_seconds = 0.0

    @classmethod
    def from_config(
        cls,
        runner: ProcessRunnerProtocol,
        config: SourcethConfig,
        *,
        containment_policy: SourceContainmentPolicy | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        random_value: Callable[[], float] = random.random,
    ) -> CastAdapter:
        """Construye el adaptador sin revelar secretos durante la configuración."""

        return cls(
            runner,
            cast_path=config.cast_path,
            api_key=config.credentials.api_key,
            rpc_url=config.credentials.rpc_url,
            retry_policy=config.retry,
            process_timeout_seconds=config.process_timeout_seconds,
            download_timeout_seconds=config.download_timeout_seconds,
            max_source_files=config.limits.max_files,
            max_source_file_bytes=config.limits.max_file_size_bytes,
            max_source_total_bytes=config.limits.max_total_size_bytes,
            networks=config.networks,
            containment_policy=containment_policy,
            sleeper=sleeper,
            monotonic=monotonic,
            random_value=random_value,
        )

    @property
    def invocations(self) -> tuple[CastInvocation, ...]:
        """Devuelve un historial inmutable y sin credenciales."""

        return tuple(self._invocations)

    @property
    def metrics(self) -> CastAdapterMetrics:
        """Devuelve una instantánea coherente de contadores y tiempos."""

        return CastAdapterMetrics(
            cast_invocations=len(self._invocations),
            adapter_attempts=self._adapter_attempts,
            retries=self._retries,
            process_duration_seconds=self._process_duration_seconds,
            retry_sleep_seconds=self._retry_sleep_seconds,
            invocations_by_operation=self._invocations_by_operation,
        )

    def check_capabilities(
        self,
        commands: Iterable[str] = (),
        *,
        refresh: bool = False,
    ) -> CastCapabilities:
        """Comprueba versión, ``source`` y solo las ayudas adicionales solicitadas.

        ``refresh`` abre un nuevo snapshot de ejecución. Las llamadas internas
        posteriores reutilizan ese snapshot, pero otro ``fetch`` no confía en
        una build que pudo haberse sustituido entre ejecuciones.
        """

        requested_commands = set(commands)
        unknown = requested_commands - {"source", "rpc"}
        if unknown:
            raise ValueError(f"Comandos de capacidad no soportados: {sorted(unknown)!r}")
        if refresh:
            self._version = None
            self._help_cache.clear()
        version, version_output = self._get_version()
        ordered_commands = ("source", *sorted(requested_commands - {"source"}))
        for command in ordered_commands:
            help_output = self._get_help(command)
            self._validate_help(command, help_output)
        return CastCapabilities(
            version=version,
            version_output=version_output,
            checked_commands=tuple(self._help_cache),
        )

    def get_chain_id(self) -> int:
        """Lee ``eth_chainId`` y exige una cantidad hexadecimal canónica."""

        value = self._rpc("eth_chainId", ())
        chain_id = self._parse_quantity(self._expect_rpc_string(value, "eth_chainId"))
        if chain_id <= 0:
            raise self._invalid_rpc_output("eth_chainId devolvió un identificador no positivo.")
        return chain_id

    def assert_chain_id(self, expected_chain_id: int | str) -> int:
        """Falla de forma estable si el RPC pertenece a otra red."""

        expected = validate_chain_id(expected_chain_id)
        observed = self.get_chain_id()
        if observed != expected:
            raise RpcError(
                ErrorCode.CHAIN_MISMATCH,
                "El chain ID del RPC no coincide con el solicitado.",
                details={"expected_chain_id": expected, "observed_chain_id": observed},
            )
        return observed

    def observe_block(self, block: int | str = "latest") -> BlockObservation:
        """Resuelve una referencia a un número y hash de bloque inmutables."""

        method, rpc_reference, expected_number, expected_hash = self._block_lookup(block)
        value = self._rpc(method, (rpc_reference, False))
        if value is None:
            raise RpcError(
                ErrorCode.RPC_ERROR,
                "El RPC no encontró el bloque solicitado.",
                details={"block": self._public_block_reference(block)},
            )
        block_object = self._expect_rpc_object(value, method)
        number_value = block_object.get("number")
        hash_value = block_object.get("hash")
        if not isinstance(number_value, str) or not isinstance(hash_value, str):
            raise self._invalid_rpc_output("El bloque RPC no contiene number y hash textuales.")
        number = self._parse_quantity(number_value)
        try:
            block_hash = validate_block_hash(hash_value)
        except ValueError as exc:
            raise self._invalid_rpc_output("El hash de bloque RPC no es válido.", exc) from exc

        if expected_number is not None and number != expected_number:
            raise self._invalid_rpc_output(
                "El RPC devolvió un número de bloque distinto al solicitado."
            )
        if expected_hash is not None and block_hash != expected_hash:
            raise self._invalid_rpc_output(
                "El RPC devolvió un hash de bloque distinto al solicitado."
            )
        return BlockObservation(number=number, hash=block_hash)

    def verify_block_unchanged(self, observation: BlockObservation) -> BlockObservation:
        """Relee el número fijado y detecta una reorganización antes de publicar."""

        original = self._validated_observation(observation)
        current = self.observe_block(original.number)
        if current.hash != original.hash:
            raise RpcError(
                ErrorCode.BLOCK_CHANGED,
                "El hash del bloque fijado cambió durante la operación.",
                details={
                    "block_number": original.number,
                    "expected_hash": original.hash,
                    "observed_hash": current.hash,
                },
            )
        return current

    def get_code(self, address: str, block: BlockReference) -> str:
        """Lee runtime bytecode exactamente en la referencia de bloque indicada."""

        canonical_address = validate_address(address).canonical
        value = self._state_rpc(
            "eth_getCode",
            (canonical_address,),
            block,
        )
        raw_code = self._expect_rpc_string(value, "eth_getCode")
        try:
            code = validate_runtime_bytecode(raw_code)
        except ValueError as exc:
            raise self._invalid_rpc_output("eth_getCode devolvió bytecode inválido.", exc) from exc
        if code == "0x":
            raise RpcError(
                ErrorCode.NO_CODE_AT_BLOCK,
                "La dirección no contiene bytecode en el bloque solicitado.",
                details={
                    "address": canonical_address,
                    "block": self._public_block_reference(block),
                },
            )
        return code

    def get_storage_at(
        self,
        address: str,
        slot: str | int,
        block: BlockReference,
    ) -> str:
        """Lee una palabra de almacenamiento de 32 bytes en un bloque fijo."""

        canonical_address = validate_address(address).canonical
        normalized_slot = self._normalize_storage_slot(slot)
        value = self._state_rpc(
            "eth_getStorageAt",
            (
                canonical_address,
                normalized_slot,
            ),
            block,
        )
        raw_word = self._expect_rpc_string(value, "eth_getStorageAt")
        try:
            word = validate_runtime_bytecode(raw_word)
        except ValueError as exc:
            raise self._invalid_rpc_output(
                "eth_getStorageAt devolvió una palabra inválida.", exc
            ) from exc
        if len(word) != 66:
            raise self._invalid_rpc_output("eth_getStorageAt debe devolver exactamente 32 bytes.")
        return word

    def eth_call(self, address: str, calldata: str, block: BlockReference) -> str:
        """Ejecuta una llamada de solo lectura con calldata hexadecimal explícita."""

        canonical_address = validate_address(address).canonical
        normalized_calldata = self._normalize_hex_data(calldata, field_name="calldata")
        value = self._state_rpc(
            "eth_call",
            ({"to": canonical_address, "data": normalized_calldata},),
            block,
        )
        raw_result = self._expect_rpc_string(value, "eth_call")
        try:
            return validate_runtime_bytecode(raw_result)
        except ValueError as exc:
            raise self._invalid_rpc_output("eth_call devolvió bytes inválidos.", exc) from exc

    def download_source(
        self,
        address: str,
        chain_id: int | str,
        directory: str | os.PathLike[str],
        *,
        timeout: float | None = None,
    ) -> DownloadAttempt:
        """Descarga fuentes a un staging vacío usando la API key solo por entorno."""

        canonical_address = validate_address(address).canonical
        normalized_chain_id = validate_chain_id(chain_id)
        network = self._networks.get(normalized_chain_id)
        if network is None:
            raise DownloadError(
                ErrorCode.NETWORK_NOT_CONFIGURED,
                "La red no tiene un endpoint de explorador configurado.",
                details={"chain_id": normalized_chain_id},
            )
        effective_timeout = (
            self._download_timeout if timeout is None else self._positive_number(timeout, "timeout")
        )
        api_key = self._reveal_required_secret(
            self._api_key,
            operation=_OperationKind.SOURCE,
            name="API key del explorador",
        )
        destination = Path(directory)
        if not destination.is_absolute():
            raise DownloadError(
                ErrorCode.INVALID_CONFIGURATION,
                "El directorio de staging de fuentes debe ser absoluto.",
            )

        capabilities = self.check_capabilities()
        self._containment_policy.check(capabilities, destination)
        self._prepare_empty_destination(destination)

        guard = self._egress_guard_factory(network.explorer_api_url)
        try:
            with guard:

                def prepare_attempt(attempt: int) -> None:
                    if guard.blocked_targets:
                        raise DownloadError(
                            ErrorCode.DOWNLOAD_FAILED,
                            "Se bloqueó una redirección del explorador a otro origen.",
                        )
                    if attempt > 1:
                        self._reset_empty_destination(destination)

                outcome = self._run_with_retries(
                    kind=_OperationKind.SOURCE,
                    operation="source",
                    argv=(
                        self._cast_path,
                        "source",
                        canonical_address,
                        "--chain",
                        str(normalized_chain_id),
                        "-d",
                        str(destination),
                    ),
                    env={
                        "ETHERSCAN_API_KEY": api_key,
                        "EXPLORER_API_URL": network.explorer_api_url,
                        "EXPLORER_URL": network.explorer_url,
                        **guard.environment,
                        **_NO_COLOR_ENV,
                    },
                    timeout=effective_timeout,
                    secrets=(api_key,),
                    before_attempt=prepare_attempt,
                )
                if guard.blocked_targets:
                    raise DownloadError(
                        ErrorCode.DOWNLOAD_FAILED,
                        "Se bloqueó una redirección del explorador a otro origen.",
                    )
            files, total_bytes = self._inspect_download_tree(destination)
        except OSError as error:
            try:
                self._reset_empty_destination(destination)
            except SourcethError as cleanup_error:
                raise cleanup_error from error
            raise DownloadError(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudo activar la guardia local de salida del explorador.",
                cause=error,
            ) from error
        except SourcethError as error:
            try:
                self._reset_empty_destination(destination)
            except SourcethError as cleanup_error:
                raise cleanup_error from error
            raise
        return DownloadAttempt(
            directory=destination,
            files=files,
            file_count=len(files),
            total_bytes=total_bytes,
            attempts=outcome.attempts,
            duration_seconds=outcome.duration_seconds,
        )

    def _rpc(
        self,
        method: str,
        params: Sequence[object],
        *,
        eip1898_probe: bool = False,
    ) -> object:
        rpc_url = self._reveal_required_secret(
            self._rpc_url,
            operation=_OperationKind.RPC,
            name="URL RPC",
        )
        self.check_capabilities(("rpc",))
        serialized_params = json.dumps(
            list(params),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded: list[object] = []

        def validate_success(result: ProcessResult) -> SourcethError | None:
            try:
                value = self._decode_rpc_output(
                    result.stdout,
                    method,
                    eip1898_probe=eip1898_probe,
                )
            except SourcethError as error:
                return error
            decoded.clear()
            decoded.append(value)
            return None

        self._run_with_retries(
            kind=_OperationKind.RPC,
            operation=f"rpc:{method}",
            argv=(self._cast_path, "rpc", "--raw", method, serialized_params),
            env={"ETH_RPC_URL": rpc_url, **_NO_COLOR_ENV},
            timeout=self._process_timeout,
            secrets=(rpc_url,),
            success_validator=validate_success,
        )
        if len(decoded) != 1:  # pragma: no cover - invariante de _run_with_retries
            raise AssertionError("La respuesta RPC aceptada debe haberse decodificado")
        return decoded[0]

    def _get_version(self) -> tuple[str, str]:
        if self._version is not None:
            return self._version
        result = self._run_capability(
            operation="capability:version",
            argv=(self._cast_path, "--version"),
        )
        output = result.stdout.strip()
        match = _CAST_VERSION_RE.search(output)
        if match is None or len(output) > 2_000:
            raise CastError(
                ErrorCode.CAST_UNSUPPORTED,
                "La salida de cast --version no tiene un formato reconocido.",
            )
        self._version = (match.group(1), output)
        return self._version

    def _get_help(self, command: str) -> str:
        cached = self._help_cache.get(command)
        if cached is not None:
            return cached
        result = self._run_capability(
            operation=f"capability:{command}",
            argv=(self._cast_path, command, "--help"),
        )
        output = result.stdout
        if not output.strip() or len(output) > 256_000:
            raise CastError(
                ErrorCode.CAST_UNSUPPORTED,
                f"La ayuda de cast {command} está vacía o excede el límite.",
            )
        self._help_cache[command] = output
        return output

    @staticmethod
    def _validate_help(command: str, help_output: str) -> None:
        requirements: Mapping[str, tuple[str, ...]] = {
            "source": (
                "<ADDRESS>",
                "--chain",
                "-d <DIRECTORY>",
                "--etherscan-api-key",
                "--explorer-api-url",
                "--explorer-url",
            ),
            "rpc": (
                "<METHOD>",
                "--raw",
                "--rpc-url",
            ),
        }
        missing = [token for token in requirements[command] if token not in help_output]
        usage = re.compile(
            rf"(?m)^Usage:\s+cast(?:\.exe)?\s+{re.escape(command)}(?:\s|$)",
            re.IGNORECASE,
        )
        if usage.search(help_output) is None:
            missing.insert(0, f"Usage: cast[.exe] {command}")
        if missing:
            raise CastError(
                ErrorCode.CAST_UNSUPPORTED,
                f"La versión de Cast no ofrece las capacidades requeridas para {command}.",
                details={"command": command, "missing": missing},
            )

    def _run_capability(self, *, operation: str, argv: Sequence[str]) -> ProcessResult:
        try:
            result = self._invoke_once(
                operation=operation,
                argv=argv,
                env=_NO_COLOR_ENV,
                timeout=self._process_timeout,
                secrets=(),
                attempt=1,
            )
        except ProcessExecutionError as exc:
            error = self._translate_process_error(_OperationKind.CAPABILITY, operation, exc)
            self._annotate_last_error(error.code)
            raise error from exc
        if result.returncode != 0:
            error = self._classify_failure(
                _OperationKind.CAPABILITY,
                operation,
                result.returncode,
                result.stdout,
                result.stderr,
                (),
            )
            self._annotate_last_error(error.code)
            raise error
        return result

    def _run_with_retries(
        self,
        *,
        kind: _OperationKind,
        operation: str,
        argv: Sequence[str],
        env: Mapping[str, str],
        timeout: float,
        secrets: Sequence[str],
        before_attempt: Callable[[int], None] | None = None,
        success_validator: Callable[[ProcessResult], SourcethError | None] | None = None,
    ) -> _CommandOutcome:
        started = self._monotonic()
        last_error: SourcethError | None = None
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            error: SourcethError | None = None
            if before_attempt is not None:
                before_attempt(attempt)
            elapsed = max(0.0, self._monotonic() - started)
            remaining_budget = self._retry_policy.budget_seconds - elapsed
            if remaining_budget <= 0:
                if last_error is not None:
                    raise last_error
                raise self._make_error(
                    kind,
                    (
                        ErrorCode.DOWNLOAD_TIMEOUT
                        if kind is _OperationKind.SOURCE
                        else ErrorCode.RPC_ERROR
                    ),
                    "Se agotó el presupuesto temporal antes de iniciar la operación.",
                    details={"operation": operation},
                    retryable=True,
                )
            try:
                result = self._invoke_once(
                    operation=operation,
                    argv=argv,
                    env=env,
                    timeout=min(timeout, remaining_budget),
                    secrets=secrets,
                    attempt=attempt,
                )
            except ProcessExecutionError as exc:
                error = self._translate_process_error(kind, operation, exc)
                self._annotate_last_error(error.code)
            else:
                if result.returncode == 0:
                    error = success_validator(result) if success_validator is not None else None
                    if error is None:
                        return _CommandOutcome(
                            result=result,
                            attempts=attempt,
                            duration_seconds=max(0.0, self._monotonic() - started),
                        )
                else:
                    error = self._classify_failure(
                        kind,
                        operation,
                        result.returncode,
                        result.stdout,
                        result.stderr,
                        secrets,
                    )
                self._annotate_last_error(error.code)

            if error is None:  # pragma: no cover - todas las rutas de éxito retornan
                raise AssertionError("Un intento fallido debe producir un error tipado")
            last_error = error
            if not error.retryable or attempt >= self._retry_policy.max_attempts:
                raise error
            delay = self._retry_delay(attempt)
            elapsed = max(0.0, self._monotonic() - started)
            if elapsed + delay > self._retry_policy.budget_seconds:
                raise error
            self._retries += 1
            self._retry_sleep_seconds += delay
            self._sleep(delay)

        raise AssertionError("El bucle de reintentos debe devolver o elevar")

    def _invoke_once(
        self,
        *,
        operation: str,
        argv: Sequence[str],
        env: Mapping[str, str],
        timeout: float,
        secrets: Sequence[str],
        attempt: int,
    ) -> ProcessResult:
        self._adapter_attempts += 1
        started = self._monotonic()
        working_directory: Path | None = None
        try:
            try:
                try:
                    working_directory = Path(tempfile.mkdtemp(prefix="sourceth-cast-"))
                    # Foundry realiza discovery propio. Estos archivos locales y
                    # vacíos cortan la búsqueda ascendente de .env/config antes
                    # de ejecutar con nuestro entorno hijo explícito.
                    (working_directory / ".env").write_text("", encoding="utf-8")
                    (working_directory / "foundry.toml").write_text(
                        "[profile.default]\n",
                        encoding="utf-8",
                    )
                except OSError as exc:
                    raise ProcessExecutionError(
                        ErrorCode.FILESYSTEM_ERROR,
                        "No se pudo crear el directorio de trabajo aislado para Cast.",
                        cause=exc,
                    ) from exc
                result = self._runner.run(
                    argv,
                    cwd=working_directory,
                    env=env,
                    timeout=timeout,
                    sensitive_values=secrets,
                )
            finally:
                if working_directory is not None:
                    shutil.rmtree(working_directory, ignore_errors=True)
        except ProcessExecutionError as exc:
            duration = max(0.0, self._monotonic() - started)
            self._record_invocation(
                operation=operation,
                argv=tuple(redact_text(str(item), secrets) for item in argv),
                attempt=attempt,
                returncode=None,
                duration_seconds=duration,
                succeeded=False,
                error_code=exc.code,
            )
            raise

        self._record_invocation(
            operation=operation,
            argv=tuple(redact_text(str(item), secrets) for item in argv),
            attempt=attempt,
            returncode=result.returncode,
            duration_seconds=result.duration_seconds,
            succeeded=result.returncode == 0,
            error_code=None,
        )
        return result

    def _record_invocation(
        self,
        *,
        operation: str,
        argv: tuple[str, ...],
        attempt: int,
        returncode: int | None,
        duration_seconds: float,
        succeeded: bool,
        error_code: ErrorCode | None,
    ) -> None:
        duration = max(0.0, duration_seconds)
        self._process_duration_seconds += duration
        self._invocations_by_operation[operation] += 1
        self._invocations.append(
            CastInvocation(
                operation=operation,
                argv=argv,
                attempt=attempt,
                returncode=returncode,
                duration_seconds=duration,
                succeeded=succeeded,
                error_code=error_code,
            )
        )

    def _annotate_last_error(self, code: ErrorCode) -> None:
        """Añade la clasificación estable tras interpretar el retorno de Cast."""

        invocation = self._invocations[-1]
        self._invocations[-1] = CastInvocation(
            operation=invocation.operation,
            argv=invocation.argv,
            attempt=invocation.attempt,
            returncode=invocation.returncode,
            duration_seconds=invocation.duration_seconds,
            succeeded=False,
            error_code=code,
        )

    def _translate_process_error(
        self,
        kind: _OperationKind,
        operation: str,
        error: ProcessExecutionError,
    ) -> SourcethError:
        if error.code in {ErrorCode.CAST_NOT_FOUND, ErrorCode.CAST_UNSUPPORTED}:
            return CastError(
                error.code,
                error.message,
                details=error.details,
                cause=error,
            )
        if error.code is ErrorCode.INVALID_CONFIGURATION:
            return CastError(
                error.code,
                error.message,
                details=error.details,
                cause=error,
            )
        if error.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED:
            return self._make_error(
                kind,
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Cast superó el límite configurado de salida capturada.",
                details={"operation": operation, "process_code": error.code.value},
                retryable=False,
                cause=error,
            )
        if error.code is ErrorCode.FILESYSTEM_ERROR:
            return self._make_error(
                kind,
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo preparar o limpiar la ejecución aislada de Cast.",
                details={"operation": operation, "process_code": error.code.value},
                retryable=False,
                cause=error,
            )
        if error.code is ErrorCode.DOWNLOAD_TIMEOUT:
            if kind is _OperationKind.SOURCE:
                return DownloadError(
                    ErrorCode.DOWNLOAD_TIMEOUT,
                    "Cast superó el timeout durante la descarga de fuentes.",
                    details={"operation": operation},
                    retryable=True,
                    cause=error,
                )
            if kind is _OperationKind.RPC:
                return RpcError(
                    ErrorCode.RPC_ERROR,
                    "Cast superó el timeout durante una lectura RPC.",
                    details={"operation": operation},
                    retryable=True,
                    cause=error,
                )
        code = (
            ErrorCode.CAST_UNSUPPORTED
            if kind is _OperationKind.CAPABILITY
            else ErrorCode.DOWNLOAD_FAILED
            if kind is _OperationKind.SOURCE
            else ErrorCode.RPC_ERROR
        )
        return self._make_error(
            kind,
            code,
            "No se pudo ejecutar Cast de forma controlada.",
            details={"operation": operation, "process_code": error.code.value},
            retryable=False,
            cause=error,
        )

    def _classify_failure(
        self,
        kind: _OperationKind,
        operation: str,
        returncode: int | None,
        stdout: str,
        stderr: str,
        secrets: Sequence[str],
    ) -> SourcethError:
        combined = redact_text("\n".join((stderr, stdout)).strip(), secrets)
        normalized = combined.casefold()

        if self._contains_any(
            normalized,
            ("invalid api key", "invalidapikey", "missing/invalid api key", "api key invalid"),
        ):
            code, retryable = ErrorCode.API_KEY_INVALID, False
            message = "El explorador rechazó la API key."
        elif self._contains_any(
            normalized,
            ("source code not verified", "contract source code not verified"),
        ):
            code, retryable = ErrorCode.SOURCE_NOT_VERIFIED, False
            message = "El explorador no publica fuentes verificadas para la dirección."
        elif self._contains_any(
            normalized,
            ("rate limit", "too many requests", "max rate limit reached", "http 429", " 429"),
        ):
            code, retryable = ErrorCode.RATE_LIMITED, True
            message = "El proveedor aplicó un límite de solicitudes."
        elif self._contains_any(
            normalized,
            (
                "free api access is not supported",
                "requires a paid plan",
                "paid subscription",
                "pro endpoint",
                "plan does not support",
            ),
        ):
            code, retryable = ErrorCode.PLAN_UNSUPPORTED, False
            message = "El plan de la API no permite esta operación."
        elif self._contains_any(
            normalized,
            ("unsupported chain", "chain not supported", "invalid chain", "unsupported network"),
        ):
            code, retryable = ErrorCode.NETWORK_UNSUPPORTED, False
            message = "El proveedor no admite la red solicitada."
        elif self._contains_any(
            normalized,
            (
                "timed out",
                "timeout",
                "connection reset",
                "connection refused",
                "connection aborted",
                "connection closed before message completed",
                "could not resolve host",
                "dns error",
                "failed to lookup address information",
                "failed to resolve",
                "http 500",
                "internal server error",
                "name or service not known",
                "no such host",
                "temporary failure in name resolution",
                "temporarily unavailable",
                "unexpected eof",
                "bad gateway",
                "gateway timeout",
                "service unavailable",
                "server busy",
            ),
        ):
            code, retryable = (
                (ErrorCode.DOWNLOAD_TIMEOUT, True)
                if kind is _OperationKind.SOURCE
                else (ErrorCode.RPC_ERROR, True)
            )
            message = "El proveedor no respondió de forma transitoria."
        elif kind is _OperationKind.CAPABILITY:
            code, retryable = ErrorCode.CAST_UNSUPPORTED, False
            message = "Cast no ofrece la capacidad requerida."
        elif kind is _OperationKind.SOURCE:
            code, retryable = ErrorCode.DOWNLOAD_FAILED, False
            message = "Cast no pudo descargar las fuentes."
        else:
            code, retryable = ErrorCode.RPC_ERROR, False
            message = "La lectura RPC mediante Cast falló."

        details: dict[str, object] = {"operation": operation}
        if returncode is not None:
            details["returncode"] = returncode
        if combined:
            details["provider_excerpt"] = combined[:_ERROR_EXCERPT_LIMIT]
        return self._make_error(
            kind,
            code,
            message,
            details=details,
            retryable=retryable,
        )

    @staticmethod
    def _make_error(
        kind: _OperationKind,
        code: ErrorCode,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        retryable: bool = False,
        cause: BaseException | None = None,
    ) -> SourcethError:
        error_type: type[SourcethError]
        if kind is _OperationKind.SOURCE:
            error_type = DownloadError
        elif kind is _OperationKind.RPC:
            error_type = RpcError
        else:
            error_type = CastError
        return error_type(
            code,
            message,
            details=details,
            retryable=retryable,
            cause=cause,
        )

    def _decode_rpc_output(
        self,
        output: str,
        method: str,
        *,
        eip1898_probe: bool = False,
    ) -> object:
        candidate = output.strip()
        if not candidate or "\x00" in candidate:
            raise self._invalid_rpc_output(f"{method} devolvió una salida vacía o con NUL.")
        try:
            parsed: object = json.loads(
                candidate,
                parse_constant=self._reject_json_constant,
                object_pairs_hook=self._json_object_no_duplicates,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            if _HEX_DATA_RE.fullmatch(candidate) is not None:
                return candidate
            raise self._invalid_rpc_output(
                f"{method} no devolvió un valor JSON completo.", exc
            ) from exc

        if isinstance(parsed, dict):
            if not all(isinstance(key, str) for key in parsed):
                raise self._invalid_rpc_output(f"{method} devolvió claves JSON no textuales.")
            response = cast(dict[str, object], parsed)
            if "error" in response and response["error"] is not None:
                if eip1898_probe and self._is_eip1898_unsupported_error(response["error"], method):
                    raise _Eip1898Unsupported(
                        ErrorCode.RPC_ERROR,
                        "El nodo RPC no admite referencias de estado EIP-1898 por hash.",
                        details={"operation": f"rpc:{method}"},
                    )
                error_text = json.dumps(
                    response["error"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                raise self._classify_failure(
                    _OperationKind.RPC,
                    f"rpc:{method}",
                    None,
                    "",
                    error_text,
                    (),
                )
            if "result" in response and ("jsonrpc" in response or "id" in response):
                return response["result"]
        return parsed

    @staticmethod
    def _is_eip1898_unsupported_error(value: object, method: str) -> bool:
        """Reconoce solo respuestas que atribuyen el rechazo al objeto de bloque.

        Un ``-32602`` genérico no basta: degradar ante un error de otro
        parámetro podría ocultar una respuesta defectuosa y mezclar estados.
        """

        if not isinstance(value, dict):
            return False
        payload = cast(dict[object, object], value)
        code = payload.get("code")
        message = payload.get("message")
        data = payload.get("data")
        parts = [item for item in (message, data) if isinstance(item, str)]
        normalized = " ".join(parts).casefold()
        if not normalized:
            return False
        if "eip-1898" in normalized or "eip1898" in normalized:
            return True
        if ("blockhash" in normalized or "block hash" in normalized) and any(
            marker in normalized
            for marker in ("unsupported", "not supported", "unknown", "invalid", "expected")
        ):
            return True
        if code != -32602:
            return False
        object_to_string = "cannot unmarshal object" in normalized and "string" in normalized
        expected_string = (
            "expected" in normalized
            and "string" in normalized
            and ("object" in normalized or "map" in normalized)
        )
        invalid_map_type = (
            "invalid type" in normalized and "map" in normalized and "string" in normalized
        )
        # ``eth_call`` también contiene un objeto de transacción válido. Sin
        # una referencia al segundo argumento, un mensaje genérico no permite
        # atribuir el rechazo al selector de bloque y se conserva el fallo.
        if method == "eth_call" and not any(
            marker in normalized
            for marker in ("argument 1", "argument #1", "parameter 1", "parameter #1")
        ):
            return False
        return object_to_string or expected_string or invalid_map_type

    @staticmethod
    def _reject_json_constant(value: str) -> object:
        raise ValueError(f"Constante JSON no permitida: {value}")

    @staticmethod
    def _json_object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Clave JSON duplicada: {key}")
            result[key] = value
        return result

    @staticmethod
    def _expect_rpc_string(value: object, method: str) -> str:
        if not isinstance(value, str):
            raise RpcError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                f"{method} no devolvió texto.",
            )
        return value

    @staticmethod
    def _expect_rpc_object(value: object, method: str) -> dict[str, object]:
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise RpcError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                f"{method} no devolvió un objeto JSON.",
            )
        return cast(dict[str, object], value)

    @staticmethod
    def _parse_quantity(value: str) -> int:
        if _HEX_QUANTITY_RE.fullmatch(value) is None or len(value[2:]) > 64:
            raise RpcError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                "El RPC devolvió una cantidad hexadecimal no canónica o fuera de 256 bits.",
            )
        return int(value[2:], 16)

    def _block_lookup(self, block: int | str) -> tuple[str, str, int | None, str | None]:
        if isinstance(block, bool):
            raise ValueError("El bloque no puede ser booleano")
        if isinstance(block, int):
            if block < 0:
                raise ValueError("El número de bloque no puede ser negativo")
            return "eth_getBlockByNumber", hex(block), block, None
        candidate = block.strip()
        if candidate == "latest":
            return "eth_getBlockByNumber", candidate, None, None
        if candidate.isdecimal():
            number = int(candidate, 10)
            return "eth_getBlockByNumber", hex(number), number, None
        block_hash = validate_block_hash(candidate)
        return "eth_getBlockByHash", block_hash, None, block_hash

    def _state_block_reference(self, block: BlockReference) -> object:
        if isinstance(block, BlockObservation):
            observation = self._validated_observation(block)
            if self._prefer_block_hash:
                return {"blockHash": observation.hash, "requireCanonical": True}
            return hex(observation.number)
        if isinstance(block, bool):
            raise ValueError("El bloque no puede ser booleano")
        if isinstance(block, int):
            if block < 0:
                raise ValueError("El número de bloque no puede ser negativo")
            return hex(block)
        candidate = block.strip()
        if candidate == "latest":
            return candidate
        if candidate.isdecimal():
            return hex(int(candidate, 10))
        return {"blockHash": validate_block_hash(candidate), "requireCanonical": True}

    def _state_rpc(
        self,
        method: str,
        leading_params: Sequence[object],
        block: BlockReference,
    ) -> object:
        """Lee estado por hash y degrada a número solo si el nodo no soporta EIP-1898.

        La degradación solo es posible para una observación que conserva ambos
        valores. El servicio vuelve a leer el hash del número antes de publicar,
        por lo que una reorganización no puede aceptarse silenciosamente.
        """

        reference = self._state_block_reference(block)
        eip1898_probe = isinstance(block, BlockObservation) and self._prefer_block_hash
        try:
            return self._rpc(
                method,
                (*leading_params, reference),
                eip1898_probe=eip1898_probe,
            )
        except _Eip1898Unsupported as unsupported:
            if not isinstance(block, BlockObservation):  # pragma: no cover - invariante
                raise
            observation = self._validated_observation(block)
            self._prefer_block_hash = False
            try:
                return self._rpc(method, (*leading_params, hex(observation.number)))
            except SourcethError as fallback_error:
                raise fallback_error from unsupported

    @staticmethod
    def _validated_observation(observation: BlockObservation) -> BlockObservation:
        if isinstance(observation.number, bool) or observation.number < 0:
            raise ValueError("BlockObservation contiene un número inválido")
        return BlockObservation(
            number=observation.number,
            hash=validate_block_hash(observation.hash),
        )

    @staticmethod
    def _public_block_reference(block: BlockReference) -> object:
        if isinstance(block, BlockObservation):
            return {"number": block.number, "hash": block.hash}
        return block

    @staticmethod
    def _normalize_storage_slot(slot: str | int) -> str:
        if isinstance(slot, bool):
            raise ValueError("El slot no puede ser booleano")
        if isinstance(slot, int):
            number = slot
        elif isinstance(slot, str):
            candidate = slot.strip()
            if candidate.isdecimal():
                if len(candidate) > 78:
                    raise ValueError("El slot debe caber en 256 bits")
                number = int(candidate, 10)
            elif _HEX_DATA_RE.fullmatch(candidate) is not None and 2 < len(candidate) <= 66:
                number = int(candidate[2:], 16)
            else:
                raise ValueError("El slot debe ser un entero o hexadecimal con prefijo 0x")
        else:
            raise ValueError("El slot debe ser un entero o texto")
        if number < 0 or number >= 2**256:
            raise ValueError("El slot debe caber en 256 bits")
        return hex(number)

    @staticmethod
    def _normalize_hex_data(value: str, *, field_name: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} debe ser texto")
        candidate = value.strip()
        if _HEX_DATA_RE.fullmatch(candidate) is None or len(candidate[2:]) % 2 != 0:
            raise ValueError(f"{field_name} debe ser bytes hexadecimales con prefijo 0x")
        return "0x" + candidate[2:].lower()

    def _prepare_empty_destination(self, destination: Path) -> None:
        try:
            if destination.exists():
                if destination.is_symlink() or destination.is_junction():
                    raise DownloadError(
                        ErrorCode.UNSAFE_OUTPUT,
                        "El staging no puede ser un enlace ni una junction.",
                    )
                if not destination.is_dir():
                    raise DownloadError(
                        ErrorCode.FILESYSTEM_ERROR,
                        "El staging de fuentes no es un directorio.",
                    )
                if next(destination.iterdir(), None) is not None:
                    raise DownloadError(
                        ErrorCode.UNSAFE_OUTPUT,
                        "El staging de fuentes debe estar vacío antes de invocar Cast.",
                    )
            else:
                parent = destination.parent
                if not parent.is_dir() or parent.is_symlink() or parent.is_junction():
                    raise DownloadError(
                        ErrorCode.UNSAFE_OUTPUT,
                        "El padre del staging no es un directorio real existente.",
                    )
                destination.mkdir(mode=0o700)
        except DownloadError:
            raise
        except OSError as exc:
            raise DownloadError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo preparar el staging de fuentes.",
                cause=exc,
            ) from exc

    def _reset_empty_destination(self, destination: Path) -> None:
        """Elimina restos de un intento fallido y deja un staging nuevo y vacío."""

        try:
            parent = destination.parent
            if not parent.is_dir() or parent.is_symlink() or parent.is_junction():
                raise DownloadError(
                    ErrorCode.UNSAFE_OUTPUT,
                    "El padre del staging dejó de ser un directorio real.",
                )

            exists_or_link = destination.exists() or destination.is_symlink()
            if exists_or_link:
                if destination.is_symlink():
                    destination.unlink()
                elif destination.is_junction():
                    destination.rmdir()
                else:
                    info = destination.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        # shutil.rmtree no sigue symlinks y, desde Python 3.8,
                        # tampoco recorre junctions de Windows.
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
            destination.mkdir(mode=0o700)
        except DownloadError:
            raise
        except OSError as exc:
            raise DownloadError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudieron retirar los restos de una descarga fallida.",
                cause=exc,
            ) from exc

    def _inspect_download_tree(self, destination: Path) -> tuple[tuple[str, ...], int]:
        try:
            root = destination.resolve(strict=True)
            if destination.is_symlink() or destination.is_junction():
                raise DownloadError(
                    ErrorCode.UNSAFE_OUTPUT,
                    "Cast sustituyó el staging por un enlace o junction.",
                )

            pending = [destination]
            files: list[str] = []
            portable_names: set[str] = set()
            total_bytes = 0
            entries_seen = 0
            max_entries = self._max_source_files * 4
            while pending:
                current = pending.pop()
                with os.scandir(current) as entries:
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > max_entries:
                            raise DownloadError(
                                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                                "El árbol descargado contiene demasiadas entradas.",
                            )
                        path = Path(entry.path)
                        if entry.is_symlink() or path.is_junction():
                            raise DownloadError(
                                ErrorCode.UNSAFE_OUTPUT,
                                "La descarga contiene un enlace o junction.",
                            )
                        resolved = path.resolve(strict=True)
                        if not resolved.is_relative_to(root):
                            raise DownloadError(
                                ErrorCode.UNSAFE_OUTPUT,
                                "La descarga contiene una ruta fuera del staging.",
                            )
                        relative = path.relative_to(destination).as_posix()
                        try:
                            portable = validate_portable_relative_path(relative)
                        except ValueError as exc:
                            raise DownloadError(
                                ErrorCode.UNSAFE_OUTPUT,
                                "La descarga contiene una ruta no portable.",
                                details={"relative_path": relative},
                                cause=exc,
                            ) from exc
                        folded = portable.casefold()
                        if folded in portable_names:
                            raise DownloadError(
                                ErrorCode.UNSAFE_OUTPUT,
                                "La descarga contiene rutas que colisionan por mayúsculas.",
                            )
                        portable_names.add(folded)

                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            raise DownloadError(
                                ErrorCode.UNSAFE_OUTPUT,
                                "La descarga contiene un archivo especial.",
                            )
                        size = entry.stat(follow_symlinks=False).st_size
                        if size > self._max_source_file_bytes:
                            raise DownloadError(
                                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                                "Un archivo descargado supera el límite configurado.",
                                details={"relative_path": portable, "size_bytes": size},
                            )
                        files.append(portable)
                        if len(files) > self._max_source_files:
                            raise DownloadError(
                                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                                "La descarga supera el número máximo de archivos.",
                            )
                        total_bytes += size
                        if total_bytes > self._max_source_total_bytes:
                            raise DownloadError(
                                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                                "La descarga supera el tamaño total permitido.",
                            )
        except DownloadError:
            raise
        except OSError as exc:
            raise DownloadError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo inspeccionar el árbol descargado.",
                cause=exc,
            ) from exc

        if not files or total_bytes == 0:
            raise DownloadError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                "Cast terminó sin producir fuentes no vacías.",
            )
        return tuple(sorted(files)), total_bytes

    def _retry_delay(self, failed_attempt: int) -> float:
        exponent = min(max(failed_attempt - 1, 0), 62)
        base = min(
            self._retry_policy.max_delay_seconds,
            self._retry_policy.base_delay_seconds * (2.0**exponent),
        )
        random_sample = self._random_value()
        if not 0.0 <= random_sample <= 1.0:
            raise ValueError("random_value debe devolver un valor entre 0 y 1")
        jitter = self._retry_policy.jitter_ratio * ((2.0 * random_sample) - 1.0)
        return float(max(0.0, base * (1.0 + jitter)))

    @staticmethod
    def _reveal_required_secret(
        secret: SecretInput | None,
        *,
        operation: _OperationKind,
        name: str,
    ) -> str:
        if secret is None:
            code = (
                ErrorCode.INVALID_CONFIGURATION
                if operation is _OperationKind.SOURCE
                else ErrorCode.NETWORK_NOT_CONFIGURED
            )
            error_type: type[SourcethError] = (
                DownloadError if operation is _OperationKind.SOURCE else RpcError
            )
            raise error_type(code, f"Falta configurar {name}.")
        value = secret.reveal() if isinstance(secret, SecretValue) else secret
        if not value:
            raise ValueError(f"{name} no puede estar vacío")
        return value

    def _invalid_rpc_output(
        self,
        message: str,
        cause: BaseException | None = None,
    ) -> RpcError:
        return RpcError(
            ErrorCode.INVALID_PROVIDER_OUTPUT,
            message,
            cause=cause,
        )

    @staticmethod
    def _contains_any(text: str, needles: Sequence[str]) -> bool:
        return any(needle in text for needle in needles)

    @staticmethod
    def _validate_retry_policy(policy: RetryPolicy) -> RetryPolicy:
        if isinstance(policy.max_attempts, bool) or policy.max_attempts < 1:
            raise ValueError("retry.max_attempts debe ser mayor que cero")
        numeric_values = {
            "base_delay_seconds": policy.base_delay_seconds,
            "max_delay_seconds": policy.max_delay_seconds,
            "budget_seconds": policy.budget_seconds,
        }
        for name, value in numeric_values.items():
            if isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ValueError(f"retry.{name} debe ser finito y no negativo")
        if policy.budget_seconds <= 0:
            raise ValueError("retry.budget_seconds debe ser mayor que cero")
        if not math.isfinite(policy.jitter_ratio) or not 0.0 <= policy.jitter_ratio <= 1.0:
            raise ValueError("retry.jitter_ratio debe estar entre 0 y 1")
        return policy

    @staticmethod
    def _positive_number(value: float, name: str) -> float:
        if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} debe ser mayor que cero")
        return float(value)

    @staticmethod
    def _positive_integer(value: int, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} debe ser un entero mayor que cero")
        return value


__all__ = [
    "BlockReference",
    "CastAdapter",
    "CastAdapterMetrics",
    "CastCapabilities",
    "CastInvocation",
    "DownloadAttempt",
    "NativeSourceContainmentPolicy",
    "SourceContainmentPolicy",
]
