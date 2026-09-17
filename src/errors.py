from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from types import MappingProxyType


class ErrorCode(StrEnum):
    """Códigos públicos y estables de error."""

    INVALID_ADDRESS = "INVALID_ADDRESS"
    INVALID_CHECKSUM = "INVALID_CHECKSUM"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    CAST_NOT_FOUND = "CAST_NOT_FOUND"
    CAST_UNSUPPORTED = "CAST_UNSUPPORTED"
    CHAIN_MISMATCH = "CHAIN_MISMATCH"
    RPC_ERROR = "RPC_ERROR"
    NO_CODE_AT_BLOCK = "NO_CODE_AT_BLOCK"
    BLOCK_CHANGED = "BLOCK_CHANGED"
    SOURCE_NOT_VERIFIED = "SOURCE_NOT_VERIFIED"
    API_KEY_INVALID = "API_KEY_INVALID"
    RATE_LIMITED = "RATE_LIMITED"
    NETWORK_NOT_CONFIGURED = "NETWORK_NOT_CONFIGURED"
    NETWORK_UNSUPPORTED = "NETWORK_UNSUPPORTED"
    PLAN_UNSUPPORTED = "PLAN_UNSUPPORTED"
    DOWNLOAD_TIMEOUT = "DOWNLOAD_TIMEOUT"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    INVALID_PROVIDER_OUTPUT = "INVALID_PROVIDER_OUTPUT"
    UNSAFE_OUTPUT = "UNSAFE_OUTPUT"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    PROXY_RESOLUTION_FAILED = "PROXY_RESOLUTION_FAILED"
    PROXY_CYCLE = "PROXY_CYCLE"
    PROXY_LIMIT_REACHED = "PROXY_LIMIT_REACHED"
    FILESYSTEM_ERROR = "FILESYSTEM_ERROR"
    INTERRUPTED = "INTERRUPTED"


_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "private_key",
    "rpc_url",
    "secret",
    "token",
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_detail(value: object, *, key: str | None = None) -> object:
    if key is not None and _is_sensitive_key(key):
        return _REDACTED
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        safe: dict[str, object] = {}
        mapping = value
        for raw_key, child in mapping.items():
            child_key = str(raw_key)
            safe[child_key] = _sanitize_detail(child, key=child_key)
        return safe
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize_detail(child) for child in value]
    # No se llama a str/repr de objetos arbitrarios: podrían contener secretos.
    return f"<{type(value).__name__}>"


def sanitize_details(details: Mapping[str, object] | None) -> Mapping[str, object]:
    """Copia y sanea metadatos antes de exponerlos en errores o JSON."""

    if details is None:
        return MappingProxyType({})
    safe = {key: _sanitize_detail(value, key=key) for key, value in details.items()}
    return MappingProxyType(safe)


def redact_text(text: str, secrets: Sequence[str]) -> str:
    """Sustituye secretos conocidos en texto externo, ignorando valores vacíos."""

    redacted = text
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = redacted.replace(secret, _REDACTED)
    return redacted


class SourcethError(Exception):
    """Error base recuperable por la API y serializable por la CLI."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        retryable: bool = False,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = sanitize_details(details)
        self.retryable = retryable
        # La causa se conserva para encadenado interno, pero nunca se serializa ni representa.
        self.__cause__ = cause

    def __str__(self) -> str:
        return f"{self.code.value}: {self.message}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code.value!r}, "
            f"message={self.message!r}, retryable={self.retryable!r})"
        )

    def to_dict(self) -> dict[str, object]:
        """Devuelve la forma pública, deliberadamente sin causa ni secretos."""

        result: dict[str, object] = {
            "code": self.code.value,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.details:
            result["details"] = dict(self.details)
        return result


class ValidationError(SourcethError):
    """Entrada del usuario sintácticamente inválida."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        if code not in {ErrorCode.INVALID_ADDRESS, ErrorCode.INVALID_CHECKSUM}:
            raise ValueError("ValidationError requiere un código de validación")
        super().__init__(code, message, details=details)


class ConfigurationError(SourcethError):
    """Configuración ausente, contradictoria o mal formada."""

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            ErrorCode.INVALID_CONFIGURATION,
            message,
            details=details,
            cause=cause,
        )


class ProcessExecutionError(SourcethError):
    """Fallo tipado al preparar o ejecutar un proceso externo."""


class CastError(SourcethError):
    """Fallo clasificado del adaptador de Foundry Cast."""


class RpcError(SourcethError):
    """Fallo durante una lectura RPC."""


class DownloadError(SourcethError):
    """Fallo al obtener fuentes del proveedor."""


class OutputSafetyError(SourcethError):
    """El resultado del proveedor no puede publicarse de forma segura."""


class ProxyResolutionError(SourcethError):
    """Fallo al resolver una relación de proxy solicitada."""


class FilesystemOperationError(SourcethError):
    """Fallo controlado de almacenamiento local."""
