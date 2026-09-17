from __future__ import annotations

import math
import re
from pathlib import Path, PurePosixPath

from eth_utils.address import is_checksum_address, to_checksum_address
from eth_utils.crypto import keccak

from .errors import ConfigurationError, ErrorCode, ValidationError
from .models import DownloadRequest, ValidatedAddress, ValidationMode

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HEX_RE = re.compile(r"[0-9a-fA-F]*\Z")
_BLOCK_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    *(f"COM{index}" for index in "123456789¹²³"),
    *(f"LPT{index}" for index in "123456789¹²³"),
}


def validate_address(value: str) -> ValidatedAddress:
    """Valida una dirección hexadecimal y aplica la política EIP-55 de V1."""

    if not isinstance(value, str):
        raise ValidationError(
            ErrorCode.INVALID_ADDRESS,
            "La dirección debe ser texto.",
        )

    original = value
    candidate = value.strip()
    if _ADDRESS_RE.fullmatch(candidate) is None:
        raise ValidationError(
            ErrorCode.INVALID_ADDRESS,
            "La dirección debe usar el prefijo 0x seguido de 40 caracteres hexadecimales.",
            details={"input_length": len(candidate)},
        )

    body = candidate[2:]
    has_lowercase = any(character in "abcdef" for character in body)
    has_uppercase = any(character in "ABCDEF" for character in body)
    if has_lowercase and has_uppercase and not is_checksum_address(candidate):
        raise ValidationError(
            ErrorCode.INVALID_CHECKSUM,
            "La dirección con mayúsculas y minúsculas no tiene un checksum EIP-55 válido.",
        )

    canonical = "0x" + body.lower()
    return ValidatedAddress(
        original=original,
        trimmed=candidate,
        canonical=canonical,
        checksum=to_checksum_address(canonical),
    )


def validate_chain_id(value: int | str) -> int:
    """Devuelve un chain ID decimal estrictamente positivo."""

    if isinstance(value, bool):
        raise ValueError("chain_id debe ser un entero positivo")
    if isinstance(value, int):
        chain_id = value
    elif isinstance(value, str) and value.strip().isdecimal():
        chain_id = int(value.strip(), 10)
    else:
        raise ValueError("chain_id debe ser un entero decimal positivo")
    if chain_id <= 0:
        raise ValueError("chain_id debe ser mayor que cero")
    return chain_id


def validate_env_name(value: str, *, field_name: str) -> str:
    """Valida el nombre de una variable, nunca su contenido secreto."""

    if _ENV_NAME_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} no es un nombre de variable de entorno válido")
    return value


def validate_runtime_bytecode(value: str) -> str:
    """Valida y normaliza una respuesta hexadecimal de ``cast code``."""

    candidate = value.strip()
    if not candidate.startswith("0x"):
        raise ValueError("El runtime bytecode debe comenzar por 0x")
    body = candidate[2:]
    if len(body) % 2 != 0 or _HEX_RE.fullmatch(body) is None:
        raise ValueError("El runtime bytecode no es hexadecimal bien formado")
    return "0x" + body.lower()


def runtime_bytecode_keccak(value: str) -> str:
    """Calcula Keccak-256 sobre los bytes decodificados, no sobre el texto hex."""

    normalized = validate_runtime_bytecode(value)
    return "0x" + keccak(bytes.fromhex(normalized[2:])).hex()


def validate_block_hash(value: str) -> str:
    candidate = value.strip()
    if _BLOCK_HASH_RE.fullmatch(candidate) is None:
        raise ValueError("El hash de bloque debe ser 0x seguido de 64 caracteres hexadecimales")
    return "0x" + candidate[2:].lower()


def validate_block_specifier(value: int | str | None) -> int | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("El bloque debe ser 'latest', un número o un hash")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("El número de bloque no puede ser negativo")
        return value
    if not isinstance(value, str):
        raise ValueError("El bloque debe ser 'latest', un número o un hash")
    candidate = value.strip()
    if candidate == "latest":
        return candidate
    if candidate.isdecimal():
        return int(candidate, 10)
    return validate_block_hash(candidate)


def validate_request(request: DownloadRequest) -> ValidatedAddress:
    """Comprueba contradicciones locales antes de cualquier operación externa."""

    address = validate_address(request.address)
    try:
        if isinstance(request.chain_id, bool) or not isinstance(request.chain_id, int):
            raise ValueError("chain_id debe ser un entero")
        validate_chain_id(request.chain_id)
        mode = request.validation_mode
        validate_block_specifier(request.block)
    except ValueError as error:
        raise ConfigurationError(
            "La solicitud contiene un argumento inválido.",
            details={"reason": str(error)},
            cause=error,
        ) from error

    if mode is ValidationMode.EXPLORER and request.block is not None:
        raise ConfigurationError("--block no está disponible con validación explorer en V1.")
    if not isinstance(request.follow_proxy, bool):
        raise ConfigurationError("follow_proxy debe ser booleano.")
    if mode is ValidationMode.EXPLORER and request.follow_proxy:
        raise ConfigurationError("--follow-proxy requiere validación RPC.")
    if request.max_depth is not None and (
        isinstance(request.max_depth, bool)
        or not isinstance(request.max_depth, int)
        or request.max_depth <= 0
    ):
        raise ConfigurationError("max_depth debe ser un entero mayor que cero.")
    if not isinstance(request.refresh, bool):
        raise ConfigurationError("refresh debe ser booleano.")
    if request.timeout is not None and (
        isinstance(request.timeout, bool)
        or not isinstance(request.timeout, (int, float))
        or not math.isfinite(float(request.timeout))
        or request.timeout <= 0
    ):
        raise ConfigurationError("timeout debe ser finito y mayor que cero.")
    if not isinstance(request.output_dir, (str, Path)):
        raise ConfigurationError("output_dir debe ser una ruta.")
    if not str(request.output_dir).strip() or "\x00" in str(request.output_dir):
        raise ConfigurationError("output_dir debe ser una ruta no vacía y sin NUL.")
    return address


def validate_portable_relative_path(value: str) -> str:
    """Valida una ruta relativa recibida de un proveedor en ambas plataformas."""

    if not value or "\x00" in value:
        raise ValueError("La ruta relativa está vacía o contiene NUL")
    normalized_separators = value.replace("\\", "/")
    if normalized_separators.startswith(("/", "//")):
        raise ValueError("No se permiten rutas absolutas")
    if _WINDOWS_DRIVE_RE.match(normalized_separators):
        raise ValueError("No se permiten rutas con unidad de Windows")

    raw_parts = normalized_separators.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("La ruta contiene componentes inseguros")
    for part in raw_parts:
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ValueError("La ruta contiene caracteres de control")
        stem = part.rstrip(" .").split(".", maxsplit=1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES or part.endswith((" ", ".")):
            raise ValueError("La ruta contiene un nombre incompatible con Windows")
        if any(character in part for character in '<>:"|?*'):
            raise ValueError("La ruta contiene caracteres incompatibles con Windows")

    return PurePosixPath(*raw_parts).as_posix()
