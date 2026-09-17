from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast
from urllib.parse import urlsplit

from dotenv import dotenv_values

from .errors import ConfigurationError, ErrorCode, SourcethError
from .validation import validate_chain_id, validate_env_name

DEFAULT_DOTENV_PATH: Final = Path(".env")
DEFAULT_API_KEY_ENV: Final = "ETHERSCAN_API_KEY"
DEFAULT_RPC_URL_ENV: Final = "ETH_RPC_URL"
DEFAULT_EXPLORER_API_URL: Final = "https://api.etherscan.io/v2/api"
DEFAULT_EXPLORER_URL: Final = "https://etherscan.io"


class SecretValue:
    """Valor sensible que exige una llamada explícita para revelarse."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise ValueError("Un secreto configurado no puede estar vacío")
        self.__value = value

    def reveal(self) -> str:
        """Devuelve el valor para construir el entorno controlado del proceso hijo."""

        return self.__value

    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        return "[REDACTED]"

    def __repr__(self) -> str:
        return "SecretValue('[REDACTED]')"


@dataclass(frozen=True, slots=True)
class Credentials:
    rpc_url: SecretValue | None = None
    api_key: SecretValue | None = None


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 8.0
    budget_seconds: float = 300.0
    jitter_ratio: float = 0.2


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_files: int = 2_000
    max_file_size_bytes: int = 10 * 1024 * 1024
    max_total_size_bytes: int = 100 * 1024 * 1024
    max_output_bytes: int = 1024 * 1024


@dataclass(frozen=True, slots=True)
class NetworkConfig:
    chain_id: int
    name: str
    provider: str
    explorer_api_url: str = DEFAULT_EXPLORER_API_URL
    explorer_url: str = DEFAULT_EXPLORER_URL

    def __post_init__(self) -> None:
        object.__setattr__(self, "chain_id", validate_chain_id(self.chain_id))
        object.__setattr__(self, "name", _parse_nonempty_string(self.name, name="network.name"))
        object.__setattr__(
            self,
            "provider",
            _parse_nonempty_string(self.provider, name="network.provider"),
        )
        object.__setattr__(
            self,
            "explorer_api_url",
            _parse_public_https_url(
                self.explorer_api_url,
                name="network.explorer_api_url",
            ),
        )
        object.__setattr__(
            self,
            "explorer_url",
            _parse_public_https_url(
                self.explorer_url,
                name="network.explorer_url",
            ),
        )

    @property
    def provider_identity_sha256(self) -> str:
        """Identidad estable de procedencia sin persistir rutas de endpoint."""

        payload = json.dumps(
            {
                "explorer_api_url": self.explorer_api_url,
                "explorer_url": self.explorer_url,
                "provider": self.provider.casefold(),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


def _default_networks() -> Mapping[int, NetworkConfig]:
    return MappingProxyType(
        {
            1: NetworkConfig(
                chain_id=1,
                name="ethereum-mainnet",
                provider="etherscan",
                explorer_api_url=DEFAULT_EXPLORER_API_URL,
                explorer_url=DEFAULT_EXPLORER_URL,
            )
        }
    )


@dataclass(frozen=True, slots=True)
class SourcethConfig:
    chain_id: int = 1
    output_dir: Path = Path("downloads")
    cast_path: str = "cast"
    rpc_url_env: str = DEFAULT_RPC_URL_ENV
    api_key_env: str = DEFAULT_API_KEY_ENV
    process_timeout_seconds: float = 30.0
    download_timeout_seconds: float = 120.0
    retry: RetryPolicy = RetryPolicy()
    cache_ttl_seconds: int = 86_400
    proxy_max_depth: int = 5
    proxy_max_addresses: int = 10
    limits: ResourceLimits = ResourceLimits()
    credentials: Credentials = Credentials()
    networks: Mapping[int, NetworkConfig] = field(default_factory=_default_networks)
    config_path: Path | None = None
    dotenv_path: Path | None = None

    @property
    def network(self) -> NetworkConfig:
        return self.networks[self.chain_id]


# Alias legible para consumidores que prefieran un nombre genérico.
AppConfig = SourcethConfig


@dataclass(frozen=True, slots=True)
class ConfigOverrides:
    """Valores ya interpretados procedentes de la CLI; ``None`` significa ausente."""

    chain_id: int | None = None
    output_dir: str | Path | None = None
    cast_path: str | None = None
    rpc_url_env: str | None = None
    api_key_env: str | None = None
    process_timeout_seconds: float | None = None
    download_timeout_seconds: float | None = None
    retry_max_attempts: int | None = None
    retry_base_delay_seconds: float | None = None
    retry_max_delay_seconds: float | None = None
    retry_budget_seconds: float | None = None
    retry_jitter_ratio: float | None = None
    cache_ttl_seconds: int | None = None
    proxy_max_depth: int | None = None
    proxy_max_addresses: int | None = None
    max_files: int | None = None
    max_file_size_bytes: int | None = None
    max_total_size_bytes: int | None = None
    max_output_bytes: int | None = None


_DEFAULT_VALUES: Final[dict[str, object]] = {
    "chain_id": 1,
    "output_dir": "downloads",
    "cast_path": "cast",
    "rpc_url_env": DEFAULT_RPC_URL_ENV,
    "api_key_env": DEFAULT_API_KEY_ENV,
    "process_timeout_seconds": 30.0,
    "download_timeout_seconds": 120.0,
    "retry_max_attempts": 3,
    "retry_base_delay_seconds": 0.5,
    "retry_max_delay_seconds": 8.0,
    "retry_budget_seconds": 300.0,
    "retry_jitter_ratio": 0.2,
    "cache_ttl_seconds": 86_400,
    "proxy_max_depth": 5,
    "proxy_max_addresses": 10,
    "max_files": 2_000,
    "max_file_size_bytes": 10 * 1024 * 1024,
    "max_total_size_bytes": 100 * 1024 * 1024,
    "max_output_bytes": 1024 * 1024,
}

_ENV_KEYS: Final[dict[str, str]] = {
    "chain_id": "SOURCETH_CHAIN_ID",
    "output_dir": "SOURCETH_OUTPUT_DIR",
    "cast_path": "SOURCETH_CAST_PATH",
    "rpc_url_env": "SOURCETH_RPC_URL_ENV",
    "api_key_env": "SOURCETH_API_KEY_ENV",
    "process_timeout_seconds": "SOURCETH_PROCESS_TIMEOUT_SECONDS",
    "download_timeout_seconds": "SOURCETH_DOWNLOAD_TIMEOUT_SECONDS",
    "retry_max_attempts": "SOURCETH_RETRY_MAX_ATTEMPTS",
    "retry_base_delay_seconds": "SOURCETH_RETRY_BASE_DELAY_SECONDS",
    "retry_max_delay_seconds": "SOURCETH_RETRY_MAX_DELAY_SECONDS",
    "retry_budget_seconds": "SOURCETH_RETRY_BUDGET_SECONDS",
    "retry_jitter_ratio": "SOURCETH_RETRY_JITTER_RATIO",
    "cache_ttl_seconds": "SOURCETH_CACHE_TTL_SECONDS",
    "proxy_max_depth": "SOURCETH_PROXY_MAX_DEPTH",
    "proxy_max_addresses": "SOURCETH_PROXY_MAX_ADDRESSES",
    "max_files": "SOURCETH_MAX_FILES",
    "max_file_size_bytes": "SOURCETH_MAX_FILE_SIZE_BYTES",
    "max_total_size_bytes": "SOURCETH_MAX_TOTAL_SIZE_BYTES",
    "max_output_bytes": "SOURCETH_MAX_OUTPUT_BYTES",
}

_ALLOWED_TOML_KEYS: Final = frozenset((*_DEFAULT_VALUES, "networks"))
_HOST_LABEL_RE: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_ADDRESS_DIRECTORY_RE: Final = re.compile(r"0x[0-9a-fA-F]{40}\Z")


def _string_mapping(value: object, *, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context} debe ser una tabla TOML.")
    raw_mapping = cast(dict[object, object], value)
    result: dict[str, object] = {}
    for key, item in raw_mapping.items():
        if not isinstance(key, str):
            raise ConfigurationError(f"{context} contiene una clave que no es texto.")
        result[key] = item
    return result


def _read_toml(path: Path | None) -> tuple[dict[str, object], Path | None]:
    if path is None:
        return {}, None
    candidate = path.expanduser()
    if not candidate.is_file():
        raise ConfigurationError(
            "No se encontró el archivo TOML solicitado.",
            details={"path": str(candidate)},
        )
    try:
        with candidate.open("rb") as stream:
            data: object = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(
            "No se pudo leer la configuración TOML.",
            details={"path": str(candidate)},
            cause=error,
        ) from error
    values = _string_mapping(data, context="La configuración")
    unknown = sorted(set(values) - _ALLOWED_TOML_KEYS)
    if unknown:
        raise ConfigurationError(
            "La configuración TOML contiene claves desconocidas.",
            details={"keys": unknown},
        )
    return values, candidate.resolve()


def _read_dotenv(path: Path | None) -> tuple[dict[str, str], Path | None]:
    if path is None:
        return {}, None
    candidate = path.expanduser()
    if _is_within_downloaded_sources(candidate.absolute()):
        raise ConfigurationError(
            "No se puede cargar un .env situado dentro de fuentes descargadas por Sourceth."
        )
    if not candidate.exists():
        return {}, None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError("No se pudo resolver el archivo .env.", cause=error) from error
    if _is_within_downloaded_sources(resolved):
        raise ConfigurationError(
            "No se puede cargar un .env situado dentro de fuentes descargadas por Sourceth."
        )
    if not resolved.is_file():
        raise ConfigurationError(
            "La ruta de .env no es un archivo regular.",
            details={"path": str(candidate)},
        )
    try:
        parsed = dotenv_values(dotenv_path=resolved, encoding="utf-8", interpolate=False)
    except (OSError, UnicodeError) as error:
        raise ConfigurationError("No se pudo leer el archivo .env.", cause=error) from error
    values = {key: value for key, value in parsed.items() if value is not None}
    return values, resolved


def _is_within_downloaded_sources(path: Path) -> bool:
    """Detecta un archivo bajo ``runs/.../contracts/ADDRESS/sources``.

    La comprobación no depende del ``output_dir`` que el propio archivo podría
    intentar alterar ni de que el manifiesto siga presente. Por eso se realiza
    antes de fusionar cualquier valor de ``.env``.
    """

    directory = path.parent
    for candidate in (directory, *directory.parents):
        if candidate.name.casefold() != "sources":
            continue
        contract_directory = candidate.parent
        contracts_directory = contract_directory.parent
        run_directory = contracts_directory.parent
        runs_directory = run_directory.parent
        root_directory = runs_directory.parent
        chain_directory = root_directory.parent
        if (
            contracts_directory.name.casefold() == "contracts"
            and runs_directory.name.casefold() == "runs"
            and bool(run_directory.name)
            and _ADDRESS_DIRECTORY_RE.fullmatch(contract_directory.name) is not None
            and _ADDRESS_DIRECTORY_RE.fullmatch(root_directory.name) is not None
            and chain_directory.name.isdecimal()
        ):
            return True
    return False


def _parse_int(value: object, *, name: str, minimum: int) -> int:
    if isinstance(value, bool):
        raise ConfigurationError(f"{name} debe ser un entero.")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate.isdecimal():
            raise ConfigurationError(f"{name} debe ser un entero decimal.")
        parsed = int(candidate, 10)
    else:
        raise ConfigurationError(f"{name} debe ser un entero.")
    if parsed < minimum:
        raise ConfigurationError(f"{name} debe ser mayor o igual que {minimum}.")
    return parsed


def _parse_float(value: object, *, name: str, minimum: float) -> float:
    if isinstance(value, bool):
        raise ConfigurationError(f"{name} debe ser numérico.")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError as error:
            raise ConfigurationError(f"{name} debe ser numérico.") from error
    else:
        raise ConfigurationError(f"{name} debe ser numérico.")
    if parsed < minimum or parsed == float("inf") or parsed != parsed:
        raise ConfigurationError(f"{name} debe ser finito y mayor o igual que {minimum}.")
    return parsed


def _parse_nonempty_string(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ConfigurationError(f"{name} debe ser texto no vacío.")
    return value.strip()


def _parse_output_path(value: object) -> Path:
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError("output_dir debe ser una ruta no vacía.")
    return Path(value.strip()).expanduser()


def _is_valid_url_hostname(hostname: str) -> bool:
    candidate = hostname.rstrip(".")
    if not candidate or "%" in candidate:
        return False
    if ":" in candidate:
        try:
            ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError:
            return False
        return True
    if all(character.isdecimal() or character == "." for character in candidate):
        try:
            ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            return False
        return True
    try:
        ascii_hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return len(ascii_hostname) <= 253 and all(
        _HOST_LABEL_RE.fullmatch(label) is not None for label in ascii_hostname.split(".")
    )


def _parse_public_https_url(value: object, *, name: str) -> str:
    candidate = _parse_nonempty_string(value, name=name)
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(f"{name} no es una URL válida.", cause=error) from error
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or not _is_valid_url_hostname(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in candidate)
    ):
        raise ConfigurationError(
            f"{name} debe ser una URL HTTPS sin credenciales, query ni fragmento."
        )
    del port  # Acceder a la propiedad valida el rango sin alterar la URL original.
    return candidate.rstrip("/")


def _parse_networks(value: object | None) -> Mapping[int, NetworkConfig]:
    networks = dict(_default_networks())
    if value is None:
        return MappingProxyType(networks)
    raw_networks = _string_mapping(value, context="networks")
    for raw_chain_id, raw_definition in raw_networks.items():
        try:
            chain_id = validate_chain_id(raw_chain_id)
        except ValueError as error:
            raise ConfigurationError(
                "networks contiene un chain ID inválido.",
                details={"chain_id": raw_chain_id},
                cause=error,
            ) from error
        definition = _string_mapping(
            raw_definition,
            context=f"networks.{raw_chain_id}",
        )
        unknown = sorted(set(definition) - {"name", "provider", "explorer_api_url", "explorer_url"})
        if unknown:
            raise ConfigurationError(
                f"networks.{raw_chain_id} contiene claves desconocidas.",
                details={"keys": unknown},
            )
        name = _parse_nonempty_string(
            definition.get("name", f"chain-{chain_id}"),
            name=f"networks.{raw_chain_id}.name",
        )
        provider = _parse_nonempty_string(
            definition.get("provider", "etherscan"),
            name=f"networks.{raw_chain_id}.provider",
        )
        existing = networks.get(chain_id)
        if existing is None and (
            "explorer_api_url" not in definition or "explorer_url" not in definition
        ):
            raise ConfigurationError(
                f"networks.{raw_chain_id} debe declarar explorer_api_url y explorer_url."
            )
        explorer_api_url = _parse_public_https_url(
            definition.get(
                "explorer_api_url",
                existing.explorer_api_url if existing is not None else "",
            ),
            name=f"networks.{raw_chain_id}.explorer_api_url",
        )
        explorer_url = _parse_public_https_url(
            definition.get(
                "explorer_url",
                existing.explorer_url if existing is not None else "",
            ),
            name=f"networks.{raw_chain_id}.explorer_url",
        )
        networks[chain_id] = NetworkConfig(
            chain_id=chain_id,
            name=name,
            provider=provider,
            explorer_api_url=explorer_api_url,
            explorer_url=explorer_url,
        )
    return MappingProxyType(networks)


def _cli_values(overrides: ConfigOverrides | None) -> dict[str, object]:
    if overrides is None:
        return {}
    result: dict[str, object] = {}
    for item in fields(overrides):
        value = getattr(overrides, item.name)
        if value is not None:
            result[item.name] = value
    return result


def _environment_values(environment: Mapping[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    for field_name, environment_name in _ENV_KEYS.items():
        if environment_name in environment:
            result[field_name] = environment[environment_name]
    return result


def _secret(environment: Mapping[str, str], name: str) -> SecretValue | None:
    value = environment.get(name)
    if value is None or not value.strip():
        return None
    return SecretValue(value)


def load_config(
    cli: ConfigOverrides | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = DEFAULT_DOTENV_PATH,
    config_path: str | Path | None = None,
) -> SourcethConfig:
    """Carga ``CLI > entorno > .env > TOML > defaults`` sin mutar ``os.environ``."""

    toml_values, loaded_config_path = _read_toml(None if config_path is None else Path(config_path))
    dotenv_values_map, loaded_dotenv_path = _read_dotenv(
        None if dotenv_path is None else Path(dotenv_path)
    )
    process_environment = dict(os.environ if environ is None else environ)

    merged_environment = dict(dotenv_values_map)
    merged_environment.update(process_environment)

    raw_values = dict(_DEFAULT_VALUES)
    networks_value = toml_values.pop("networks", None)
    raw_values.update(toml_values)
    raw_values.update(_environment_values(dotenv_values_map))
    raw_values.update(_environment_values(process_environment))
    raw_values.update(_cli_values(cli))

    chain_id_raw = raw_values["chain_id"]
    try:
        chain_id = validate_chain_id(cast(int | str, chain_id_raw))
    except (TypeError, ValueError) as error:
        raise ConfigurationError(
            "chain_id debe ser un entero decimal positivo.",
            cause=error,
        ) from error

    output_dir = _parse_output_path(raw_values["output_dir"])
    cast_path = _parse_nonempty_string(raw_values["cast_path"], name="cast_path")
    try:
        rpc_url_env = validate_env_name(
            _parse_nonempty_string(raw_values["rpc_url_env"], name="rpc_url_env"),
            field_name="rpc_url_env",
        )
        api_key_env = validate_env_name(
            _parse_nonempty_string(raw_values["api_key_env"], name="api_key_env"),
            field_name="api_key_env",
        )
    except ValueError as error:
        raise ConfigurationError(str(error), cause=error) from error

    networks = _parse_networks(networks_value)
    if chain_id not in networks:
        raise SourcethError(
            ErrorCode.NETWORK_NOT_CONFIGURED,
            "La red solicitada no está registrada en la configuración de Sourceth.",
            details={"chain_id": chain_id},
        )

    if loaded_dotenv_path is not None:
        try:
            loaded_dotenv_path.relative_to(output_dir.resolve())
        except ValueError:
            pass
        else:
            raise ConfigurationError(
                "No se puede cargar un .env situado dentro del directorio de salida."
            )

    max_attempts = _parse_int(
        raw_values["retry_max_attempts"],
        name="retry_max_attempts",
        minimum=1,
    )
    base_delay = _parse_float(
        raw_values["retry_base_delay_seconds"],
        name="retry_base_delay_seconds",
        minimum=0.0,
    )
    max_delay = _parse_float(
        raw_values["retry_max_delay_seconds"],
        name="retry_max_delay_seconds",
        minimum=0.0,
    )
    if max_delay < base_delay:
        raise ConfigurationError(
            "retry_max_delay_seconds no puede ser menor que retry_base_delay_seconds."
        )
    jitter_ratio = _parse_float(
        raw_values["retry_jitter_ratio"],
        name="retry_jitter_ratio",
        minimum=0.0,
    )
    if jitter_ratio > 1.0:
        raise ConfigurationError("retry_jitter_ratio no puede ser mayor que 1.")

    max_file_size = _parse_int(
        raw_values["max_file_size_bytes"],
        name="max_file_size_bytes",
        minimum=1,
    )
    max_total_size = _parse_int(
        raw_values["max_total_size_bytes"],
        name="max_total_size_bytes",
        minimum=1,
    )
    if max_file_size > max_total_size:
        raise ConfigurationError("max_file_size_bytes no puede ser mayor que max_total_size_bytes.")

    return SourcethConfig(
        chain_id=chain_id,
        output_dir=output_dir,
        cast_path=cast_path,
        rpc_url_env=rpc_url_env,
        api_key_env=api_key_env,
        process_timeout_seconds=_parse_float(
            raw_values["process_timeout_seconds"],
            name="process_timeout_seconds",
            minimum=0.001,
        ),
        download_timeout_seconds=_parse_float(
            raw_values["download_timeout_seconds"],
            name="download_timeout_seconds",
            minimum=0.001,
        ),
        retry=RetryPolicy(
            max_attempts=max_attempts,
            base_delay_seconds=base_delay,
            max_delay_seconds=max_delay,
            budget_seconds=_parse_float(
                raw_values["retry_budget_seconds"],
                name="retry_budget_seconds",
                minimum=0.001,
            ),
            jitter_ratio=jitter_ratio,
        ),
        cache_ttl_seconds=_parse_int(
            raw_values["cache_ttl_seconds"],
            name="cache_ttl_seconds",
            minimum=0,
        ),
        proxy_max_depth=_parse_int(
            raw_values["proxy_max_depth"],
            name="proxy_max_depth",
            minimum=1,
        ),
        proxy_max_addresses=_parse_int(
            raw_values["proxy_max_addresses"],
            name="proxy_max_addresses",
            minimum=1,
        ),
        limits=ResourceLimits(
            max_files=_parse_int(raw_values["max_files"], name="max_files", minimum=1),
            max_file_size_bytes=max_file_size,
            max_total_size_bytes=max_total_size,
            max_output_bytes=_parse_int(
                raw_values["max_output_bytes"],
                name="max_output_bytes",
                minimum=1,
            ),
        ),
        credentials=Credentials(
            rpc_url=_secret(merged_environment, rpc_url_env),
            api_key=_secret(merged_environment, api_key_env),
        ),
        networks=networks,
        config_path=loaded_config_path,
        dotenv_path=loaded_dotenv_path,
    )
