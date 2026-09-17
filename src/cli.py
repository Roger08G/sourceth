from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never

from . import __version__
from .adapters.cast import CastAdapter, NativeSourceContainmentPolicy
from .adapters.process import ProcessRunner
from .config import ConfigOverrides, SourcethConfig, load_config
from .errors import ErrorCode, SourcethError
from .manifest import result_json
from .models import DownloadRequest, DownloadResult, OverallStatus
from .presentation import render_doctor, render_error, render_result
from .service import SourceDownloader

LOGGER = logging.getLogger("sourceth")
_INVALID_INPUT_CODES = {
    ErrorCode.INVALID_ADDRESS,
    ErrorCode.INVALID_CHECKSUM,
    ErrorCode.INVALID_CONFIGURATION,
    ErrorCode.NETWORK_NOT_CONFIGURED,
}


class _CliUsageError(Exception):
    """Error de parsing que el borde CLI puede serializar de forma uniforme."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message  # Puede contener entrada sensible; no se refleja en la salida.
        raise _CliUsageError

    @staticmethod
    def _translate_help(text: str) -> str:
        translations = (
            ("usage: ", "uso: "),
            ("positional arguments:\n", "argumentos posicionales:\n"),
            ("optional arguments:\n", "argumentos opcionales:\n"),
            ("options:\n", "opciones:\n"),
            ("show this help message and exit", "muestra esta ayuda y termina"),
        )
        for source, target in translations:
            text = text.replace(source, target)
        return text

    def format_usage(self) -> str:
        return self._translate_help(super().format_usage())

    def format_help(self) -> str:
        return self._translate_help(super().format_help())


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="sourceth",
        description="Descarga fuentes publicadas de una dirección EVM mediante Foundry Cast.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Muestra la versión y termina.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Archivo TOML explícito; no se descubre automáticamente.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Archivo .env exacto (predeterminado: ./.env).",
    )
    parser.add_argument("--cast-path", help="Ruta o nombre del binario Cast.")

    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor = subparsers.add_parser(
        "doctor",
        help="Comprueba Cast y la configuración sin red por defecto.",
    )
    doctor.add_argument("--chain", type=int, help="Chain ID que debe comprobarse.")
    doctor.add_argument(
        "--remote",
        action="store_true",
        help="Realiza además una comprobación RPC explícita.",
    )
    doctor.add_argument("--json", action="store_true", help="Emite un único JSON por stdout.")
    doctor.add_argument(
        "--verbose",
        action="store_true",
        help="Activa diagnóstico adicional saneado por stderr.",
    )

    fetch = subparsers.add_parser("fetch", help="Descarga una dirección.")
    fetch.add_argument("address", help="Dirección 0x de 20 bytes; no se admite ENS.")
    fetch.add_argument("--chain", type=int, help="Chain ID EIP-155.")
    fetch.add_argument("--output", type=Path, help="Directorio de revisiones.")
    fetch.add_argument(
        "--validation",
        choices=("rpc", "explorer"),
        default="rpc",
        help="Modo de validación (predeterminado: rpc).",
    )
    fetch.add_argument("--block", help="latest, número decimal o hash de bloque.")
    fetch.add_argument(
        "--follow-proxy",
        action="store_true",
        help="Resuelve EIP-1967, beacon y ERC-1167 en modo RPC.",
    )
    fetch.add_argument(
        "--max-depth",
        type=int,
        help="Profundidad máxima de proxies para esta ejecución.",
    )
    fetch.add_argument(
        "--refresh",
        action="store_true",
        help="Ignora la caché y crea una revisión nueva.",
    )
    fetch.add_argument("--timeout", type=float, help="Timeout de la descarga en segundos.")
    fetch.add_argument("--json", action="store_true", help="Emite un único JSON por stdout.")
    fetch.add_argument(
        "--verbose",
        action="store_true",
        help="Activa diagnóstico adicional saneado por stderr.",
    )
    return parser


def _load_for_args(args: argparse.Namespace) -> SourcethConfig:
    overrides = ConfigOverrides(
        chain_id=getattr(args, "chain", None),
        output_dir=getattr(args, "output", None),
        cast_path=args.cast_path,
        download_timeout_seconds=getattr(args, "timeout", None),
    )
    return load_config(
        overrides,
        dotenv_path=args.env_file,
        config_path=args.config,
    )


def _runner(config: SourcethConfig) -> ProcessRunner:
    return ProcessRunner(
        timeout=config.process_timeout_seconds,
        max_stdout_bytes=config.limits.max_output_bytes,
        max_stderr_bytes=config.limits.max_output_bytes,
    )


def _doctor(args: argparse.Namespace) -> int:
    config = _load_for_args(args)
    adapter = CastAdapter.from_config(_runner(config), config)
    # La ayuda de rpc es una comprobación local y forma parte del modo
    # predeterminado; --remote solo habilita la llamada real de chain ID.
    capabilities = adapter.check_capabilities(("rpc",))
    checks: list[dict[str, object]] = [
        {
            "name": "cast_capabilities",
            "status": "ok",
            "version": capabilities.version,
            "commands": list(capabilities.checked_commands),
        }
    ]
    status = "ok"

    try:
        NativeSourceContainmentPolicy().check(capabilities, config.output_dir.resolve())
    except SourcethError as error:
        status = "failed"
        checks.append(
            {"name": "source_output_containment", "status": "failed", "error": error.to_dict()}
        )
    else:
        checks.append({"name": "source_output_containment", "status": "ok"})

    if config.credentials.api_key is None:
        status = "failed"
        checks.append(
            {
                "name": "explorer_api_key",
                "status": "missing",
                "environment_name": config.api_key_env,
            }
        )
    else:
        checks.append({"name": "explorer_api_key", "status": "configured"})

    if config.credentials.rpc_url is None:
        checks.append(
            {
                "name": "rpc_url",
                "status": "missing",
                "environment_name": config.rpc_url_env,
            }
        )
        if args.remote:
            status = "failed"
    else:
        checks.append({"name": "rpc_url", "status": "configured"})

    if args.remote and config.credentials.rpc_url is not None:
        observed = adapter.assert_chain_id(config.chain_id)
        checks.append(
            {
                "name": "rpc_chain_id",
                "status": "ok",
                "requested": config.chain_id,
                "observed": observed,
            }
        )

    payload = {
        "schema_version": 1,
        "command": "doctor",
        "status": status,
        "network_access": bool(args.remote),
        "checks": checks,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    else:
        render_doctor(status, checks)
    return 0 if status == "ok" else 2


def _fetch(args: argparse.Namespace) -> int:
    config = _load_for_args(args)
    request = DownloadRequest(
        address=args.address,
        chain_id=config.chain_id,
        output_dir=config.output_dir,
        validation=args.validation,
        block=args.block,
        follow_proxy=args.follow_proxy,
        max_depth=args.max_depth,
        refresh=args.refresh,
        timeout=args.timeout,
    )
    result = SourceDownloader(config, runner=_runner(config)).fetch(request)
    if args.json:
        manifest: dict[str, object] | None = None
        if result.manifest_path is not None:
            loaded = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = {str(key): value for key, value in loaded.items()}
        print(result_json(result, manifest))
    else:
        _print_result(result)
    return _result_exit_code(result.status)


def _print_result(result: DownloadResult) -> None:
    render_result(result)


def _result_exit_code(status: OverallStatus) -> int:
    if status is OverallStatus.COMPLETE:
        return 0
    if status is OverallStatus.PARTIAL:
        return 3
    return 4


def _error_exit_code(error: SourcethError) -> int:
    return 2 if error.code in _INVALID_INPUT_CODES else 4


def _emit_error(error: SourcethError, *, json_output: bool) -> None:
    if json_output:
        payload = {
            "schema_version": 1,
            "status": "failed",
            "error": error.to_dict(),
        }
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    else:
        render_error(error)


def _configure_logging(*, verbose: bool) -> None:
    """Activa diagnóstico propio sin inundar la terminal con dependencias."""

    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s: %(message)s",
    )
    logging.getLogger().setLevel(logging.WARNING)
    LOGGER.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("filelock").setLevel(logging.WARNING)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in arguments
    try:
        args = parser.parse_args(arguments)
    except _CliUsageError:
        error = SourcethError(
            ErrorCode.INVALID_CONFIGURATION,
            "Los argumentos de la CLI no son válidos.",
        )
        if not json_output:
            parser.print_usage(file=sys.stderr)
        _emit_error(error, json_output=json_output)
        return 2
    _configure_logging(verbose=bool(getattr(args, "verbose", False)))
    json_output = bool(getattr(args, "json", False))
    try:
        if args.command == "doctor":
            return _doctor(args)
        if args.command == "fetch":
            return _fetch(args)
        parser.error("Subcomando desconocido")
    except KeyboardInterrupt:
        error = SourcethError(ErrorCode.INTERRUPTED, "Operación interrumpida por el usuario.")
        _emit_error(error, json_output=json_output)
        return 130
    except SourcethError as error:
        _emit_error(error, json_output=json_output)
        return _error_exit_code(error)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        if getattr(args, "verbose", False):
            LOGGER.error("Fallo local no clasificado (%s)", type(error).__name__)
        wrapped = SourcethError(
            ErrorCode.FILESYSTEM_ERROR,
            "No se pudo leer o presentar el resultado local.",
        )
        _emit_error(wrapped, json_output=json_output)
        return 4
    except Exception as error:
        if getattr(args, "verbose", False):
            # No se imprime el mensaje ni el traceback: una dependencia podría
            # haber incluido credenciales en la excepción original.
            LOGGER.error("Fallo interno no clasificado (%s)", type(error).__name__)
        wrapped = SourcethError(
            ErrorCode.DOWNLOAD_FAILED,
            "Se produjo un fallo interno no clasificado.",
        )
        _emit_error(wrapped, json_output=json_output)
        return 4


__all__ = ["build_parser", "main"]
