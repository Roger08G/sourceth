from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .errors import SourcethError
from .models import (
    CodeValidationStatus,
    ContractResult,
    ContractRole,
    Diagnostic,
    DownloadResult,
    OverallStatus,
    SourceStatus,
)

_OVERALL_PRESENTATION: Mapping[OverallStatus, tuple[str, str, str]] = {
    OverallStatus.COMPLETE: ("✓", "Descarga completada", "green"),
    OverallStatus.PARTIAL: ("!", "Descarga parcial", "yellow"),
    OverallStatus.FAILED: ("✗", "Descarga fallida", "red"),
}
_SOURCE_PRESENTATION: Mapping[SourceStatus, tuple[str, str]] = {
    SourceStatus.NOT_ATTEMPTED: ("sin intentar", "dim"),
    SourceStatus.DOWNLOADED: ("descargadas", "green"),
    SourceStatus.REUSED: ("reutilizadas", "cyan"),
    SourceStatus.NOT_VERIFIED: ("no verificadas", "yellow"),
    SourceStatus.FAILED: ("fallo", "red"),
}
_CODE_PRESENTATION: Mapping[CodeValidationStatus, tuple[str, str]] = {
    CodeValidationStatus.NOT_ATTEMPTED: ("sin intentar", "dim"),
    CodeValidationStatus.PRESENT: ("presente", "green"),
    CodeValidationStatus.NO_CODE: ("sin bytecode", "red"),
    CodeValidationStatus.SKIPPED: ("omitido", "yellow"),
    CodeValidationStatus.FAILED: ("fallo", "red"),
}
_ROLE_LABELS: Mapping[ContractRole, str] = {
    ContractRole.ROOT: "raíz",
    ContractRole.IMPLEMENTATION: "implementación",
    ContractRole.BEACON: "beacon",
}
_CHECK_LABELS: Mapping[str, str] = {
    "cast_capabilities": "Foundry Cast",
    "source_output_containment": "Contención de salida",
    "explorer_api_key": "API key del explorador",
    "rpc_url": "URL RPC",
    "rpc_chain_id": "Chain ID RPC",
}
_CHECK_PRESENTATION: Mapping[str, tuple[str, str, str]] = {
    "ok": ("✓", "correcto", "green"),
    "configured": ("✓", "configurado", "green"),
    "missing": ("!", "ausente", "yellow"),
    "failed": ("✗", "fallo", "red"),
}


def _console(*, stderr: bool = False) -> Console:
    """Crea la consola en el momento de uso para respetar TTY y redirecciones."""

    return Console(
        file=sys.stderr if stderr else sys.stdout,
        highlight=False,
        soft_wrap=False,
    )


def _short_address(address: str) -> str:
    if len(address) <= 24:
        return address
    return f"{address[:12]}…{address[-8:]}"


def _styled_value(value: tuple[str, str]) -> Text:
    label, style = value
    return Text(label, style=style)


def _count_label(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _summary_grid(result: DownloadResult) -> Table:
    grid = Table.grid(padding=(0, 2), expand=True)
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(overflow="fold")
    _, _, status_style = _OVERALL_PRESENTATION[result.status]
    grid.add_row("Estado", Text(result.status.value, style=f"bold {status_style}"))
    grid.add_row("Dirección", Text(result.checksum_address, style="bold white"))
    grid.add_row("Red", f"chain {result.request.chain_id}")
    grid.add_row("Validación", result.request.validation_mode.value)
    if result.manifest_path is not None:
        grid.add_row("Manifiesto", Text(str(result.manifest_path), style="dim"))
    return grid


def _contracts_table(contracts: Sequence[ContractResult]) -> Table:
    table = Table(
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold bright_cyan",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Contrato", ratio=3, no_wrap=True)
    table.add_column("Rol", ratio=2)
    table.add_column("Fuentes", ratio=2)
    table.add_column("Código", ratio=2)
    table.add_column("N.º", justify="right", ratio=1)
    for contract in contracts:
        table.add_row(
            Text(_short_address(contract.checksum_address), style="cyan"),
            _ROLE_LABELS[contract.role],
            _styled_value(_SOURCE_PRESENTATION[contract.source_status]),
            _styled_value(_CODE_PRESENTATION[contract.code_validation_status]),
            str(len(contract.files)),
        )
    return table


def _unique_diagnostics(
    result: DownloadResult,
) -> tuple[tuple[Diagnostic, ...], tuple[Diagnostic, ...]]:
    warnings: list[Diagnostic] = [*result.warnings]
    errors: list[Diagnostic] = [*result.errors]
    for contract in result.contracts:
        warnings.extend(contract.warnings)
        errors.extend(contract.errors)

    def unique(items: Sequence[Diagnostic]) -> tuple[Diagnostic, ...]:
        seen: set[tuple[str, str]] = set()
        output: list[Diagnostic] = []
        for item in items:
            identity = (item.code, item.message)
            if identity not in seen:
                seen.add(identity)
                output.append(item)
        return tuple(output)

    return unique(warnings), unique(errors)


def render_result(
    result: DownloadResult,
    *,
    console: Console | None = None,
    error_console: Console | None = None,
) -> None:
    """Presenta un resultado humano; la serialización JSON vive fuera de esta capa."""

    output = console or _console()
    diagnostics_output = error_console or _console(stderr=True)
    icon, title, style = _OVERALL_PRESENTATION[result.status]
    output.print()
    output.print(
        Panel(
            _summary_grid(result),
            title=Text(f"{icon} {title}", style=f"bold {style}"),
            subtitle=Text(f"Sourceth {__version__}", style="dim"),
            border_style=style,
            padding=(1, 2),
        )
    )
    if result.contracts:
        output.print(_contracts_table(result.contracts))

    warnings, errors = _unique_diagnostics(result)
    contract_count = len(result.contracts)
    file_count = sum(len(contract.files) for contract in result.contracts)
    footer_style = style if not errors else "red"
    footer_icon = icon if not errors else "✗"
    output.print(
        Text(
            f"{footer_icon} {_count_label(contract_count, 'contrato', 'contratos')} · "
            f"{_count_label(file_count, 'archivo', 'archivos')} · "
            f"{_count_label(len(warnings), 'aviso', 'avisos')} · "
            f"{_count_label(len(errors), 'error', 'errores')}",
            style=f"bold {footer_style}",
        )
    )
    for warning in warnings:
        diagnostics_output.print(
            Text.assemble(
                ("! ", "bold yellow"),
                (warning.code, "bold yellow"),
                (f": {warning.message}", "yellow"),
            )
        )
    for error in errors:
        diagnostics_output.print(
            Text.assemble(
                ("✗ ", "bold red"),
                (error.code, "bold red"),
                (f": {error.message}", "red"),
            )
        )


def _doctor_detail(check: Mapping[str, object]) -> str:
    if isinstance(check.get("version"), str):
        commands = check.get("commands")
        command_text = ""
        if isinstance(commands, list) and all(isinstance(item, str) for item in commands):
            command_text = f" · {', '.join(commands)}"
        return f"v{check['version']}{command_text}"
    if isinstance(check.get("environment_name"), str):
        return str(check["environment_name"])
    requested = check.get("requested")
    observed = check.get("observed")
    if requested is not None or observed is not None:
        return f"solicitado={requested} · observado={observed}"
    error = check.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        message = error.get("message")
        if isinstance(code, str) and isinstance(message, str):
            return f"{code}: {message}"
    return ""


def render_doctor(
    status: str,
    checks: Sequence[Mapping[str, object]],
    *,
    console: Console | None = None,
) -> None:
    output = console or _console()
    healthy = status == "ok"
    style = "green" if healthy else "red"
    icon = "✓" if healthy else "✗"
    title = "Entorno preparado" if healthy else "Revisión necesaria"
    table = Table(
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold bright_cyan",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Comprobación", ratio=3)
    table.add_column("Estado", ratio=2, no_wrap=True)
    table.add_column("Detalle", ratio=5)
    for check in checks:
        name = str(check.get("name", "desconocida"))
        check_status = str(check.get("status", "failed"))
        check_icon, check_label, check_style = _CHECK_PRESENTATION.get(
            check_status,
            ("?", check_status, "yellow"),
        )
        table.add_row(
            _CHECK_LABELS.get(name, name),
            Text(f"{check_icon} {check_label}", style=f"bold {check_style}"),
            Text(_doctor_detail(check), style="dim"),
        )
    output.print()
    output.print(
        Panel(
            table,
            title=Text(f"{icon} {title}", style=f"bold {style}"),
            subtitle=Text(f"Sourceth {__version__} · doctor", style="dim"),
            border_style=style,
            padding=(1, 2),
        )
    )


def render_error(error: SourcethError, *, console: Console | None = None) -> None:
    output = console or _console(stderr=True)
    output.print(
        Panel(
            Text(error.message, style="red"),
            title=Text(f"✗ {error.code.value}", style="bold red"),
            border_style="red",
            padding=(0, 1),
        )
    )


__all__ = ["render_doctor", "render_error", "render_result"]
