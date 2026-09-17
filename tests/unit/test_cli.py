"""Pruebas de contrato de la CLI, sus salidas y códigos de proceso."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from types import MappingProxyType
from typing import cast

import pytest
from rich.console import Console

import src.cli as cli
from src.adapters.cast import CastCapabilities
from src.config import Credentials, NetworkConfig, SecretValue, SourcethConfig
from src.errors import ErrorCode, SourcethError, ValidationError
from src.models import (
    CodeValidationStatus,
    ContractResult,
    ContractRole,
    Diagnostic,
    DownloadRequest,
    DownloadResult,
    OverallStatus,
    SourceStatus,
)
from src.presentation import render_result

ADDRESS = "0x" + ("1" * 40)


def _config(tmp_path: Path, *, with_rpc: bool = True) -> SourcethConfig:
    return SourcethConfig(
        output_dir=tmp_path / "downloads",
        credentials=Credentials(
            rpc_url=(SecretValue("https://rpc.invalid/private") if with_rpc else None),
            api_key=SecretValue("never-print-this-api-secret"),
        ),
        networks=MappingProxyType(
            {1: NetworkConfig(chain_id=1, name="ethereum-mainnet", provider="etherscan")}
        ),
    )


def _result(tmp_path: Path, status: OverallStatus) -> DownloadResult:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "run": {"status": status.value}}) + "\n",
        encoding="utf-8",
    )
    source_status = (
        SourceStatus.DOWNLOADED if status is not OverallStatus.FAILED else SourceStatus.FAILED
    )
    errors = (
        ()
        if status is OverallStatus.COMPLETE
        else (Diagnostic(code="TEST_FAILURE", message="fallo controlado"),)
    )
    request = DownloadRequest(address=ADDRESS, output_dir=tmp_path / "downloads")
    return DownloadResult(
        status=status,
        request=request,
        root_address=ADDRESS,
        checksum_address=ADDRESS,
        run_id="run-test",
        run_directory=tmp_path / "run-test",
        manifest_path=manifest_path,
        contracts=(
            ContractResult(
                address=ADDRESS,
                checksum_address=ADDRESS,
                role=ContractRole.ROOT,
                source_status=source_status,
                code_validation_status=CodeValidationStatus.PRESENT,
                errors=errors,
            ),
        ),
        errors=errors,
    )


class _FakeDownloader:
    def __init__(self, result: DownloadResult) -> None:
        self._result = result
        self.requests: list[DownloadRequest] = []

    def fetch(self, request: DownloadRequest) -> DownloadResult:
        self.requests.append(request)
        return self._result


def _install_fetch_doubles(
    monkeypatch: pytest.MonkeyPatch,
    config: SourcethConfig,
    result: DownloadResult,
) -> _FakeDownloader:
    downloader = _FakeDownloader(result)
    monkeypatch.setattr(cli, "_load_for_args", lambda _args: config)
    monkeypatch.setattr(cli, "_runner", lambda _config: object())
    monkeypatch.setattr(
        cli,
        "SourceDownloader",
        lambda _config, *, runner: downloader,
    )
    return downloader


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [
        (OverallStatus.COMPLETE, 0),
        (OverallStatus.PARTIAL, 3),
        (OverallStatus.FAILED, 4),
    ],
)
def test_fetch_json_stdout_is_one_clean_document_and_maps_result_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    status: OverallStatus,
    expected_exit: int,
) -> None:
    result = _result(tmp_path, status)
    downloader = _install_fetch_doubles(monkeypatch, _config(tmp_path), result)

    exit_code = cli.main(
        [
            "fetch",
            ADDRESS,
            "--chain",
            "1",
            "--output",
            str(tmp_path / "chosen"),
            "--block",
            "42",
            "--follow-proxy",
            "--max-depth",
            "3",
            "--refresh",
            "--timeout",
            "9",
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    assert exit_code == expected_exit
    assert payload["schema_version"] == 1
    assert payload["status"] == status.value
    assert isinstance(payload["manifest"], dict)
    assert captured.out.count("\n") == 1
    assert captured.err == ""
    assert len(downloader.requests) == 1
    request = downloader.requests[0]
    assert request.address == ADDRESS
    assert request.block == "42"
    assert request.follow_proxy
    assert request.max_depth == 3
    assert request.refresh
    assert request.timeout == 9


def test_human_fetch_keeps_diagnostics_out_of_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    result = _result(tmp_path, OverallStatus.PARTIAL)
    _install_fetch_doubles(monkeypatch, _config(tmp_path), result)

    assert cli.main(["fetch", ADDRESS]) == 3

    captured = capsys.readouterr()
    assert "Descarga parcial" in captured.out
    assert "TEST_FAILURE" not in captured.out
    assert "TEST_FAILURE" in captured.err
    assert "\x1b[" not in captured.out + captured.err


def test_human_fetch_uses_color_when_stdout_is_a_terminal(tmp_path: Path) -> None:
    stdout = StringIO()
    stderr = StringIO()
    render_result(
        _result(tmp_path, OverallStatus.COMPLETE),
        console=Console(
            file=stdout,
            force_terminal=True,
            color_system="standard",
            width=140,
            highlight=False,
        ),
        error_console=Console(
            file=stderr,
            force_terminal=True,
            color_system="standard",
            width=140,
            highlight=False,
        ),
    )

    assert "\x1b[" in stdout.getvalue()
    assert "Descarga completada" in stdout.getvalue()
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (ValidationError(ErrorCode.INVALID_ADDRESS, "dirección inválida"), 2),
        (SourcethError(ErrorCode.NETWORK_NOT_CONFIGURED, "red ausente"), 2),
        (SourcethError(ErrorCode.CAST_NOT_FOUND, "cast ausente"), 4),
        (SourcethError(ErrorCode.DOWNLOAD_FAILED, "descarga fallida"), 4),
    ],
)
def test_typed_execution_errors_use_json_schema_and_exit_2_or_4(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: SourcethError,
    expected_exit: int,
) -> None:
    def fail(_args: object) -> int:
        raise error

    monkeypatch.setattr(cli, "_fetch", fail)

    exit_code = cli.main(["fetch", ADDRESS, "--json"])

    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    public_error = cast(dict[str, object], payload["error"])
    assert exit_code == expected_exit
    assert payload["status"] == "failed"
    assert public_error["code"] == error.code.value
    assert captured.out.count("\n") == 1
    assert captured.err == ""


def test_unexpected_execution_error_is_generic_json_without_secret_leak(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "runtime-super-secret"

    def fail(_args: object) -> int:
        raise RuntimeError(secret)

    monkeypatch.setattr(cli, "_fetch", fail)

    assert cli.main(["fetch", ADDRESS, "--json", "--verbose"]) == 4

    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    error = cast(dict[str, object], payload["error"])
    assert error["code"] == ErrorCode.DOWNLOAD_FAILED.value
    assert secret not in captured.out + captured.err
    assert captured.out.count("\n") == 1


@pytest.mark.parametrize("json_output", [False, True])
def test_keyboard_interrupt_always_returns_130(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
) -> None:
    def interrupt(_args: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_fetch", interrupt)
    arguments = ["fetch", ADDRESS]
    if json_output:
        arguments.append("--json")

    assert cli.main(arguments) == 130

    captured = capsys.readouterr()
    if json_output:
        payload = cast(dict[str, object], json.loads(captured.out))
        error = cast(dict[str, object], payload["error"])
        assert error["code"] == ErrorCode.INTERRUPTED.value
        assert captured.err == ""
    else:
        assert captured.out == ""
        assert ErrorCode.INTERRUPTED.value in captured.err


class _DoctorAdapter:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.chain_checks: list[int] = []

    def check_capabilities(self, commands: tuple[str, ...] = ()) -> CastCapabilities:
        self.commands.append(commands)
        return CastCapabilities("1.8.1", "cast 1.8.1 (fake)", ("source", *commands))

    def assert_chain_id(self, expected: int) -> int:
        self.chain_checks.append(expected)
        return expected


class _AllowPolicy:
    def check(self, capabilities: CastCapabilities, destination: Path) -> None:
        assert capabilities.version == "1.8.1"
        assert destination.is_absolute()


def _install_doctor_doubles(
    monkeypatch: pytest.MonkeyPatch,
    config: SourcethConfig,
) -> _DoctorAdapter:
    adapter = _DoctorAdapter()

    class DoctorAdapterFactory:
        @classmethod
        def from_config(
            cls,
            runner: object,
            active_config: SourcethConfig,
        ) -> _DoctorAdapter:
            del cls, runner
            assert active_config is config
            return adapter

    monkeypatch.setattr(cli, "_load_for_args", lambda _args: config)
    monkeypatch.setattr(cli, "_runner", lambda _config: object())
    monkeypatch.setattr(cli, "CastAdapter", DoctorAdapterFactory)
    monkeypatch.setattr(cli, "NativeSourceContainmentPolicy", _AllowPolicy)
    return adapter


@pytest.mark.parametrize("remote", [False, True])
def test_doctor_is_offline_by_default_and_json_never_prints_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    remote: bool,
) -> None:
    config = _config(tmp_path)
    adapter = _install_doctor_doubles(monkeypatch, config)
    arguments = ["doctor", "--json"]
    if remote:
        arguments.append("--remote")

    assert cli.main(arguments) == 0

    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    assert payload["status"] == "ok"
    assert payload["network_access"] is remote
    assert adapter.commands == [("rpc",)]
    assert adapter.chain_checks == ([1] if remote else [])
    assert "never-print-this-api-secret" not in captured.out + captured.err
    assert "https://rpc.invalid/private" not in captured.out + captured.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["fetch", "--json"],
        ["fetch", ADDRESS, "--validation", "invalid", "--json"],
        ["--json", "fetch", ADDRESS],
        ["unknown", "--json"],
    ],
)
def test_invalid_json_arguments_keep_stdout_machine_readable(
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    assert cli.main(arguments) == 2

    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    error = cast(dict[str, object], payload["error"])
    assert error["code"] == ErrorCode.INVALID_CONFIGURATION.value
    assert captured.out.count("\n") == 1
    assert captured.err == ""


def test_invalid_human_arguments_return_2_with_usage_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "uso: sourceth" in captured.err
    assert ErrorCode.INVALID_CONFIGURATION.value in captured.err


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["--help"], "Descarga fuentes publicadas"),
        (["doctor", "--help"], "comprobación RPC explícita"),
        (["fetch", "--help"], "Profundidad máxima de proxies"),
    ],
)
def test_cli_help_is_fully_presented_in_spanish(
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    expected: str,
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(arguments)

    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "uso: sourceth" in captured.out
    assert expected in captured.out
    assert "usage:" not in captured.out
    assert "positional arguments:" not in captured.out
    assert "options:" not in captured.out
    assert "show this help message and exit" not in captured.out
    assert "show program's version number and exit" not in captured.out
