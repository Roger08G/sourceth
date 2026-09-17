"""Integración offline de ProcessRunner contra un proceso Cast simulado."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from src.adapters.process import (
    DEFAULT_ALLOWED_ENVIRONMENT,
    DEFAULT_INHERITED_ENVIRONMENT,
    DEFAULT_SECRET_ENVIRONMENT,
    ProcessResult,
    ProcessRunner,
    _WindowsJob,
)
from src.errors import ErrorCode, ProcessExecutionError


@pytest.fixture
def fake_executable(tmp_path: Path) -> Path:
    """Script multi-modo ejecutado por el intérprete real, sin red ni Cast."""

    script = tmp_path / "fake_cast.py"
    script.write_text(
        """
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse

mode = sys.argv[1]
if mode == "streams":
    print("salida-out")
    print("salida-err", file=sys.stderr)
elif mode == "exit":
    print("fallo controlado", file=sys.stderr)
    raise SystemExit(int(sys.argv[2]))
elif mode == "env":
    print(json.dumps({name: os.environ.get(name) for name in sys.argv[2:]}))
elif mode == "secret-env":
    print(os.environ["ETH_RPC_URL"])
    print(os.environ["ETHERSCAN_API_KEY"], file=sys.stderr)
elif mode == "secret-url-fragments":
    parsed = urllib.parse.urlsplit(os.environ["ETH_RPC_URL"])
    query_values = [value for _name, value in urllib.parse.parse_qsl(parsed.query)]
    path_parts = parsed.path.strip("/").split("/")
    print("|".join((parsed.username or "", parsed.password or "", *path_parts, *query_values)))
    print("usrname|pwmeter|v20|mainnetwork|SECRETARY|query-secret-suffix", file=sys.stderr)
elif mode == "public-url":
    print("https://rpc.invalid/path?token=unknown")
elif mode == "flood":
    sys.stdout.write("x" * int(sys.argv[2]))
    sys.stdout.flush()
elif mode == "flood-stderr":
    sys.stderr.write("x" * int(sys.argv[2]))
    sys.stderr.flush()
elif mode == "invalid-utf8":
    sys.stdout.buffer.write(bytes([0xff]))
    sys.stdout.buffer.flush()
elif mode == "cwd":
    print(Path.cwd().name)
elif mode == "quiet":
    pass
elif mode == "sleep":
    print("started", flush=True)
    time.sleep(float(sys.argv[2]))
elif mode == "delayed-marker":
    time.sleep(float(sys.argv[3]))
    Path(sys.argv[2]).write_text("orphan", encoding="utf-8")
elif mode == "grandchild":
    marker = Path(sys.argv[2])
    delay = sys.argv[3]
    code = (
        "from pathlib import Path; import sys,time; "
        "time.sleep(float(sys.argv[2])); Path(sys.argv[1]).write_text('orphan', encoding='utf-8')"
    )
    child = subprocess.Popen([sys.executable, "-c", code, str(marker), delay])
    print(child.pid, flush=True)
    time.sleep(30)
elif mode == "grandchild-ignore-term":
    marker = Path(sys.argv[2])
    ready = Path(sys.argv[3])
    delay = sys.argv[4]
    code = (
        "from pathlib import Path; import signal,sys,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[2]).write_text('ready', encoding='utf-8'); "
        "time.sleep(float(sys.argv[3])); "
        "Path(sys.argv[1]).write_text('orphan', encoding='utf-8')"
    )
    child = subprocess.Popen([sys.executable, "-c", code, str(marker), str(ready), delay])
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    raise SystemExit(0)
else:
    raise SystemExit(99)
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return script


def _command(fake_executable: Path, *arguments: str) -> list[str]:
    return [sys.executable, str(fake_executable), *arguments]


def _process_details(error: ProcessExecutionError) -> Mapping[str, object]:
    value = error.details.get("process")
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def test_runner_captures_stdout_and_stderr_separately(fake_executable: Path) -> None:
    result = ProcessRunner(timeout=5).run(_command(fake_executable, "streams"))

    assert result.returncode == 0
    assert result.succeeded
    assert result.stdout.strip() == "salida-out"
    assert result.stderr.strip() == "salida-err"
    assert not result.stdout_truncated
    assert not result.stderr_truncated
    assert result.cleanup_succeeded
    assert result.duration_seconds >= 0


def test_nonzero_exit_is_returned_for_adapter_classification(fake_executable: Path) -> None:
    result = ProcessRunner(timeout=5).run(_command(fake_executable, "exit", "7"))

    assert result.returncode == 7
    assert not result.succeeded
    assert "fallo controlado" in result.stderr


def test_environment_is_allowlisted_and_not_implicitly_leaked(fake_executable: Path) -> None:
    host_environment = dict(os.environ)
    host_environment["SHOULD_NOT_LEAK"] = "private-value"
    runner = ProcessRunner(host_environment=host_environment)

    result = runner.run(
        _command(fake_executable, "env", "SHOULD_NOT_LEAK", "NO_COLOR"),
        env={"NO_COLOR": "1"},
    )
    payload = cast(dict[str, object], json.loads(result.stdout))

    assert payload == {"SHOULD_NOT_LEAK": None, "NO_COLOR": "1"}


def test_environment_override_outside_allowlist_is_rejected(fake_executable: Path) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(
            _command(fake_executable, "streams"),
            env={"UNLISTED_SECRET": "must-not-pass"},
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION
    assert "must-not-pass" not in str(raised.value.to_dict())


def test_secrets_and_sensitive_urls_are_redacted_everywhere(fake_executable: Path) -> None:
    api_key = "api-secret-123456"
    rpc_url = "https://user:password@rpc.invalid/private-key?token=secret"

    result = ProcessRunner().run(
        _command(fake_executable, "secret-env"),
        env={"ETHERSCAN_API_KEY": api_key, "ETH_RPC_URL": rpc_url},
    )
    public_text = repr(result) + str(result.to_dict())

    assert api_key not in public_text
    assert rpc_url not in public_text
    assert "private-key" not in public_text
    assert "[REDACTADO]" in result.stderr
    assert "[REDACTADO]" in result.stdout

    unknown_url = ProcessRunner().run(_command(fake_executable, "public-url"))
    assert unknown_url.stdout.strip() == "[URL_REDACTADA]"


def test_rpc_url_credentials_and_path_query_tokens_are_redacted_as_fragments(
    fake_executable: Path,
) -> None:
    credentials = ("usr", "pw")
    path_tokens = ("v2", "mainnet")
    query_tokens = ("SECRET", "query-secret")
    rpc_url = (
        f"https://{credentials[0]}:{credentials[1]}@rpc.invalid/{'/'.join(path_tokens)}"
        f"?foo={query_tokens[0]}&unrecognized={query_tokens[1]}"
    )

    result = ProcessRunner().run(
        _command(fake_executable, "secret-url-fragments"),
        env={"ETH_RPC_URL": rpc_url},
    )
    for secret in (*credentials, *path_tokens, *query_tokens):
        assert secret not in result.stdout
    assert rpc_url not in repr(result) + str(result.to_dict())
    assert result.stdout.count("[REDACTADO]") == 6
    # Los límites evitan redactar coincidencias dentro de palabras corrientes.
    assert result.stderr.strip() == (
        "usrname|pwmeter|v20|mainnetwork|SECRETARY|query-secret-suffix"
    )


def test_known_sensitive_value_in_arguments_is_rejected(fake_executable: Path) -> None:
    secret = "known-secret"

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(
            _command(fake_executable, "exit", secret),
            sensitive_values=(secret,),
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION
    assert secret not in str(raised.value.to_dict())


@pytest.mark.parametrize(
    "arguments",
    [
        ("--rpc-url", "https://rpc.invalid/key"),
        ("--api-key=secret",),
        ("https://rpc.invalid/private",),
    ],
)
def test_sensitive_url_or_flag_in_arguments_is_rejected(
    fake_executable: Path, arguments: tuple[str, ...]
) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(_command(fake_executable, "exit", *arguments))

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_missing_executable_has_stable_error_code() -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(["sourceth-definitely-missing-binary-3d8703"])

    assert raised.value.code is ErrorCode.CAST_NOT_FOUND


def test_cmd_and_bat_wrappers_are_rejected_before_execution(tmp_path: Path) -> None:
    for suffix in (".cmd", ".BAT"):
        wrapper = tmp_path / f"fake{suffix}"
        wrapper.write_text("echo unsafe\n", encoding="utf-8")
        with pytest.raises(ProcessExecutionError) as raised:
            ProcessRunner().run([wrapper])
        assert raised.value.code is ErrorCode.CAST_UNSUPPORTED


def test_relative_executable_path_is_rejected() -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run([str(Path("bin") / "cast")])

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_bare_executable_is_resolved_only_from_absolute_path_entries() -> None:
    executable = Path(sys.executable).resolve()
    host_environment = {
        "PATH": str(executable.parent),
        "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE"),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
    }
    runner = ProcessRunner(host_environment=host_environment)

    result = runner.run([executable.name, "-c", "print('resolved')"])

    assert result.stdout.strip() == "resolved"
    assert result.executable == executable


def test_timeout_raises_typed_error_with_bounded_partial_output(
    fake_executable: Path,
) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner(timeout=0.2, max_stdout_bytes=128).run(
            _command(fake_executable, "sleep", "30")
        )

    error = raised.value
    details = _process_details(error)
    assert error.code is ErrorCode.DOWNLOAD_TIMEOUT
    assert error.retryable
    assert details["timed_out"] is True
    assert details["output_limit_exceeded"] is False
    assert details["cleanup_succeeded"] is True
    assert str(details["stdout"]).strip() == "started"


def test_stdout_limit_terminates_process_and_keeps_only_bounded_diagnostics(
    fake_executable: Path,
) -> None:
    limit = 64

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner(timeout=5, max_stdout_bytes=limit).run(
            _command(fake_executable, "flood", "1000000")
        )

    details = _process_details(raised.value)
    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert details["output_limit_exceeded"] is True
    assert details["stdout_truncated"] is True
    assert len(str(details["stdout"]).encode("utf-8")) <= limit
    assert cast(int, details["stdout_total_bytes"]) > limit


def test_stderr_limit_uses_independent_budget(fake_executable: Path) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner(timeout=5, max_stdout_bytes=1024, max_stderr_bytes=16).run(
            _command(fake_executable, "flood-stderr", "100000")
        )

    details = _process_details(raised.value)
    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert details["stderr_truncated"] is True
    assert len(str(details["stderr"]).encode("utf-8")) <= 16


def test_output_exactly_at_limit_is_not_truncated(fake_executable: Path) -> None:
    result = ProcessRunner(max_stdout_bytes=64).run(_command(fake_executable, "flood", "64"))

    assert len(result.stdout.encode("utf-8")) == 64
    assert not result.stdout_truncated
    assert not result.output_limit_exceeded


def test_zero_capture_limit_allows_silent_process(fake_executable: Path) -> None:
    result = ProcessRunner(max_stdout_bytes=0, max_stderr_bytes=0).run(
        _command(fake_executable, "quiet")
    )

    assert result.succeeded
    assert result.stdout == ""
    assert result.stderr == ""


def test_invalid_utf8_is_replaced_not_raised(fake_executable: Path) -> None:
    result = ProcessRunner().run(_command(fake_executable, "invalid-utf8"))

    assert result.stdout == "\ufffd"


def test_timeout_cleans_up_grandchild_process(fake_executable: Path, tmp_path: Path) -> None:
    marker = tmp_path / "orphan-marker.txt"

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner(timeout=0.25).run(_command(fake_executable, "grandchild", str(marker), "0.8"))

    assert raised.value.code is ErrorCode.DOWNLOAD_TIMEOUT
    time.sleep(1.0)
    assert not marker.exists(), "el proceso nieto sobrevivió al timeout"


def test_normal_parent_exit_kills_grandchild_that_ignores_sigterm(
    fake_executable: Path,
    tmp_path: Path,
) -> None:
    marker = tmp_path / "late-orphan-marker.txt"
    ready = tmp_path / "child-ready.txt"

    result = ProcessRunner(termination_grace_seconds=0.15).run(
        _command(
            fake_executable,
            "grandchild-ignore-term",
            str(marker),
            str(ready),
            "0.7",
        )
    )

    assert result.returncode == 0
    assert result.cleanup_succeeded
    time.sleep(0.9)
    assert not marker.exists(), "el nieto ignoró SIGTERM y sobrevivió a la limpieza"


def test_capture_thread_start_failure_cleans_process(
    fake_executable: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "thread-start-orphan.txt"

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(_command(fake_executable, "delayed-marker", str(marker), "0.5"))

    assert raised.value.code is ErrorCode.DOWNLOAD_FAILED
    time.sleep(0.7)
    assert not marker.exists()


@pytest.mark.parametrize(
    "argv",
    [
        [],
        "cast --version",
        [""],
        ["cast\0evil"],
    ],
)
def test_malformed_argv_is_rejected_without_spawning(argv: object) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(cast(list[str], argv))

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_result_serialization_contains_no_environment_or_cwd(fake_executable: Path) -> None:
    result: ProcessResult = ProcessRunner().run(_command(fake_executable, "streams"))
    payload = result.to_dict()

    assert "env" not in payload
    assert "cwd" not in payload
    assert payload["argv"] == list(result.argv)


def test_explicit_working_directory_is_resolved_but_not_exposed(
    fake_executable: Path,
    tmp_path: Path,
) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir()

    result = ProcessRunner().run(
        _command(fake_executable, "cwd"),
        cwd=working_directory,
    )

    assert result.stdout.strip() == working_directory.name
    assert str(working_directory) not in repr(ProcessRunner())
    assert "cwd" not in result.to_dict()


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_invalid_working_directory_is_typed(
    fake_executable: Path,
    tmp_path: Path,
    kind: str,
) -> None:
    candidate = tmp_path / kind
    if kind == "file":
        candidate.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(_command(fake_executable, "quiet"), cwd=candidate)

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_invalid_native_executable_maps_spawn_failure(tmp_path: Path) -> None:
    executable = tmp_path / "invalid.exe"
    executable.write_bytes(b"this is not a native executable")
    executable.chmod(0o700)

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run([executable])

    assert raised.value.code is ErrorCode.DOWNLOAD_FAILED


def test_absolute_missing_executable_has_not_found_code(tmp_path: Path) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run([tmp_path / "missing.exe"])

    assert raised.value.code is ErrorCode.CAST_NOT_FOUND


def test_relative_only_path_entry_is_not_searched() -> None:
    runner = ProcessRunner(host_environment={"PATH": ".", "PATHEXT": ".EXE"})

    with pytest.raises(ProcessExecutionError) as raised:
        runner.run(["python"])

    assert raised.value.code is ErrorCode.CAST_NOT_FOUND


def test_custom_inherited_secret_is_redacted(fake_executable: Path) -> None:
    name = "CUSTOM_TOKEN"
    secret = "custom-super-secret"
    runner = ProcessRunner(
        environment_allowlist=DEFAULT_ALLOWED_ENVIRONMENT | {name},
        inherited_environment=DEFAULT_INHERITED_ENVIRONMENT | {name},
        secret_environment=DEFAULT_SECRET_ENVIRONMENT | {name},
        host_environment={**os.environ, name: secret},
    )

    result = runner.run(_command(fake_executable, "env", name))

    assert secret not in result.stdout
    assert "[REDACTADO]" in result.stdout


def test_invalid_inherited_environment_value_is_rejected(fake_executable: Path) -> None:
    runner = ProcessRunner(host_environment={**os.environ, "PATH": "invalid\0path"})

    with pytest.raises(ProcessExecutionError) as raised:
        runner.run(_command(fake_executable, "quiet"))

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_environment_value_with_nul_is_rejected(fake_executable: Path) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(
            _command(fake_executable, "quiet"),
            env={"NO_COLOR": "yes\0no"},
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_non_text_sensitive_value_is_rejected(fake_executable: Path) -> None:
    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(
            _command(fake_executable, "quiet"),
            sensitive_values=cast(tuple[str], (123,)),
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_constructor_rejects_invalid_numeric_limits() -> None:
    constructors: tuple[Callable[[], ProcessRunner], ...] = (
        lambda: ProcessRunner(timeout=0),
        lambda: ProcessRunner(timeout=True),
        lambda: ProcessRunner(timeout=float("inf")),
        lambda: ProcessRunner(timeout=cast(float, "invalid")),
        lambda: ProcessRunner(max_stdout_bytes=-1),
        lambda: ProcessRunner(max_stderr_bytes=True),
        lambda: ProcessRunner(termination_grace_seconds=-1),
        lambda: ProcessRunner(termination_grace_seconds=cast(float, "invalid")),
    )

    for constructor in constructors:
        with pytest.raises(ProcessExecutionError) as raised:
            constructor()
        assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


def test_constructor_rejects_invalid_environment_policies() -> None:
    constructors: tuple[Callable[[], ProcessRunner], ...] = (
        lambda: ProcessRunner(environment_allowlist={"BAD-NAME"}),
        lambda: ProcessRunner(environment_allowlist={"PATH"}, inherited_environment={"HOME"}),
        lambda: ProcessRunner(environment_allowlist={"PATH"}, secret_environment={"TOKEN"}),
    )

    for constructor in constructors:
        with pytest.raises(ProcessExecutionError) as raised:
            constructor()
        assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


@pytest.mark.skipif(os.name != "nt", reason="verifica la ruta de Job Objects de Windows")
def test_windows_job_handle_is_closed_even_if_explicit_termination_fails() -> None:
    class FailedTerminationJob:
        close_called = False

        def terminate(self) -> bool:
            return False

        def close(self) -> bool:
            self.close_called = True
            return True

    class ExitedProcess:
        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

        def poll(self) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("un proceso ya terminado no debe recibir kill")

    job = FailedTerminationJob()
    runner = ProcessRunner()

    cleaned = runner._terminate_tree(
        cast(subprocess.Popen[bytes], ExitedProcess()),
        cast(_WindowsJob, job),
    )

    assert not cleaned
    assert job.close_called


@pytest.mark.skipif(os.name != "nt", reason="verifica el handshake previo al Job Object")
def test_windows_assignment_failure_never_starts_target(
    fake_executable: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "must-not-start.txt"

    def fail_assign(_job: _WindowsJob, _process_id: int) -> None:
        raise OSError("assignment failed")

    monkeypatch.setattr(_WindowsJob, "assign", fail_assign)

    with pytest.raises(ProcessExecutionError) as raised:
        ProcessRunner().run(_command(fake_executable, "delayed-marker", str(marker), "0.1"))

    assert raised.value.code is ErrorCode.DOWNLOAD_FAILED
    time.sleep(0.3)
    assert not marker.exists()
