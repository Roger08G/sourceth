"""Pruebas offline del adaptador Cast y su frontera de seguridad."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from sourceth.adapters.cast import (
    CastAdapter,
    CastCapabilities,
    NativeSourceContainmentPolicy,
)
from sourceth.adapters.process import ProcessResult
from sourceth.config import RetryPolicy
from sourceth.errors import CastError, DownloadError, ErrorCode, ProcessExecutionError, RpcError
from sourceth.models import BlockObservation

ADDRESS = "0x" + ("1" * 40)
BLOCK_HASH = "0x" + ("a" * 64)
OTHER_BLOCK_HASH = "0x" + ("b" * 64)
VERSION_OUTPUT = "cast 1.8.1 (stable)"
SOURCE_HELP = """Usage: cast source [OPTIONS] <ADDRESS>
  --chain <CHAIN>
  -d <DIRECTORY>
  --etherscan-api-key <KEY>
  --explorer-api-url <EXPLORER_API_URL>
  --explorer-url <EXPLORER_URL>
"""
RPC_HELP = """Usage: cast rpc [OPTIONS] <METHOD> [PARAMS]...
  --raw
  --rpc-url <URL>
"""


@dataclass(frozen=True, slots=True)
class RunnerCall:
    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    timeout: float | None
    sensitive_values: tuple[str, ...]


class ScriptedRunner:
    """Runner determinista que conserva la llamada pública y devuelve un guion."""

    def __init__(
        self,
        responses: Sequence[ProcessResult | ProcessExecutionError],
        *,
        on_run: Callable[[RunnerCall], None] | None = None,
    ) -> None:
        self._responses = list(responses)
        self._on_run = on_run
        self.calls: list[RunnerCall] = []

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sensitive_values: Iterable[str] = (),
    ) -> ProcessResult:
        assert cwd is not None
        resolved_cwd = Path(cwd).resolve(strict=True)
        assert resolved_cwd.is_dir()
        assert sorted(path.name for path in resolved_cwd.iterdir()) == [".env", "foundry.toml"]
        assert (resolved_cwd / ".env").read_bytes() == b""
        assert (resolved_cwd / "foundry.toml").read_text(encoding="utf-8") == (
            "[profile.default]\n"
        )
        call = RunnerCall(
            argv=tuple(os.fspath(item) for item in argv),
            cwd=resolved_cwd,
            env=dict(env or {}),
            timeout=timeout,
            sensitive_values=tuple(sensitive_values),
        )
        self.calls.append(call)
        if self._on_run is not None:
            self._on_run(call)
        if not self._responses:
            raise AssertionError(f"llamada Cast inesperada: {call.argv!r}")
        response = self._responses.pop(0)
        if isinstance(response, ProcessExecutionError):
            raise response
        return response

    @property
    def pending(self) -> int:
        return len(self._responses)


class AllowContainment:
    def __init__(self) -> None:
        self.destinations: list[Path] = []

    def check(self, capabilities: CastCapabilities, destination: Path) -> None:
        assert capabilities.version == "1.8.1"
        self.destinations.append(destination)


def _result(
    stdout: str = "",
    *,
    stderr: str = "",
    returncode: int = 0,
    duration: float = 0.01,
) -> ProcessResult:
    return ProcessResult(
        argv=("cast",),
        executable=Path("cast"),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        stdout_total_bytes=len(stdout.encode()),
        stderr_total_bytes=len(stderr.encode()),
    )


def _capabilities(*, source_help: str = SOURCE_HELP) -> list[ProcessResult]:
    return [_result(VERSION_OUTPUT), _result(source_help)]


def _rpc_adapter(
    *rpc_results: ProcessResult | ProcessExecutionError,
    retry_policy: RetryPolicy | None = None,
    sleeper: Callable[[float], None] = lambda _delay: None,
    monotonic: Callable[[], float] | None = None,
    rpc_url: str = "https://user:password@rpc.invalid/token",
) -> tuple[CastAdapter, ScriptedRunner]:
    runner = ScriptedRunner([*_capabilities(), _result(RPC_HELP), *rpc_results])
    if monotonic is None:
        adapter = CastAdapter(
            runner,
            api_key="explorer-secret",
            rpc_url=rpc_url,
            retry_policy=retry_policy or RetryPolicy(max_attempts=1),
            sleeper=sleeper,
            random_value=lambda: 0.5,
        )
    else:
        adapter = CastAdapter(
            runner,
            api_key="explorer-secret",
            rpc_url=rpc_url,
            retry_policy=retry_policy or RetryPolicy(max_attempts=1),
            sleeper=sleeper,
            monotonic=monotonic,
            random_value=lambda: 0.5,
        )
    return adapter, runner


def test_capabilities_are_checked_once_and_reject_unknown_commands() -> None:
    runner = ScriptedRunner([*_capabilities(), _result(RPC_HELP)])
    adapter = CastAdapter(runner, retry_policy=RetryPolicy(max_attempts=1))

    first = adapter.check_capabilities(("rpc",))
    second = adapter.check_capabilities(("rpc", "source"))

    assert first == second
    assert first.version == "1.8.1"
    assert first.checked_commands == ("source", "rpc")
    assert [call.argv[1:] for call in runner.calls] == [
        ("--version",),
        ("source", "--help"),
        ("rpc", "--help"),
    ]
    assert all(not call.cwd.exists() for call in runner.calls)
    with pytest.raises(ValueError, match="no soportados"):
        adapter.check_capabilities(("code",))


def test_capability_snapshot_is_refreshed_between_high_level_executions() -> None:
    runner = ScriptedRunner(
        [
            *_capabilities(),
            _result("cast 1.8.2 (replacement)"),
            _result(SOURCE_HELP),
        ]
    )
    adapter = CastAdapter(runner, retry_policy=RetryPolicy(max_attempts=1))

    first = adapter.check_capabilities()
    second = adapter.check_capabilities(refresh=True)

    assert first.version == "1.8.1"
    assert second.version == "1.8.2"
    assert [call.argv[1:] for call in runner.calls] == [
        ("--version",),
        ("source", "--help"),
        ("--version",),
        ("source", "--help"),
    ]


def test_capabilities_accept_official_windows_cast_exe_usage_banner() -> None:
    windows_source_help = SOURCE_HELP.replace("Usage: cast source", "Usage: cast.exe source")
    windows_rpc_help = RPC_HELP.replace("Usage: cast rpc", "Usage: cast.exe rpc")
    runner = ScriptedRunner(
        [_result(VERSION_OUTPUT), _result(windows_source_help), _result(windows_rpc_help)]
    )
    adapter = CastAdapter(runner, retry_policy=RetryPolicy(max_attempts=1))

    capabilities = adapter.check_capabilities(("rpc",))

    assert capabilities.version == "1.8.1"
    assert capabilities.checked_commands == ("source", "rpc")


@pytest.mark.parametrize(
    ("responses", "expected_code"),
    [
        ([_result("unexpected version")], ErrorCode.CAST_UNSUPPORTED),
        (_capabilities(source_help="Usage: cast source <ADDRESS>\n"), ErrorCode.CAST_UNSUPPORTED),
        (
            [
                ProcessExecutionError(ErrorCode.CAST_NOT_FOUND, "no existe"),
            ],
            ErrorCode.CAST_NOT_FOUND,
        ),
    ],
)
def test_capability_failures_have_stable_codes(
    responses: list[ProcessResult | ProcessExecutionError], expected_code: ErrorCode
) -> None:
    adapter = CastAdapter(ScriptedRunner(responses), retry_policy=RetryPolicy(max_attempts=1))

    with pytest.raises(CastError) as raised:
        adapter.check_capabilities()

    assert raised.value.code is expected_code


def test_native_containment_policy_is_injectable_and_fail_closed() -> None:
    reviewed_output = "cast Version: 1.8.3\nCommit SHA: cae51ad458f6abb64852b7709eb784352429825d"
    stable = CastCapabilities("1.8.3", reviewed_output, ("source",))
    nightly = CastCapabilities(
        "1.8.0-nightly",
        "cast 1.8.0-nightly (abcdef 2026-01-01T00:00:00Z)",
        ("source",),
    )
    destination = Path("C:/staging")

    NativeSourceContainmentPolicy(platform="linux").check(stable, destination)
    NativeSourceContainmentPolicy(platform="win32", approved_windows_versions={"1.8.3"}).check(
        stable, destination
    )
    with pytest.raises(CastError) as windows_error:
        NativeSourceContainmentPolicy(platform="win32").check(stable, destination)
    with pytest.raises(CastError) as nightly_error:
        NativeSourceContainmentPolicy(platform="linux").check(nightly, destination)
    with pytest.raises(CastError) as version_error:
        NativeSourceContainmentPolicy(platform="linux").check(
            CastCapabilities("2.0.0", "cast 2.0.0", ("source",)), destination
        )

    assert windows_error.value.code is ErrorCode.UNSAFE_OUTPUT
    assert windows_error.value.details["reason"] == "windows_path_containment_not_proven"
    assert nightly_error.value.code is ErrorCode.CAST_UNSUPPORTED
    assert version_error.value.code is ErrorCode.CAST_UNSUPPORTED


def test_rpc_argv_uses_raw_json_and_secret_only_in_environment() -> None:
    rpc_url = "https://user:password@rpc.invalid/private?token=abc"
    adapter, runner = _rpc_adapter(_result('"0x1"\n'), rpc_url=rpc_url)

    assert adapter.get_chain_id() == 1

    call = runner.calls[-1]
    assert call.argv == ("cast", "rpc", "--raw", "eth_chainId", "[]")
    assert call.env == {"ETH_RPC_URL": rpc_url, "NO_COLOR": "1"}
    assert call.sensitive_values == (rpc_url,)
    assert rpc_url not in repr(adapter.invocations)
    assert all(
        rpc_url not in argument
        for invocation in adapter.invocations
        for argument in invocation.argv
    )


def test_chain_id_mismatch_and_invalid_rpc_quantities_are_distinct() -> None:
    adapter, _ = _rpc_adapter(_result('"0x2"'))
    with pytest.raises(RpcError) as mismatch:
        adapter.assert_chain_id(1)
    assert mismatch.value.code is ErrorCode.CHAIN_MISMATCH

    for raw in ('"0x01"', '"0x0"', '"1"', '"0x' + ("f" * 65) + '"'):
        invalid, _ = _rpc_adapter(_result(raw))
        with pytest.raises(RpcError) as raised:
            invalid.get_chain_id()
        assert raised.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT


@pytest.mark.parametrize(
    ("requested", "method", "reference"),
    [
        ("latest", "eth_getBlockByNumber", "latest"),
        (42, "eth_getBlockByNumber", "0x2a"),
        ("42", "eth_getBlockByNumber", "0x2a"),
        (BLOCK_HASH, "eth_getBlockByHash", BLOCK_HASH),
    ],
)
def test_observe_block_pins_number_and_hash(
    requested: int | str, method: str, reference: str
) -> None:
    payload = '{"hash":"' + BLOCK_HASH + '","number":"0x2a"}'
    adapter, runner = _rpc_adapter(_result(payload))

    observation = adapter.observe_block(requested)

    assert observation == BlockObservation(42, BLOCK_HASH)
    assert runner.calls[-1].argv[-2] == method
    assert runner.calls[-1].argv[-1] == f'["{reference}",false]'


def test_observe_block_rejects_mismatched_or_missing_provider_data() -> None:
    mismatched, _ = _rpc_adapter(_result('{"hash":"' + BLOCK_HASH + '","number":"0x2b"}'))
    with pytest.raises(RpcError) as wrong_number:
        mismatched.observe_block(42)
    assert wrong_number.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT

    missing, _ = _rpc_adapter(_result("null"))
    with pytest.raises(RpcError) as not_found:
        missing.observe_block(42)
    assert not_found.value.code is ErrorCode.RPC_ERROR


def test_block_change_is_detected_by_hash() -> None:
    payload = '{"hash":"' + OTHER_BLOCK_HASH + '","number":"0x2a"}'
    adapter, _ = _rpc_adapter(_result(payload))

    with pytest.raises(RpcError) as raised:
        adapter.verify_block_unchanged(BlockObservation(42, BLOCK_HASH))

    assert raised.value.code is ErrorCode.BLOCK_CHANGED
    assert raised.value.details["expected_hash"] == BLOCK_HASH
    assert raised.value.details["observed_hash"] == OTHER_BLOCK_HASH


def test_code_distinguishes_empty_from_single_zero_byte_and_uses_eip1898() -> None:
    empty, _ = _rpc_adapter(_result('"0x"'))
    with pytest.raises(RpcError) as no_code:
        empty.get_code(ADDRESS, BlockObservation(42, BLOCK_HASH))
    assert no_code.value.code is ErrorCode.NO_CODE_AT_BLOCK

    zero, runner = _rpc_adapter(_result('"0x00"'))
    code = zero.get_code(ADDRESS.upper().replace("0X", "0x"), BlockObservation(42, BLOCK_HASH))
    assert code == "0x00"
    assert runner.calls[-1].argv[-1] == (
        '["' + ADDRESS + '",{"blockHash":"' + BLOCK_HASH + '","requireCanonical":true}]'
    )


def test_state_reads_fall_back_to_number_when_rpc_rejects_eip1898() -> None:
    unsupported = _result(
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,'
        '"message":"invalid argument 1: json: cannot unmarshal object into Go value '
        'of type string"}}'
    )
    adapter, runner = _rpc_adapter(
        unsupported,
        _result('"0x00"'),
        _result('"0x01"'),
    )
    block = BlockObservation(42, BLOCK_HASH)

    assert adapter.get_code(ADDRESS, block) == "0x00"
    assert adapter.get_code(ADDRESS, block) == "0x01"

    rpc_calls = [call for call in runner.calls if call.argv[1:3] == ("rpc", "--raw")]
    assert len(rpc_calls) == 3
    assert (
        rpc_calls[0]
        .argv[-1]
        .endswith('{"blockHash":"' + BLOCK_HASH + '","requireCanonical":true}]')
    )
    assert rpc_calls[1].argv[-1] == '["' + ADDRESS + '","0x2a"]'
    assert rpc_calls[2].argv[-1] == '["' + ADDRESS + '","0x2a"]'


def test_state_reads_do_not_fall_back_on_unrelated_invalid_params() -> None:
    unrelated = _result(
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid address parameter"}}'
    )
    adapter, runner = _rpc_adapter(unrelated)

    with pytest.raises(RpcError) as raised:
        adapter.get_code(ADDRESS, BlockObservation(42, BLOCK_HASH))

    assert raised.value.code is ErrorCode.RPC_ERROR
    rpc_calls = [call for call in runner.calls if call.argv[1:3] == ("rpc", "--raw")]
    assert len(rpc_calls) == 1


def test_eth_call_does_not_misclassify_its_transaction_object_as_eip1898() -> None:
    ambiguous = _result(
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,'
        '"message":"json: cannot unmarshal object into Go value of type string"}}'
    )
    adapter, runner = _rpc_adapter(ambiguous)

    with pytest.raises(RpcError):
        adapter.eth_call(ADDRESS, "0x1234", BlockObservation(42, BLOCK_HASH))

    rpc_calls = [call for call in runner.calls if call.argv[1:3] == ("rpc", "--raw")]
    assert len(rpc_calls) == 1


def test_storage_and_eth_call_require_well_formed_bytes() -> None:
    word = "0x" + ("0" * 63) + "1"
    adapter, runner = _rpc_adapter(_result(f'"{word}"'), _result('"0xAABB"'))
    block = BlockObservation(42, BLOCK_HASH)

    assert adapter.get_storage_at(ADDRESS, 1, block) == word
    assert adapter.eth_call(ADDRESS, " 0xAAbb ", block) == "0xaabb"
    assert runner.calls[-2].argv[-1].startswith('["' + ADDRESS + '","0x1",')
    assert runner.calls[-1].argv[-1].startswith('[{"data":"0xaabb","to":"' + ADDRESS)

    malformed, _ = _rpc_adapter(_result('"0x00"'))
    with pytest.raises(RpcError) as raised:
        malformed.get_storage_at(ADDRESS, 0, block)
    assert raised.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT


@pytest.mark.parametrize(
    ("stderr", "expected", "retryable"),
    [
        ("Invalid API Key", ErrorCode.API_KEY_INVALID, False),
        ("Contract source code not verified", ErrorCode.SOURCE_NOT_VERIFIED, False),
        ("API credentials not verified", ErrorCode.DOWNLOAD_FAILED, False),
        ("Free API access is not supported", ErrorCode.PLAN_UNSUPPORTED, False),
        ("unsupported chain", ErrorCode.NETWORK_UNSUPPORTED, False),
        ("HTTP 500 Internal Server Error", ErrorCode.DOWNLOAD_TIMEOUT, True),
        ("temporary failure in name resolution", ErrorCode.DOWNLOAD_TIMEOUT, True),
        ("unexpected EOF", ErrorCode.DOWNLOAD_TIMEOUT, True),
        ("unexpected failure", ErrorCode.DOWNLOAD_FAILED, False),
    ],
)
def test_source_error_classification_is_stable(
    tmp_path: Path, stderr: str, expected: ErrorCode, retryable: bool
) -> None:
    runner = ScriptedRunner([*_capabilities(), _result(stderr=stderr, returncode=1)])
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )

    with pytest.raises(DownloadError) as raised:
        adapter.download_source(ADDRESS, 1, tmp_path / "sources")

    assert raised.value.code is expected
    assert raised.value.retryable is retryable


def test_rate_limit_retries_with_bounded_backoff_then_succeeds(tmp_path: Path) -> None:
    sleeps: list[float] = []
    elapsed = 0.0

    def sleep(delay: float) -> None:
        nonlocal elapsed
        sleeps.append(delay)
        elapsed += delay

    def write_source(call: RunnerCall) -> None:
        if len(call.argv) > 1 and call.argv[1] == "source" and len(runner.calls) == 5:
            destination = Path(call.argv[call.argv.index("-d") + 1])
            (destination / "Contract.sol").write_text("contract C {}", encoding="utf-8")

    runner = ScriptedRunner(
        [
            *_capabilities(),
            _result(stderr="HTTP 429 rate limit", returncode=1),
            _result(stderr="too many requests", returncode=1),
            _result(),
        ],
        on_run=write_source,
    )
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(
            max_attempts=3,
            base_delay_seconds=0.25,
            max_delay_seconds=1,
            budget_seconds=10,
            jitter_ratio=0,
        ),
        containment_policy=AllowContainment(),
        sleeper=sleep,
        monotonic=lambda: elapsed,
        random_value=lambda: 0.5,
    )

    attempt = adapter.download_source(ADDRESS, 1, tmp_path / "sources")

    assert attempt.attempts == 3
    assert attempt.duration_seconds == 0.75
    assert sleeps == [0.25, 0.5]
    assert adapter.metrics.retries == 2
    assert adapter.metrics.invocations_by_operation["source"] == 3
    assert [item.error_code for item in adapter.invocations[-3:]] == [
        ErrorCode.RATE_LIMITED,
        ErrorCode.RATE_LIMITED,
        None,
    ]


def test_json_rpc_error_with_zero_exit_is_retried_and_recorded_as_failed() -> None:
    sleeps: list[float] = []
    rate_limited = _result(
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"rate limit"}}'
    )
    adapter, runner = _rpc_adapter(
        rate_limited,
        _result('{"jsonrpc":"2.0","id":1,"result":"0x1"}'),
        retry_policy=RetryPolicy(
            max_attempts=2,
            base_delay_seconds=0.25,
            max_delay_seconds=1,
            budget_seconds=5,
            jitter_ratio=0,
        ),
        sleeper=sleeps.append,
    )

    assert adapter.get_chain_id() == 1

    rpc_calls = [call for call in runner.calls if call.argv[1:3] == ("rpc", "--raw")]
    rpc_invocations = [
        invocation
        for invocation in adapter.invocations
        if invocation.operation == "rpc:eth_chainId"
    ]
    assert len(rpc_calls) == 2
    assert sleeps == [0.25]
    assert not rpc_invocations[0].succeeded
    assert rpc_invocations[0].returncode == 0
    assert rpc_invocations[0].error_code is ErrorCode.RATE_LIMITED
    assert rpc_invocations[1].succeeded
    assert rpc_invocations[1].error_code is None


def test_source_retry_removes_partial_files_before_next_attempt(tmp_path: Path) -> None:
    source_attempt = 0

    def write_partial_then_success(call: RunnerCall) -> None:
        nonlocal source_attempt
        if len(call.argv) <= 1 or call.argv[1] != "source" or "-d" not in call.argv:
            return
        source_attempt += 1
        destination = Path(call.argv[call.argv.index("-d") + 1])
        if source_attempt == 1:
            (destination / "partial.sol").write_text("partial", encoding="utf-8")
            return
        assert list(destination.iterdir()) == []
        (destination / "Complete.sol").write_text("contract Complete {}", encoding="utf-8")

    runner = ScriptedRunner(
        [
            *_capabilities(),
            _result(stderr="rate limit", returncode=1),
            _result(),
        ],
        on_run=write_partial_then_success,
    )
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(
            max_attempts=2,
            base_delay_seconds=0,
            max_delay_seconds=0,
            budget_seconds=5,
            jitter_ratio=0,
        ),
        containment_policy=AllowContainment(),
        sleeper=lambda _delay: None,
        random_value=lambda: 0.5,
    )
    destination = (tmp_path / "sources").resolve()

    result = adapter.download_source(ADDRESS, 1, destination)

    assert result.files == ("Complete.sol",)
    assert not (destination / "partial.sol").exists()


def test_source_final_failure_leaves_an_empty_destination(tmp_path: Path) -> None:
    def write_partial(call: RunnerCall) -> None:
        if len(call.argv) > 1 and call.argv[1] == "source" and "-d" in call.argv:
            destination = Path(call.argv[call.argv.index("-d") + 1])
            (destination / "untrusted.sol").write_text("partial", encoding="utf-8")

    runner = ScriptedRunner(
        [*_capabilities(), _result(stderr="invalid api key", returncode=1)],
        on_run=write_partial,
    )
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )
    destination = (tmp_path / "sources").resolve()

    with pytest.raises(DownloadError) as raised:
        adapter.download_source(ADDRESS, 1, destination)

    assert raised.value.code is ErrorCode.API_KEY_INVALID
    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_retry_budget_prevents_an_extra_attempt(tmp_path: Path) -> None:
    runner = ScriptedRunner([*_capabilities(), _result(stderr="rate limit", returncode=1)])
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(
            max_attempts=3,
            base_delay_seconds=2,
            max_delay_seconds=2,
            budget_seconds=1,
            jitter_ratio=0,
        ),
        containment_policy=AllowContainment(),
        sleeper=lambda _delay: pytest.fail("no debe dormir fuera del presupuesto"),
        random_value=lambda: 0.5,
    )

    with pytest.raises(DownloadError) as raised:
        adapter.download_source(ADDRESS, 1, tmp_path / "sources")

    assert raised.value.code is ErrorCode.RATE_LIMITED
    assert adapter.metrics.retries == 0


def test_retry_budget_caps_the_timeout_of_each_process_attempt(tmp_path: Path) -> None:
    def write_source(call: RunnerCall) -> None:
        if len(call.argv) > 1 and call.argv[1] == "source" and "-d" in call.argv:
            destination = Path(call.argv[call.argv.index("-d") + 1])
            (destination / "Contract.sol").write_text("contract C {}", encoding="utf-8")

    runner = ScriptedRunner([*_capabilities(), _result()], on_run=write_source)
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1, budget_seconds=1),
        download_timeout_seconds=120,
        containment_policy=AllowContainment(),
    )

    adapter.download_source(ADDRESS, 1, (tmp_path / "sources").resolve())

    source_timeout = runner.calls[-1].timeout
    assert source_timeout is not None
    assert 0 < source_timeout <= 1


def test_process_output_limit_keeps_its_stable_error_code(tmp_path: Path) -> None:
    runner = ScriptedRunner(
        [
            *_capabilities(),
            ProcessExecutionError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "demasiada salida",
            ),
        ]
    )
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )

    with pytest.raises(DownloadError) as raised:
        adapter.download_source(ADDRESS, 1, (tmp_path / "sources").resolve())

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert not raised.value.retryable


def test_download_builds_exact_argv_and_preserves_multiple_files(tmp_path: Path) -> None:
    secret = "super-secret-api-key"

    def write_files(call: RunnerCall) -> None:
        if len(call.argv) > 1 and call.argv[1] == "source" and "-d" in call.argv:
            destination = Path(call.argv[call.argv.index("-d") + 1])
            (destination / "src").mkdir()
            (destination / "src" / "Token.sol").write_bytes(b"contract Token {}\r\n")
            (destination / "metadata.json").write_bytes(b"{}\n")

    containment = AllowContainment()
    runner = ScriptedRunner([*_capabilities(), _result(duration=0.5)], on_run=write_files)
    adapter = CastAdapter(
        runner,
        api_key=secret,
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=containment,
    )
    destination = (tmp_path / "sources").resolve()

    attempt = adapter.download_source(ADDRESS, 1, destination, timeout=9)

    assert attempt.files == ("metadata.json", "src/Token.sol")
    assert attempt.file_count == 2
    assert attempt.total_bytes == len(b"{}\ncontract Token {}\r\n")
    source_call = runner.calls[-1]
    assert source_call.argv == (
        "cast",
        "source",
        ADDRESS,
        "--chain",
        "1",
        "-d",
        str(destination),
    )
    assert source_call.timeout == 9
    assert source_call.env is not None
    assert source_call.env["ETHERSCAN_API_KEY"] == secret
    assert source_call.env["EXPLORER_API_URL"] == "https://api.etherscan.io/v2/api"
    assert source_call.env["EXPLORER_URL"] == "https://etherscan.io"
    assert source_call.env["NO_COLOR"] == "1"
    assert source_call.env["NO_PROXY"] == "__sourceth_force_proxy__.invalid"
    assert source_call.env["HTTPS_PROXY"].startswith("http://sourceth:")
    assert source_call.env["HTTP_PROXY"] == source_call.env["HTTPS_PROXY"]
    assert source_call.env["ALL_PROXY"] == source_call.env["HTTPS_PROXY"]
    assert secret not in repr(adapter.invocations)
    assert containment.destinations == [destination]


@pytest.mark.parametrize("payload", [{}, {"Empty.sol": b""}])
def test_download_rejects_empty_source_results(tmp_path: Path, payload: dict[str, bytes]) -> None:
    def write_files(call: RunnerCall) -> None:
        if len(call.argv) > 1 and call.argv[1] == "source" and "-d" in call.argv:
            destination = Path(call.argv[call.argv.index("-d") + 1])
            for relative, content in payload.items():
                (destination / relative).write_bytes(content)

    runner = ScriptedRunner([*_capabilities(), _result()], on_run=write_files)
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )

    with pytest.raises(DownloadError) as raised:
        adapter.download_source(ADDRESS, 1, (tmp_path / "sources").resolve())

    assert raised.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT


def test_download_rejects_relative_or_nonempty_destination_before_source_process(
    tmp_path: Path,
) -> None:
    relative = CastAdapter(
        ScriptedRunner([]),
        api_key="secret",
        containment_policy=AllowContainment(),
    )
    with pytest.raises(DownloadError) as relative_error:
        relative.download_source(ADDRESS, 1, "relative")
    assert relative_error.value.code is ErrorCode.INVALID_CONFIGURATION

    destination = (tmp_path / "sources").resolve()
    destination.mkdir()
    (destination / "existing.sol").write_text("keep", encoding="utf-8")
    runner = ScriptedRunner(_capabilities())
    adapter = CastAdapter(
        runner,
        api_key="secret",
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )
    with pytest.raises(DownloadError) as nonempty_error:
        adapter.download_source(ADDRESS, 1, destination)
    assert nonempty_error.value.code is ErrorCode.UNSAFE_OUTPUT
    assert (destination / "existing.sol").read_text(encoding="utf-8") == "keep"


def test_missing_credentials_fail_before_invoking_cast(tmp_path: Path) -> None:
    adapter = CastAdapter(ScriptedRunner([]), retry_policy=RetryPolicy(max_attempts=1))

    with pytest.raises(RpcError) as rpc_error:
        adapter.get_chain_id()
    with pytest.raises(DownloadError) as source_error:
        adapter.download_source(ADDRESS, 1, (tmp_path / "sources").resolve())

    assert rpc_error.value.code is ErrorCode.NETWORK_NOT_CONFIGURED
    assert source_error.value.code is ErrorCode.INVALID_CONFIGURATION
