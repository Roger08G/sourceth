"""Integración del adaptador con un ejecutable Cast simulado real."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import cast

from sourceth.adapters.cast import CastAdapter, CastCapabilities
from sourceth.adapters.process import ProcessResult, ProcessRunner
from sourceth.config import RetryPolicy
from sourceth.models import BlockObservation

ADDRESS = "0x" + ("1" * 40)
BLOCK_HASH = "0x" + ("a" * 64)


class PythonCastExecutable:
    """Traduce la ruta lógica de Cast al fixture Python multiplataforma."""

    def __init__(self, script: Path, state_directory: Path) -> None:
        self._script = script
        self._state_directory = state_directory
        self._runner = ProcessRunner(timeout=5)

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
        controlled_cwd = Path(cwd).resolve(strict=True)
        assert controlled_cwd.is_dir()
        assert sorted(path.name for path in controlled_cwd.iterdir()) == [
            ".env",
            "foundry.toml",
        ]
        assert (controlled_cwd / ".env").read_bytes() == b""
        logical_arguments = [os.fspath(item) for item in argv]
        return self._runner.run(
            [
                sys.executable,
                self._script,
                self._state_directory,
                *logical_arguments[1:],
            ],
            cwd=controlled_cwd,
            env=env,
            timeout=timeout,
            sensitive_values=sensitive_values,
        )


class AllowContainment:
    def check(self, capabilities: CastCapabilities, destination: Path) -> None:
        assert capabilities.version == "1.8.1"
        assert destination.is_absolute()


def _calls(state_directory: Path) -> list[dict[str, object]]:
    lines = (state_directory / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    return [cast(dict[str, object], json.loads(line)) for line in lines]


def test_full_adapter_flow_uses_real_subprocess_without_leaking_secrets(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "fake_cast.py"
    state = tmp_path / "state"
    rpc_secret = "https://user:password@rpc.invalid/private?token=rpc-secret"
    api_secret = "etherscan-secret-value"
    adapter = CastAdapter(
        PythonCastExecutable(fixture, state),
        cast_path="cast-simulado",
        rpc_url=rpc_secret,
        api_key=api_secret,
        retry_policy=RetryPolicy(max_attempts=1),
        containment_policy=AllowContainment(),
    )

    assert adapter.assert_chain_id(1) == 1
    block = adapter.observe_block("latest")
    assert block == BlockObservation(42, BLOCK_HASH)
    assert adapter.get_code(ADDRESS, block) == "0x00"
    download = adapter.download_source(ADDRESS, 1, (tmp_path / "sources").resolve())

    assert download.files == ("src/Contract.sol",)
    assert (download.directory / "src" / "Contract.sol").read_bytes().endswith(b"{}\n")
    calls = _calls(state)
    assert [item["arguments"] for item in calls] == [
        ["--version"],
        ["source", "--help"],
        ["rpc", "--help"],
        ["rpc", "--raw", "eth_chainId", "[]"],
        ["rpc", "--raw", "eth_getBlockByNumber", '["latest",false]'],
        [
            "rpc",
            "--raw",
            "eth_getCode",
            '["' + ADDRESS + '",{"blockHash":"' + BLOCK_HASH + '","requireCanonical":true}]',
        ],
        [
            "source",
            ADDRESS,
            "--chain",
            "1",
            "-d",
            str((tmp_path / "sources").resolve()),
        ],
    ]
    assert calls[-1]["api_key_configured"] is True
    assert calls[-1]["rpc_url_configured"] is False
    assert calls[-1]["explorer_api_url_configured"] is True
    assert calls[-1]["explorer_url_configured"] is True
    assert calls[-2]["api_key_configured"] is False
    assert calls[-2]["rpc_url_configured"] is True
    public = repr(adapter.invocations) + repr(adapter.metrics)
    assert api_secret not in public
    assert rpc_secret not in public
    assert adapter.metrics.cast_invocations == 7
