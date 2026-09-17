"""Prueba real opt-in; nunca forma parte de la validación offline normal."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from src.adapters.cast import CastAdapter
from src.adapters.process import ProcessRunner
from src.config import ConfigOverrides, load_config
from src.models import CodeValidationStatus, DownloadRequest, OverallStatus, SourceStatus
from src.service import SourceDownloader

WETH_MAINNET = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"


def _require_real_environment() -> None:
    if os.environ.get("SOURCETH_RUN_REAL") != "1":
        pytest.skip("requiere SOURCETH_RUN_REAL=1")
    if os.environ.get("ETH_RPC_URL", "").strip() == "":
        pytest.skip("requiere ETH_RPC_URL")
    if os.environ.get("ETHERSCAN_API_KEY", "").strip() == "":
        pytest.skip("requiere ETHERSCAN_API_KEY")
    configured_cast = os.environ.get("SOURCETH_CAST_PATH", "cast")
    if Path(configured_cast).is_absolute():
        if not Path(configured_cast).is_file():
            pytest.skip("la ruta configurada de Cast no existe")
    elif shutil.which(configured_cast) is None:
        pytest.skip("Cast no está instalado o no figura en PATH")
    if os.name == "nt":
        pytest.skip("cast source nativo está cerrado por seguridad en Windows; use Linux/WSL")


@pytest.mark.real
def test_mainnet_weth_rpc_validation_and_source_download(tmp_path: Path) -> None:
    """Valida una descarga real conocida sin fijar su contenido ni resultado exacto."""

    _require_real_environment()
    config = load_config(
        ConfigOverrides(output_dir=tmp_path / "downloads"),
        environ=os.environ,
        dotenv_path=None,
    )
    runner = ProcessRunner(
        timeout=config.process_timeout_seconds,
        max_stdout_bytes=config.limits.max_output_bytes,
        max_stderr_bytes=config.limits.max_output_bytes,
    )
    adapter = CastAdapter.from_config(runner, config)

    result = SourceDownloader(config, cast_adapter=adapter).fetch(
        DownloadRequest(
            address=WETH_MAINNET,
            chain_id=1,
            output_dir=tmp_path / "downloads",
            validation="rpc",
            follow_proxy=False,
            refresh=True,
        )
    )

    assert result.status is OverallStatus.COMPLETE
    assert result.observed_chain_id == 1
    assert result.observed_block is not None
    assert len(result.contracts) == 1
    contract = result.contracts[0]
    assert contract.code_validation_status is CodeValidationStatus.PRESENT
    assert contract.source_status is SourceStatus.DOWNLOADED
    assert contract.files
    assert result.manifest_path is not None and result.manifest_path.is_file()
    assert adapter.metrics.cast_invocations >= 1
