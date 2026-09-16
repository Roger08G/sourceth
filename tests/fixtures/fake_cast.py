"""Ejecutable Cast simulado para las pruebas de integración offline.

Se invoca mediante el intérprete de la suite para que el mismo fixture funcione
en Windows y POSIX. Nunca persiste valores de credenciales, solo su presencia.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import cast

BLOCK_HASH = "0x" + ("a" * 64)


def _append_call(state_directory: Path, arguments: list[str]) -> None:
    payload = {
        "arguments": arguments,
        "api_key_configured": bool(os.environ.get("ETHERSCAN_API_KEY")),
        "rpc_url_configured": bool(os.environ.get("ETH_RPC_URL")),
        "explorer_api_url_configured": bool(os.environ.get("EXPLORER_API_URL")),
        "explorer_url_configured": bool(os.environ.get("EXPLORER_URL")),
        "no_color": os.environ.get("NO_COLOR"),
    }
    with (state_directory / "calls.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")


def _rpc(method: str, raw_params: str) -> object:
    params = cast(list[object], json.loads(raw_params))
    if method == "eth_chainId":
        assert params == []
        return "0x1"
    if method == "eth_getBlockByNumber":
        assert params == ["latest", False]
        return {"number": "0x2a", "hash": BLOCK_HASH}
    if method == "eth_getCode":
        assert len(params) == 2
        return "0x00"
    raise AssertionError(f"método RPC inesperado: {method}")


def main() -> int:
    state_directory = Path(sys.argv[1])
    state_directory.mkdir(parents=True, exist_ok=True)
    arguments = sys.argv[2:]
    _append_call(state_directory, arguments)

    if arguments == ["--version"]:
        print("cast 1.8.1 (fake integration executable)")
        return 0
    if arguments == ["source", "--help"]:
        print(
            "Usage: cast source [OPTIONS] <ADDRESS>\n"
            "  --chain <CHAIN>\n"
            "  -d <DIRECTORY>\n"
            "  --etherscan-api-key <KEY>\n"
            "  --explorer-api-url <EXPLORER_API_URL>\n"
            "  --explorer-url <EXPLORER_URL>"
        )
        return 0
    if arguments == ["rpc", "--help"]:
        print("Usage: cast rpc [OPTIONS] <METHOD>\n  --raw\n  --rpc-url <URL>")
        return 0
    if arguments[:2] == ["rpc", "--raw"]:
        print(json.dumps(_rpc(arguments[2], arguments[3]), separators=(",", ":")))
        return 0
    if len(arguments) >= 2 and arguments[0] == "source":
        destination = Path(arguments[arguments.index("-d") + 1])
        (destination / "src").mkdir()
        (destination / "src" / "Contract.sol").write_bytes(
            b"// SPDX-License-Identifier: MIT\ncontract Contract {}\n"
        )
        return 0
    print("invocación no soportada", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
