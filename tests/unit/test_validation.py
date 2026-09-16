"""Pruebas offline de las validaciones puras."""

from __future__ import annotations

from typing import cast

import pytest

from sourceth.errors import ConfigurationError, ErrorCode, ValidationError
from sourceth.models import DownloadRequest
from sourceth.validation import (
    runtime_bytecode_keccak,
    validate_address,
    validate_block_hash,
    validate_block_specifier,
    validate_chain_id,
    validate_env_name,
    validate_portable_relative_path,
    validate_request,
    validate_runtime_bytecode,
)

ZERO_ADDRESS = "0x" + ("0" * 40)
LOWER_ADDRESS = "0xde709f2102306220921060314715629080e2fb77"
CHECKSUM_ADDRESS = "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE"


@pytest.mark.parametrize(
    ("raw", "canonical", "checksum"),
    [
        (LOWER_ADDRESS, LOWER_ADDRESS, "0xde709f2102306220921060314715629080e2fb77"),
        (LOWER_ADDRESS.upper().replace("0X", "0x"), LOWER_ADDRESS, LOWER_ADDRESS),
        (CHECKSUM_ADDRESS, CHECKSUM_ADDRESS.lower(), CHECKSUM_ADDRESS),
        (ZERO_ADDRESS, ZERO_ADDRESS, ZERO_ADDRESS),
    ],
)
def test_validate_address_accepts_supported_forms(raw: str, canonical: str, checksum: str) -> None:
    result = validate_address(raw)

    assert result.original == raw
    assert result.trimmed == raw
    assert result.canonical == canonical
    assert result.checksum == checksum
    assert result.is_zero is (canonical == ZERO_ADDRESS)


def test_validate_address_trims_only_outer_whitespace() -> None:
    raw = f" \t{LOWER_ADDRESS}\r\n"

    result = validate_address(raw)

    assert result.original == raw
    assert result.trimmed == LOWER_ADDRESS
    assert result.canonical == LOWER_ADDRESS


def test_validate_address_rejects_bad_mixed_case_checksum() -> None:
    invalid = "0x5aEDA56215b167893e80B4fE645BA6d5Bab767DE"

    with pytest.raises(ValidationError) as raised:
        validate_address(invalid)

    assert raised.value.code is ErrorCode.INVALID_CHECKSUM


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0x",
        "0x1234",
        "0x" + ("0" * 39),
        "0x" + ("0" * 41),
        "0X" + ("0" * 40),
        "0x" + ("g" * 40),
        "0x" + ("0" * 20) + " " + ("0" * 20),
        "0x" + ("0" * 20) + "\n" + ("0" * 20),
        f"{LOWER_ADDRESS}; rm -rf /",
        f"https://etherscan.io/address/{LOWER_ADDRESS}",
        "vitalik.eth",
    ],
)
def test_validate_address_rejects_malformed_or_malicious_input(value: str) -> None:
    with pytest.raises(ValidationError) as raised:
        validate_address(value)

    assert raised.value.code is ErrorCode.INVALID_ADDRESS


def test_validate_address_rejects_non_text_without_echoing_value() -> None:
    with pytest.raises(ValidationError) as raised:
        validate_address(123)  # type: ignore[arg-type]

    assert raised.value.code is ErrorCode.INVALID_ADDRESS
    assert "123" not in str(raised.value)


@pytest.mark.parametrize(("value", "expected"), [(1, 1), (" 1 ", 1), ("11155111", 11155111)])
def test_validate_chain_id_accepts_positive_decimal(value: int | str, expected: int) -> None:
    assert validate_chain_id(value) == expected


@pytest.mark.parametrize("value", [True, False, 0, -1, "", "0", "-1", "0x1", "1.0"])
def test_validate_chain_id_rejects_non_positive_or_non_decimal(value: int | str) -> None:
    with pytest.raises(ValueError):
        validate_chain_id(value)


@pytest.mark.parametrize("name", ["ETH_RPC_URL", "_PRIVATE", "SOURCETH_1"])
def test_validate_env_name_accepts_portable_names(name: str) -> None:
    assert validate_env_name(name, field_name="test") == name


@pytest.mark.parametrize("name", ["", "1KEY", "API-KEY", "API KEY", "KEY=value", "KEY\0X"])
def test_validate_env_name_rejects_unsafe_names(name: str) -> None:
    with pytest.raises(ValueError):
        validate_env_name(name, field_name="test")


def test_runtime_bytecode_distinguishes_empty_from_single_zero_byte() -> None:
    empty_hash = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    assert validate_runtime_bytecode(" 0x ") == "0x"
    assert validate_runtime_bytecode("0x00") == "0x00"
    assert validate_runtime_bytecode("0xAa00") == "0xaa00"
    assert runtime_bytecode_keccak("0x") == empty_hash
    assert runtime_bytecode_keccak("0x00") != empty_hash


@pytest.mark.parametrize("value", ["", "00", "0x0", "0x0g", "0x00 00", "0X00"])
def test_validate_runtime_bytecode_rejects_malformed_hex(value: str) -> None:
    with pytest.raises(ValueError):
        validate_runtime_bytecode(value)


def test_validate_block_hash_and_specifiers() -> None:
    block_hash = "0x" + ("AB" * 32)

    assert validate_block_hash(block_hash) == block_hash.lower()
    assert validate_block_specifier(None) is None
    assert validate_block_specifier("latest") == "latest"
    assert validate_block_specifier(" 42 ") == 42
    assert validate_block_specifier(0) == 0
    assert validate_block_specifier(block_hash) == block_hash.lower()


@pytest.mark.parametrize("value", [True, -1, "-1", "LATEST", "pending", "0x12", "abc"])
def test_validate_block_specifier_rejects_unsupported_values(value: int | str) -> None:
    with pytest.raises(ValueError):
        validate_block_specifier(value)


def test_validate_request_accepts_zero_address_in_rpc_mode() -> None:
    result = validate_request(DownloadRequest(address=ZERO_ADDRESS, block="latest"))

    assert result.is_zero


@pytest.mark.parametrize(
    "download_request",
    [
        DownloadRequest(address=LOWER_ADDRESS, validation="explorer", block=1),
        DownloadRequest(address=LOWER_ADDRESS, validation="explorer", follow_proxy=True),
        DownloadRequest(address=LOWER_ADDRESS, validation="invalid"),
        DownloadRequest(address=LOWER_ADDRESS, max_depth=0),
        DownloadRequest(address=LOWER_ADDRESS, max_depth=True),
        DownloadRequest(address=LOWER_ADDRESS, timeout=0),
        DownloadRequest(address=LOWER_ADDRESS, timeout=True),
        DownloadRequest(address=LOWER_ADDRESS, timeout=float("nan")),
        DownloadRequest(address=LOWER_ADDRESS, timeout=float("inf")),
        DownloadRequest(address=LOWER_ADDRESS, chain_id=0),
        DownloadRequest(address=LOWER_ADDRESS, chain_id=cast(int, "1")),
        DownloadRequest(address=LOWER_ADDRESS, block=cast(int | str | None, 1.5)),
        DownloadRequest(address=LOWER_ADDRESS, follow_proxy=cast(bool, "yes")),
        DownloadRequest(address=LOWER_ADDRESS, refresh=cast(bool, 1)),
        DownloadRequest(address=LOWER_ADDRESS, output_dir=""),
        DownloadRequest(address=LOWER_ADDRESS, output_dir="bad\x00path"),
        DownloadRequest(address=LOWER_ADDRESS, output_dir=cast(str, object())),
    ],
)
def test_validate_request_rejects_contradictory_configuration(
    download_request: DownloadRequest,
) -> None:
    with pytest.raises(ConfigurationError) as raised:
        validate_request(download_request)

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Contract.sol", "Contract.sol"),
        ("src/lib/Contract.vy", "src/lib/Contract.vy"),
        (r"src\Contract.sol", "src/Contract.sol"),
        ("Unicode-ñ.sol", "Unicode-ñ.sol"),
    ],
)
def test_validate_portable_relative_path_normalizes_safe_paths(value: str, expected: str) -> None:
    assert validate_portable_relative_path(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/absolute.sol",
        r"\server\share\Contract.sol",
        r"C:\Contract.sol",
        "../Contract.sol",
        "src/../Contract.sol",
        "./Contract.sol",
        "src//Contract.sol",
        "src/Contract.sol/",
        "src/CON.sol",
        "src/CONIN$.sol",
        "src/CONOUT$.txt",
        "src/COM¹.sol",
        "src/COM²",
        "src/LPT³.txt",
        "src/NUL",
        "src/name.",
        "src/name ",
        "src/na:me.sol",
        "src/*.sol",
        "src/name\0.sol",
        "src/control\x01.sol",
    ],
)
def test_validate_portable_relative_path_rejects_cross_platform_hazards(value: str) -> None:
    with pytest.raises(ValueError):
        validate_portable_relative_path(value)
