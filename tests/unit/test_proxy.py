"""Pruebas offline y deterministas del resolvedor de proxies soportados."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from src.errors import ConfigurationError, ErrorCode, SourcethError
from src.models import (
    BlockObservation,
    CodeValidationStatus,
    ContractRole,
    ProxyResolutionStatus,
    RelationKind,
)
from src.proxy import (
    BEACON_IMPLEMENTATION_CALLDATA,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    ERC1167_PREFIX,
    ERC1167_SUFFIX,
    ProxyResolutionResult,
    ProxyResolver,
    ResolvedContract,
    _State,
)
from src.validation import validate_address

ROOT = "0x1111111111111111111111111111111111111111"
IMPLEMENTATION = "0x2222222222222222222222222222222222222222"
SECOND_IMPLEMENTATION = "0x3333333333333333333333333333333333333333"
BEACON = "0x4444444444444444444444444444444444444444"
ZERO_ADDRESS = "0x" + ("0" * 40)
ZERO_WORD = "0x" + ("0" * 64)
BLOCK = BlockObservation(number=19_876_543, hash="0x" + ("ab" * 32))
NON_PROXY_CODE = "0x6001600055"

type BlockSpecifier = BlockObservation | int | str
type RpcResponse = str | SourcethError


def _word(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


def _clone_runtime(address: str) -> str:
    return f"0x{ERC1167_PREFIX}{address[2:]}{ERC1167_SUFFIX}"


def _error(code: ErrorCode = ErrorCode.RPC_ERROR) -> SourcethError:
    return SourcethError(code, "fallo RPC simulado")


def _respond(response: RpcResponse) -> str:
    if isinstance(response, SourcethError):
        raise response
    return response


class RecordingAdapter:
    """Doble RPC estricto que conserva cada referencia de bloque recibida."""

    def __init__(
        self,
        *,
        codes: Mapping[str, RpcResponse],
        storage: Mapping[tuple[str, str | int], RpcResponse] | None = None,
        calls: Mapping[tuple[str, str], RpcResponse] | None = None,
        default_storage: RpcResponse = ZERO_WORD,
    ) -> None:
        self.codes = dict(codes)
        self.storage = dict(storage or {})
        self.calls = dict(calls or {})
        self.default_storage = default_storage
        self.code_requests: list[tuple[str, BlockSpecifier]] = []
        self.storage_requests: list[tuple[str, str | int, BlockSpecifier]] = []
        self.call_requests: list[tuple[str, str, BlockSpecifier]] = []
        self.blocks: list[BlockSpecifier] = []

    def get_code(self, address: str, block: BlockSpecifier) -> str:
        self.code_requests.append((address, block))
        self.blocks.append(block)
        try:
            response = self.codes[address]
        except KeyError as error:
            raise AssertionError(f"get_code inesperado para {address}") from error
        return _respond(response)

    def get_storage_at(
        self,
        address: str,
        slot: str | int,
        block: BlockSpecifier,
    ) -> str:
        self.storage_requests.append((address, slot, block))
        self.blocks.append(block)
        return _respond(self.storage.get((address, slot), self.default_storage))

    def eth_call(self, address: str, calldata: str, block: BlockSpecifier) -> str:
        self.call_requests.append((address, calldata, block))
        self.blocks.append(block)
        try:
            response = self.calls[(address, calldata)]
        except KeyError as error:
            raise AssertionError(f"eth_call inesperado para {address} con {calldata}") from error
        return _respond(response)


def _contract(result: ProxyResolutionResult, address: str) -> ResolvedContract:
    return next(contract for contract in result.contracts if contract.address == address)


def _diagnostic_codes(result: ProxyResolutionResult) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def _assert_same_block(adapter: RecordingAdapter, block: BlockObservation) -> None:
    assert adapter.blocks
    assert all(observed is block for observed in adapter.blocks)


def test_eip1967_implementation_is_resolved_with_exact_evidence_and_block() -> None:
    raw_slot = _word(IMPLEMENTATION)
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x6002"},
        storage={(ROOT, EIP1967_IMPLEMENTATION_SLOT): raw_slot},
    )

    result = ProxyResolver(adapter).resolve(ROOT.upper().replace("0X", "0x"), BLOCK)

    assert result.root_address == ROOT
    assert result.block is BLOCK
    assert result.status is ProxyResolutionStatus.RESOLVED
    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert result.code_lookups == 2
    assert result.code_cache_hits == 0
    root = _contract(result, ROOT)
    implementation = _contract(result, IMPLEMENTATION)
    assert root.roles == (ContractRole.ROOT,)
    assert root.depth == 0
    assert implementation.roles == (ContractRole.IMPLEMENTATION,)
    assert implementation.role is ContractRole.IMPLEMENTATION
    assert implementation.depth == 1
    assert implementation.runtime_bytecode == "0x6002"
    assert implementation.code_validation_status is CodeValidationStatus.PRESENT
    assert len(result.relations) == 1
    relation = result.relations[0]
    assert relation.source_address == ROOT
    assert relation.target_address == IMPLEMENTATION
    assert relation.kind is RelationKind.IMPLEMENTATION
    assert relation.detection_method == "eip1967_implementation_slot"
    assert dict(relation.evidence) == {
        "standard": "EIP-1967",
        "slot": EIP1967_IMPLEMENTATION_SLOT,
        "raw_value": raw_slot,
        "semantics_confirmed": False,
        "block_number": BLOCK.number,
        "block_hash": BLOCK.hash,
    }
    assert (ROOT, EIP1967_BEACON_SLOT, BLOCK) not in adapter.storage_requests
    _assert_same_block(adapter, BLOCK)


def test_eip1967_implementation_slot_takes_precedence_over_beacon_slot() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x6002"},
        storage={
            (ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION),
            (ROOT, EIP1967_BEACON_SLOT): _word(BEACON),
        },
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert [relation.kind for relation in result.relations] == [RelationKind.IMPLEMENTATION]
    assert not adapter.call_requests
    assert (ROOT, EIP1967_BEACON_SLOT, BLOCK) not in adapter.storage_requests


def test_eip1967_beacon_resolves_implementation_and_preserves_evidence() -> None:
    beacon_slot = _word(BEACON)
    call_result = _word(IMPLEMENTATION)
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, BEACON: "0x6003", IMPLEMENTATION: "0x6004"},
        storage={(ROOT, EIP1967_BEACON_SLOT): beacon_slot},
        calls={(BEACON, BEACON_IMPLEMENTATION_CALLDATA): call_result},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.RESOLVED
    assert result.addresses == (ROOT, BEACON, IMPLEMENTATION)
    assert result.code_lookups == 3
    beacon = _contract(result, BEACON)
    implementation = _contract(result, IMPLEMENTATION)
    assert beacon.roles == (ContractRole.BEACON,)
    assert beacon.role is ContractRole.BEACON
    assert beacon.depth == 1
    assert implementation.roles == (ContractRole.IMPLEMENTATION,)
    assert implementation.depth == 2
    assert [relation.kind for relation in result.relations] == [
        RelationKind.BEACON,
        RelationKind.BEACON_IMPLEMENTATION,
    ]
    assert dict(result.relations[0].evidence) == {
        "standard": "EIP-1967",
        "slot": EIP1967_BEACON_SLOT,
        "raw_value": beacon_slot,
        "semantics_confirmed": False,
        "block_number": BLOCK.number,
        "block_hash": BLOCK.hash,
    }
    assert dict(result.relations[1].evidence) == {
        "standard": "EIP-1967",
        "calldata": BEACON_IMPLEMENTATION_CALLDATA,
        "raw_result": call_result,
        "semantics_confirmed": False,
        "block_number": BLOCK.number,
        "block_hash": BLOCK.hash,
    }
    assert adapter.call_requests == [(BEACON, BEACON_IMPLEMENTATION_CALLDATA, BLOCK)]
    _assert_same_block(adapter, BLOCK)


@pytest.mark.parametrize("uppercase_body", [False, True], ids=["lowercase", "uppercase-body"])
def test_exact_canonical_erc1167_runtime_is_resolved(uppercase_body: bool) -> None:
    runtime = _clone_runtime(IMPLEMENTATION)
    if uppercase_body:
        runtime = "0x" + runtime[2:].upper()
    adapter = RecordingAdapter(codes={ROOT: runtime, IMPLEMENTATION: "0x6005"})

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.RESOLVED
    assert result.addresses == (ROOT, IMPLEMENTATION)
    relation = result.relations[0]
    assert relation.kind is RelationKind.IMPLEMENTATION
    assert relation.detection_method == "erc1167_canonical_runtime"
    assert dict(relation.evidence) == {
        "standard": "ERC-1167",
        "pattern": "canonical_runtime_exact",
        "runtime_length_bytes": 45,
        "runtime_bytecode": _clone_runtime(IMPLEMENTATION),
        "semantics_confirmed": False,
        "block_number": BLOCK.number,
        "block_hash": BLOCK.hash,
    }
    assert all(address != ROOT for address, _, _ in adapter.storage_requests)
    _assert_same_block(adapter, BLOCK)


CANONICAL_CLONE = _clone_runtime(IMPLEMENTATION)


@pytest.mark.parametrize(
    "runtime",
    [
        "0x37" + CANONICAL_CLONE[4:],
        CANONICAL_CLONE[:-2] + "f2",
        "0x00" + CANONICAL_CLONE[2:],
        CANONICAL_CLONE + "00",
        CANONICAL_CLONE[:-2],
        "0x6000" + CANONICAL_CLONE[2:] + "00",
    ],
    ids=[
        "wrong-prefix",
        "wrong-suffix",
        "leading-byte",
        "trailing-byte",
        "truncated",
        "embedded-runtime",
    ],
)
def test_noncanonical_erc1167_variants_are_rejected(runtime: str) -> None:
    adapter = RecordingAdapter(codes={ROOT: runtime})

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED
    assert result.addresses == (ROOT,)
    assert not result.relations
    assert ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED.value in _diagnostic_codes(result)
    assert [request[:2] for request in adapter.storage_requests] == [
        (ROOT, EIP1967_IMPLEMENTATION_SLOT),
        (ROOT, EIP1967_BEACON_SLOT),
    ]


def test_canonical_erc1167_with_zero_target_is_an_explicit_failure() -> None:
    adapter = RecordingAdapter(codes={ROOT: _clone_runtime(ZERO_ADDRESS)})

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.FAILED
    assert result.addresses == (ROOT,)
    assert not result.relations
    assert _diagnostic_codes(result) == {"ERC1167_IMPLEMENTATION_NULL"}
    assert not adapter.storage_requests


def test_cycle_is_bounded_merges_roles_and_does_not_reload_code() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x6002"},
        storage={
            (ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION),
            (IMPLEMENTATION, EIP1967_IMPLEMENTATION_SLOT): _word(ROOT),
        },
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.CYCLE
    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert [relation.target_address for relation in result.relations] == [IMPLEMENTATION, ROOT]
    assert _contract(result, ROOT).roles == (
        ContractRole.ROOT,
        ContractRole.IMPLEMENTATION,
    )
    assert _contract(result, ROOT).role is ContractRole.ROOT
    assert _contract(result, IMPLEMENTATION).roles == (ContractRole.IMPLEMENTATION,)
    assert result.code_lookups == 2
    assert result.code_cache_hits == 0
    assert [request[0] for request in adapter.code_requests] == [ROOT, IMPLEMENTATION]
    assert ErrorCode.PROXY_CYCLE.value in _diagnostic_codes(result)


def test_beacon_self_cycle_merges_beacon_and_implementation_roles() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, BEACON: "0x6003"},
        storage={(ROOT, EIP1967_BEACON_SLOT): _word(BEACON)},
        calls={(BEACON, BEACON_IMPLEMENTATION_CALLDATA): _word(BEACON)},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.CYCLE
    assert _contract(result, BEACON).roles == (
        ContractRole.BEACON,
        ContractRole.IMPLEMENTATION,
    )
    assert _contract(result, BEACON).role is ContractRole.BEACON
    assert result.code_lookups == 2


def test_code_cache_is_used_when_the_same_registered_node_is_checked_twice() -> None:
    adapter = RecordingAdapter(codes={ROOT: NON_PROXY_CODE})
    resolver = ProxyResolver(adapter)
    state = _State(block=BLOCK)
    first_node = resolver._register(
        state,
        validate_address(ROOT),
        ContractRole.ROOT,
        depth=0,
    )

    resolver._ensure_code(state, first_node)
    cached_node = resolver._register(
        state,
        validate_address(ROOT),
        ContractRole.IMPLEMENTATION,
        depth=1,
    )
    resolver._ensure_code(state, cached_node)
    resolver._ensure_code(state, cached_node)

    assert first_node.runtime_bytecode == NON_PROXY_CODE
    assert cached_node.runtime_bytecode == NON_PROXY_CODE
    assert cached_node.code_status is CodeValidationStatus.PRESENT
    assert cached_node.roles == [ContractRole.IMPLEMENTATION]
    assert state.code_lookups == 1
    assert state.code_cache_hits == 2
    assert adapter.code_requests == [(ROOT, BLOCK)]


def test_max_depth_records_candidate_relation_without_registering_target() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x6002"},
        storage={
            (ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION),
            (IMPLEMENTATION, EIP1967_IMPLEMENTATION_SLOT): _word(SECOND_IMPLEMENTATION),
        },
    )

    result = ProxyResolver(adapter, max_depth=1, max_addresses=10).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.LIMIT_REACHED
    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert [relation.target_address for relation in result.relations] == [
        IMPLEMENTATION,
        SECOND_IMPLEMENTATION,
    ]
    assert SECOND_IMPLEMENTATION not in result.addresses
    diagnostic = next(
        item for item in result.diagnostics if item.code == ErrorCode.PROXY_LIMIT_REACHED.value
    )
    assert dict(diagnostic.details) == {
        "max_depth": 1,
        "target_address": SECOND_IMPLEMENTATION,
    }
    assert result.code_lookups == 2


def test_max_addresses_records_candidate_relation_without_loading_target() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x6002"},
        storage={
            (ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION),
            (IMPLEMENTATION, EIP1967_IMPLEMENTATION_SLOT): _word(SECOND_IMPLEMENTATION),
        },
    )

    result = ProxyResolver(adapter, max_depth=5, max_addresses=2).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.LIMIT_REACHED
    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert [relation.target_address for relation in result.relations] == [
        IMPLEMENTATION,
        SECOND_IMPLEMENTATION,
    ]
    diagnostic = next(
        item for item in result.diagnostics if item.code == ErrorCode.PROXY_LIMIT_REACHED.value
    )
    assert dict(diagnostic.details) == {
        "max_addresses": 2,
        "target_address": SECOND_IMPLEMENTATION,
    }
    assert [request[0] for request in adapter.code_requests] == [ROOT, IMPLEMENTATION]


@pytest.mark.parametrize(
    ("max_depth", "max_addresses"),
    [(0, 10), (-1, 10), (5, 0), (5, -1)],
)
def test_nonpositive_limits_are_rejected(max_depth: int, max_addresses: int) -> None:
    adapter = RecordingAdapter(codes={})

    with pytest.raises(ConfigurationError) as raised:
        ProxyResolver(adapter, max_depth=max_depth, max_addresses=max_addresses)

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


@pytest.mark.parametrize(
    "code_response",
    ["0x", _error(ErrorCode.NO_CODE_AT_BLOCK)],
    ids=["empty-code-response", "typed-no-code-error"],
)
def test_resolved_implementation_without_code_is_partial_and_explicit(
    code_response: RpcResponse,
) -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: code_response},
        storage={(ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION)},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.PARTIAL
    assert result.addresses == (ROOT, IMPLEMENTATION)
    assert len(result.relations) == 1
    implementation = _contract(result, IMPLEMENTATION)
    assert implementation.runtime_bytecode is None
    assert implementation.code_validation_status is CodeValidationStatus.NO_CODE
    assert [item.code for item in implementation.diagnostics] == [ErrorCode.NO_CODE_AT_BLOCK.value]
    assert ErrorCode.NO_CODE_AT_BLOCK.value in _diagnostic_codes(result)


def test_malformed_implementation_code_is_partial_not_absent_code() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, IMPLEMENTATION: "0x0g"},
        storage={(ROOT, EIP1967_IMPLEMENTATION_SLOT): _word(IMPLEMENTATION)},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    implementation = _contract(result, IMPLEMENTATION)
    assert result.status is ProxyResolutionStatus.PARTIAL
    assert implementation.code_validation_status is CodeValidationStatus.FAILED
    assert ErrorCode.INVALID_PROVIDER_OUTPUT.value in _diagnostic_codes(result)
    assert ErrorCode.NO_CODE_AT_BLOCK.value not in _diagnostic_codes(result)


@pytest.mark.parametrize(
    ("response", "expected_code_status", "diagnostic_code"),
    [
        ("0x", CodeValidationStatus.NO_CODE, ErrorCode.NO_CODE_AT_BLOCK.value),
        (
            _error(ErrorCode.NO_CODE_AT_BLOCK),
            CodeValidationStatus.NO_CODE,
            ErrorCode.NO_CODE_AT_BLOCK.value,
        ),
        (
            _error(ErrorCode.RPC_ERROR),
            CodeValidationStatus.FAILED,
            ErrorCode.PROXY_RESOLUTION_FAILED.value,
        ),
        (
            "invalid",
            CodeValidationStatus.FAILED,
            ErrorCode.INVALID_PROVIDER_OUTPUT.value,
        ),
    ],
    ids=["empty", "typed-no-code", "rpc-error", "malformed"],
)
def test_root_code_failures_do_not_attempt_storage(
    response: RpcResponse,
    expected_code_status: CodeValidationStatus,
    diagnostic_code: str,
) -> None:
    adapter = RecordingAdapter(codes={ROOT: response})

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.FAILED
    assert result.addresses == (ROOT,)
    assert _contract(result, ROOT).code_validation_status is expected_code_status
    assert diagnostic_code in _diagnostic_codes(result)
    assert not result.relations
    assert not adapter.storage_requests
    assert not adapter.call_requests


def test_storage_errors_are_recorded_independently_and_do_not_create_relations() -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE},
        storage={
            (ROOT, EIP1967_IMPLEMENTATION_SLOT): _error(ErrorCode.RPC_ERROR),
            (ROOT, EIP1967_BEACON_SLOT): _error(ErrorCode.BLOCK_CHANGED),
        },
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.FAILED
    assert not result.relations
    assert [item.code for item in result.diagnostics] == [
        ErrorCode.PROXY_RESOLUTION_FAILED.value,
        ErrorCode.PROXY_RESOLUTION_FAILED.value,
    ]
    assert [item.details["upstream_code"] for item in result.diagnostics] == [
        ErrorCode.RPC_ERROR.value,
        ErrorCode.BLOCK_CHANGED.value,
    ]
    _assert_same_block(adapter, BLOCK)


@pytest.mark.parametrize(
    ("slot", "malformed"),
    [
        (EIP1967_IMPLEMENTATION_SLOT, "0x1234"),
        (EIP1967_IMPLEMENTATION_SLOT, "0x" + ("01" * 12) + IMPLEMENTATION[2:]),
        (EIP1967_BEACON_SLOT, "not-hex"),
    ],
    ids=[
        "implementation-wrong-length",
        "implementation-nonzero-abi-padding",
        "beacon-non-hex",
    ],
)
def test_malformed_storage_is_invalid_provider_output(slot: str, malformed: str) -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE},
        storage={(ROOT, slot): malformed},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.FAILED
    assert not result.relations
    assert ErrorCode.INVALID_PROVIDER_OUTPUT.value in _diagnostic_codes(result)
    assert ErrorCode.NO_CODE_AT_BLOCK.value not in _diagnostic_codes(result)


@pytest.mark.parametrize(
    ("call_response", "diagnostic_code"),
    [
        (_error(ErrorCode.RPC_ERROR), "BEACON_IMPLEMENTATION_CALL_FAILED"),
        ("0x1234", ErrorCode.INVALID_PROVIDER_OUTPUT.value),
        (
            "0x" + ("01" * 12) + IMPLEMENTATION[2:],
            ErrorCode.INVALID_PROVIDER_OUTPUT.value,
        ),
        (ZERO_WORD, "BEACON_IMPLEMENTATION_NULL"),
    ],
    ids=["rpc-error", "wrong-length", "nonzero-abi-padding", "null-target"],
)
def test_beacon_call_failures_preserve_beacon_candidate(
    call_response: RpcResponse,
    diagnostic_code: str,
) -> None:
    adapter = RecordingAdapter(
        codes={ROOT: NON_PROXY_CODE, BEACON: "0x6003"},
        storage={(ROOT, EIP1967_BEACON_SLOT): _word(BEACON)},
        calls={(BEACON, BEACON_IMPLEMENTATION_CALLDATA): call_response},
    )

    result = ProxyResolver(adapter).resolve(ROOT, BLOCK)

    assert result.status is ProxyResolutionStatus.PARTIAL
    assert result.addresses == (ROOT, BEACON)
    assert [relation.kind for relation in result.relations] == [RelationKind.BEACON]
    assert diagnostic_code in _diagnostic_codes(result)
    assert _contract(result, BEACON).code_validation_status is CodeValidationStatus.PRESENT
    _assert_same_block(adapter, BLOCK)
