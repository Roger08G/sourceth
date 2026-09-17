from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from .errors import ConfigurationError, ErrorCode, SourcethError
from .models import (
    BlockObservation,
    CodeValidationStatus,
    ContractRole,
    Diagnostic,
    ProxyRelation,
    ProxyResolutionStatus,
    RelationKind,
    ValidatedAddress,
)
from .validation import validate_address, validate_runtime_bytecode

# https://eips.ethereum.org/EIPS/eip-1967
EIP1967_IMPLEMENTATION_SLOT: Final = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
EIP1967_BEACON_SLOT: Final = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
BEACON_IMPLEMENTATION_CALLDATA: Final = "0x5c60da1b"

# Runtime canónico exacto de https://eips.ethereum.org/EIPS/eip-1167.
ERC1167_PREFIX: Final = "363d3d373d3d3d363d73"
ERC1167_SUFFIX: Final = "5af43d82803e903d91602b57fd5bf3"
_ZERO_WORD: Final = "0" * 64

type BlockSpecifier = BlockObservation | int | str


class ProxyRpcAdapter(Protocol):
    """Superficie RPC mínima que satisface ``CastAdapter``."""

    def get_code(self, address: str, block: BlockSpecifier) -> str: ...

    def get_storage_at(
        self,
        address: str,
        slot: str | int,
        block: BlockSpecifier,
    ) -> str: ...

    def eth_call(self, address: str, calldata: str, block: BlockSpecifier) -> str: ...


@dataclass(frozen=True, slots=True)
class ResolvedContract:
    """Dirección única descubierta durante la resolución."""

    address: str
    checksum_address: str
    roles: tuple[ContractRole, ...]
    depth: int
    runtime_bytecode: str | None
    code_validation_status: CodeValidationStatus
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def role(self) -> ContractRole:
        """Rol principal, para consumidores que solo admiten uno."""

        for candidate in (
            ContractRole.ROOT,
            ContractRole.BEACON,
            ContractRole.IMPLEMENTATION,
        ):
            if candidate in self.roles:
                return candidate
        return self.roles[0]


@dataclass(frozen=True, slots=True)
class ProxyResolutionResult:
    root_address: str
    block: BlockObservation
    status: ProxyResolutionStatus
    contracts: tuple[ResolvedContract, ...]
    relations: tuple[ProxyRelation, ...]
    diagnostics: tuple[Diagnostic, ...]
    code_lookups: int
    code_cache_hits: int

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(contract.address for contract in self.contracts)


@dataclass(slots=True)
class _Node:
    address: str
    checksum_address: str
    roles: list[ContractRole]
    depth: int
    runtime_bytecode: str | None = None
    code_status: CodeValidationStatus = CodeValidationStatus.NOT_ATTEMPTED
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _CodeEntry:
    runtime_bytecode: str | None
    status: CodeValidationStatus


@dataclass(slots=True)
class _State:
    block: BlockObservation
    nodes: dict[str, _Node] = field(default_factory=dict)
    relations: list[ProxyRelation] = field(default_factory=list)
    relation_keys: set[tuple[str, str, RelationKind, str]] = field(default_factory=set)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    code_cache: dict[str, _CodeEntry] = field(default_factory=dict)
    proxy_expanded_at: dict[str, int] = field(default_factory=dict)
    beacon_expanded_at: dict[str, int] = field(default_factory=dict)
    code_lookups: int = 0
    code_cache_hits: int = 0
    relation_found: bool = False
    had_failure: bool = False
    cycle_detected: bool = False
    limit_reached: bool = False


class ProxyResolver:
    """Resuelve EIP-1967 y ERC-1167 sin efectuar descargas de fuentes."""

    def __init__(
        self,
        adapter: ProxyRpcAdapter,
        *,
        max_depth: int = 5,
        max_addresses: int = 10,
    ) -> None:
        if max_depth < 1:
            raise ConfigurationError("max_depth debe ser mayor que cero.")
        if max_addresses < 1:
            raise ConfigurationError("max_addresses debe ser mayor que cero.")
        self._adapter = adapter
        self._max_depth = max_depth
        self._max_addresses = max_addresses

    def resolve(
        self,
        root_address: str,
        block: BlockObservation,
    ) -> ProxyResolutionResult:
        """Resuelve relaciones usando exactamente la misma observación de bloque."""

        root = validate_address(root_address)
        state = _State(block=block)
        root_node = self._register(state, root, ContractRole.ROOT, depth=0)
        self._ensure_code(state, root_node)
        if root_node.code_status is CodeValidationStatus.PRESENT:
            self._expand_proxy(
                state,
                root_node,
                depth=0,
                ancestry=(root.canonical,),
            )

        contracts = tuple(self._freeze_node(node) for node in state.nodes.values())
        return ProxyResolutionResult(
            root_address=root.canonical,
            block=block,
            status=self._result_status(state),
            contracts=contracts,
            relations=tuple(state.relations),
            diagnostics=tuple(state.diagnostics),
            code_lookups=state.code_lookups,
            code_cache_hits=state.code_cache_hits,
        )

    def _expand_proxy(
        self,
        state: _State,
        node: _Node,
        *,
        depth: int,
        ancestry: tuple[str, ...],
    ) -> None:
        previous_depth = state.proxy_expanded_at.get(node.address)
        if previous_depth is not None and previous_depth <= depth:
            return
        state.proxy_expanded_at[node.address] = depth

        runtime_bytecode = node.runtime_bytecode
        if runtime_bytecode is None:
            return

        clone_target = _extract_erc1167_target(runtime_bytecode)
        if clone_target is not None:
            if clone_target.is_zero:
                self._record(
                    state,
                    node,
                    "ERC1167_IMPLEMENTATION_NULL",
                    "El runtime ERC-1167 contiene una implementación nula.",
                    failure=True,
                )
                return
            evidence: dict[str, object] = {
                "standard": "ERC-1167",
                "pattern": "canonical_runtime_exact",
                "runtime_length_bytes": 45,
                "runtime_bytecode": runtime_bytecode,
                "semantics_confirmed": False,
                **_block_evidence(state.block),
            }
            self._link_and_expand(
                state,
                source=node,
                target=clone_target,
                kind=RelationKind.IMPLEMENTATION,
                detection_method="erc1167_canonical_runtime",
                evidence=evidence,
                role=ContractRole.IMPLEMENTATION,
                depth=depth,
                ancestry=ancestry,
                as_beacon=False,
            )
            return

        implementation, implementation_ok, implementation_raw = self._read_slot_address(
            state,
            node,
            EIP1967_IMPLEMENTATION_SLOT,
            empty_code="EIP1967_IMPLEMENTATION_SLOT_EMPTY",
            label="implementación EIP-1967",
        )
        if implementation is not None:
            self._link_and_expand(
                state,
                source=node,
                target=implementation,
                kind=RelationKind.IMPLEMENTATION,
                detection_method="eip1967_implementation_slot",
                evidence={
                    "standard": "EIP-1967",
                    "slot": EIP1967_IMPLEMENTATION_SLOT,
                    "raw_value": implementation_raw,
                    "semantics_confirmed": False,
                    **_block_evidence(state.block),
                },
                role=ContractRole.IMPLEMENTATION,
                depth=depth,
                ancestry=ancestry,
                as_beacon=False,
            )
            return

        beacon, beacon_ok, beacon_raw = self._read_slot_address(
            state,
            node,
            EIP1967_BEACON_SLOT,
            empty_code="EIP1967_BEACON_SLOT_EMPTY",
            label="beacon EIP-1967",
        )
        if beacon is not None:
            self._link_and_expand(
                state,
                source=node,
                target=beacon,
                kind=RelationKind.BEACON,
                detection_method="eip1967_beacon_slot",
                evidence={
                    "standard": "EIP-1967",
                    "slot": EIP1967_BEACON_SLOT,
                    "raw_value": beacon_raw,
                    "semantics_confirmed": False,
                    **_block_evidence(state.block),
                },
                role=ContractRole.BEACON,
                depth=depth,
                ancestry=ancestry,
                as_beacon=True,
            )
            return

        if implementation_ok and beacon_ok:
            self._record(
                state,
                node,
                ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED.value,
                "No se detectó ningún patrón de proxy soportado.",
                details={"address": node.address},
            )

    def _expand_beacon(
        self,
        state: _State,
        node: _Node,
        *,
        depth: int,
        ancestry: tuple[str, ...],
    ) -> None:
        previous_depth = state.beacon_expanded_at.get(node.address)
        if previous_depth is not None and previous_depth <= depth:
            return
        state.beacon_expanded_at[node.address] = depth

        try:
            raw_result = self._adapter.eth_call(
                node.address,
                BEACON_IMPLEMENTATION_CALLDATA,
                state.block,
            )
        except SourcethError as error:
            self._record(
                state,
                node,
                "BEACON_IMPLEMENTATION_CALL_FAILED",
                "La llamada implementation() del beacon revirtió o falló.",
                details={"upstream_code": error.code.value, "reason": error.message},
                failure=True,
            )
            return

        try:
            implementation = _decode_address_word(raw_result)
        except ValueError as error:
            self._record(
                state,
                node,
                ErrorCode.INVALID_PROVIDER_OUTPUT.value,
                "La respuesta de implementation() del beacon está mal formada.",
                details={"reason": str(error)},
                failure=True,
            )
            return
        if implementation is None:
            self._record(
                state,
                node,
                "BEACON_IMPLEMENTATION_NULL",
                "implementation() devolvió una dirección nula.",
                failure=True,
            )
            return

        self._link_and_expand(
            state,
            source=node,
            target=implementation,
            kind=RelationKind.BEACON_IMPLEMENTATION,
            detection_method="eip1967_beacon_implementation_call",
            evidence={
                "standard": "EIP-1967",
                "calldata": BEACON_IMPLEMENTATION_CALLDATA,
                "raw_result": raw_result,
                "semantics_confirmed": False,
                **_block_evidence(state.block),
            },
            role=ContractRole.IMPLEMENTATION,
            depth=depth,
            ancestry=ancestry,
            as_beacon=False,
        )

    def _read_slot_address(
        self,
        state: _State,
        node: _Node,
        slot: str,
        *,
        empty_code: str,
        label: str,
    ) -> tuple[ValidatedAddress | None, bool, str | None]:
        try:
            raw_value = self._adapter.get_storage_at(node.address, slot, state.block)
        except SourcethError as error:
            self._record(
                state,
                node,
                ErrorCode.PROXY_RESOLUTION_FAILED.value,
                f"No se pudo leer el slot de {label}.",
                details={"slot": slot, "upstream_code": error.code.value},
                failure=True,
            )
            return None, False, None

        try:
            target = _decode_address_word(raw_value)
        except ValueError as error:
            self._record(
                state,
                node,
                ErrorCode.INVALID_PROVIDER_OUTPUT.value,
                f"El slot de {label} devolvió datos mal formados.",
                details={"slot": slot, "reason": str(error)},
                failure=True,
            )
            return None, False, raw_value
        if target is None:
            self._record(
                state,
                node,
                empty_code,
                f"El slot de {label} contiene una dirección nula.",
                details={"slot": slot},
            )
        return target, True, raw_value

    def _link_and_expand(
        self,
        state: _State,
        *,
        source: _Node,
        target: ValidatedAddress,
        kind: RelationKind,
        detection_method: str,
        evidence: dict[str, object],
        role: ContractRole,
        depth: int,
        ancestry: tuple[str, ...],
        as_beacon: bool,
    ) -> None:
        state.relation_found = True
        self._add_relation(
            state,
            source.address,
            target.canonical,
            kind,
            detection_method,
            evidence,
        )

        if target.canonical in ancestry:
            existing = state.nodes.get(target.canonical)
            if existing is not None and role not in existing.roles:
                existing.roles.append(role)
            state.cycle_detected = True
            self._record(
                state,
                source,
                ErrorCode.PROXY_CYCLE.value,
                "La relación de proxy forma un ciclo.",
                details={"target_address": target.canonical},
                failure=True,
            )
            return

        next_depth = depth + 1
        if next_depth > self._max_depth:
            state.limit_reached = True
            self._record(
                state,
                source,
                ErrorCode.PROXY_LIMIT_REACHED.value,
                "Se alcanzó la profundidad máxima de resolución.",
                details={"max_depth": self._max_depth, "target_address": target.canonical},
                failure=True,
            )
            return

        target_node = state.nodes.get(target.canonical)
        if target_node is None:
            if len(state.nodes) >= self._max_addresses:
                state.limit_reached = True
                self._record(
                    state,
                    source,
                    ErrorCode.PROXY_LIMIT_REACHED.value,
                    "Se alcanzó el número máximo de direcciones.",
                    details={
                        "max_addresses": self._max_addresses,
                        "target_address": target.canonical,
                    },
                    failure=True,
                )
                return
            target_node = self._register(state, target, role, depth=next_depth)
        else:
            if role not in target_node.roles:
                target_node.roles.append(role)
            target_node.depth = min(target_node.depth, next_depth)

        self._ensure_code(state, target_node)
        if target_node.code_status is not CodeValidationStatus.PRESENT:
            return
        next_ancestry = (*ancestry, target.canonical)
        if as_beacon:
            self._expand_beacon(
                state,
                target_node,
                depth=next_depth,
                ancestry=next_ancestry,
            )
        else:
            self._expand_proxy(
                state,
                target_node,
                depth=next_depth,
                ancestry=next_ancestry,
            )

    def _ensure_code(self, state: _State, node: _Node) -> None:
        if node.code_status is not CodeValidationStatus.NOT_ATTEMPTED:
            if node.address in state.code_cache:
                state.code_cache_hits += 1
            return
        cached = state.code_cache.get(node.address)
        if cached is not None:
            state.code_cache_hits += 1
            node.runtime_bytecode = cached.runtime_bytecode
            node.code_status = cached.status
            return

        state.code_lookups += 1
        try:
            raw_code = self._adapter.get_code(node.address, state.block)
        except SourcethError as error:
            if error.code is ErrorCode.NO_CODE_AT_BLOCK:
                node.code_status = CodeValidationStatus.NO_CODE
                state.code_cache[node.address] = _CodeEntry(None, node.code_status)
                self._record(
                    state,
                    node,
                    ErrorCode.NO_CODE_AT_BLOCK.value,
                    "La dirección resuelta no contiene código en el bloque observado.",
                    details={"address": node.address},
                    failure=True,
                )
            else:
                node.code_status = CodeValidationStatus.FAILED
                state.code_cache[node.address] = _CodeEntry(None, node.code_status)
                self._record(
                    state,
                    node,
                    ErrorCode.PROXY_RESOLUTION_FAILED.value,
                    "No se pudo comprobar el código de la dirección resuelta.",
                    details={"address": node.address, "upstream_code": error.code.value},
                    failure=True,
                )
            return

        try:
            runtime_bytecode = validate_runtime_bytecode(raw_code)
        except ValueError as error:
            node.code_status = CodeValidationStatus.FAILED
            state.code_cache[node.address] = _CodeEntry(None, node.code_status)
            self._record(
                state,
                node,
                ErrorCode.INVALID_PROVIDER_OUTPUT.value,
                "La respuesta de código RPC está mal formada.",
                details={"address": node.address, "reason": str(error)},
                failure=True,
            )
            return
        if runtime_bytecode == "0x":
            node.code_status = CodeValidationStatus.NO_CODE
            state.code_cache[node.address] = _CodeEntry(None, node.code_status)
            self._record(
                state,
                node,
                ErrorCode.NO_CODE_AT_BLOCK.value,
                "La dirección resuelta no contiene código en el bloque observado.",
                details={"address": node.address},
                failure=True,
            )
            return

        node.runtime_bytecode = runtime_bytecode
        node.code_status = CodeValidationStatus.PRESENT
        state.code_cache[node.address] = _CodeEntry(runtime_bytecode, node.code_status)

    @staticmethod
    def _register(
        state: _State,
        address: ValidatedAddress,
        role: ContractRole,
        *,
        depth: int,
    ) -> _Node:
        node = _Node(
            address=address.canonical,
            checksum_address=address.checksum,
            roles=[role],
            depth=depth,
        )
        state.nodes[address.canonical] = node
        return node

    @staticmethod
    def _add_relation(
        state: _State,
        source_address: str,
        target_address: str,
        kind: RelationKind,
        detection_method: str,
        evidence: dict[str, object],
    ) -> None:
        key = (source_address, target_address, kind, detection_method)
        if key in state.relation_keys:
            return
        state.relation_keys.add(key)
        state.relations.append(
            ProxyRelation(
                source_address=source_address,
                target_address=target_address,
                kind=kind,
                detection_method=detection_method,
                evidence=evidence,
            )
        )

    @staticmethod
    def _record(
        state: _State,
        node: _Node,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
        failure: bool = False,
    ) -> None:
        diagnostic = Diagnostic(code=code, message=message, details=details or {})
        node.diagnostics.append(diagnostic)
        state.diagnostics.append(diagnostic)
        if failure:
            state.had_failure = True

    @staticmethod
    def _freeze_node(node: _Node) -> ResolvedContract:
        role_order = {
            ContractRole.ROOT: 0,
            ContractRole.BEACON: 1,
            ContractRole.IMPLEMENTATION: 2,
        }
        roles = tuple(sorted(set(node.roles), key=role_order.__getitem__))
        return ResolvedContract(
            address=node.address,
            checksum_address=node.checksum_address,
            roles=roles,
            depth=node.depth,
            runtime_bytecode=node.runtime_bytecode,
            code_validation_status=node.code_status,
            diagnostics=tuple(node.diagnostics),
        )

    @staticmethod
    def _result_status(state: _State) -> ProxyResolutionStatus:
        if state.limit_reached:
            return ProxyResolutionStatus.LIMIT_REACHED
        if state.cycle_detected:
            return ProxyResolutionStatus.CYCLE
        if state.relation_found and state.had_failure:
            return ProxyResolutionStatus.PARTIAL
        if state.relation_found:
            return ProxyResolutionStatus.RESOLVED
        if state.had_failure:
            return ProxyResolutionStatus.FAILED
        return ProxyResolutionStatus.NO_SUPPORTED_PATTERN_DETECTED


def _decode_address_word(value: str) -> ValidatedAddress | None:
    normalized = validate_runtime_bytecode(value)
    body = normalized[2:]
    if len(body) != 64:
        raise ValueError("se esperaban exactamente 32 bytes")
    if body == _ZERO_WORD:
        return None
    if body[:24] != "0" * 24:
        raise ValueError("los 12 bytes superiores de una dirección ABI deben ser cero")
    return validate_address("0x" + body[24:])


def _extract_erc1167_target(runtime_bytecode: str) -> ValidatedAddress | None:
    normalized = validate_runtime_bytecode(runtime_bytecode)
    body = normalized[2:]
    expected_length = len(ERC1167_PREFIX) + 40 + len(ERC1167_SUFFIX)
    if len(body) != expected_length:
        return None
    if not body.startswith(ERC1167_PREFIX) or not body.endswith(ERC1167_SUFFIX):
        return None
    return validate_address("0x" + body[len(ERC1167_PREFIX) : len(ERC1167_PREFIX) + 40])


def _block_evidence(block: BlockObservation) -> dict[str, object]:
    return {"block_number": block.number, "block_hash": block.hash}


__all__: Sequence[str] = (
    "BEACON_IMPLEMENTATION_CALLDATA",
    "EIP1967_BEACON_SLOT",
    "EIP1967_IMPLEMENTATION_SLOT",
    "ERC1167_PREFIX",
    "ERC1167_SUFFIX",
    "ProxyResolutionResult",
    "ProxyResolver",
    "ProxyRpcAdapter",
    "ResolvedContract",
)
