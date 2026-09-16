from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from .errors import sanitize_details


class ValidationMode(StrEnum):
    RPC = "rpc"
    EXPLORER = "explorer"


class OverallStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class SourceStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    DOWNLOADED = "downloaded"
    REUSED = "reused"
    NOT_VERIFIED = "not_verified"
    FAILED = "failed"


class CodeValidationStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    PRESENT = "present"
    NO_CODE = "no_code"
    SKIPPED = "skipped"
    FAILED = "failed"


class ProxyResolutionStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    RESOLVED = "resolved"
    NO_SUPPORTED_PATTERN_DETECTED = "no_supported_pattern_detected"
    PARTIAL = "partial"
    FAILED = "failed"
    CYCLE = "cycle"
    LIMIT_REACHED = "limit_reached"


class ContractRole(StrEnum):
    ROOT = "root"
    IMPLEMENTATION = "implementation"
    BEACON = "beacon"


class RelationKind(StrEnum):
    IMPLEMENTATION = "implementation"
    BEACON = "beacon"
    BEACON_IMPLEMENTATION = "beacon_implementation"


class IndependentVerificationStatus(StrEnum):
    NOT_PERFORMED = "not_performed"


@dataclass(frozen=True, slots=True)
class ValidatedAddress:
    """Tres representaciones de una dirección ya validada."""

    original: str
    trimmed: str
    canonical: str
    checksum: str

    @property
    def is_zero(self) -> bool:
        return self.canonical == "0x" + ("0" * 40)


@dataclass(frozen=True, slots=True)
class DownloadRequest:
    """Solicitud de alto nivel aceptada por :class:`SourceDownloader`."""

    address: str
    chain_id: int = 1
    output_dir: str | Path = Path("downloads")
    validation: ValidationMode | str = ValidationMode.RPC
    block: int | str | None = None
    follow_proxy: bool = False
    max_depth: int | None = None
    refresh: bool = False
    timeout: float | None = None

    @property
    def validation_mode(self) -> ValidationMode:
        return (
            self.validation
            if isinstance(self.validation, ValidationMode)
            else ValidationMode(self.validation)
        )

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)


@dataclass(frozen=True, slots=True)
class BlockObservation:
    number: int
    hash: str


@dataclass(frozen=True, slots=True)
class FileDigest:
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    message: str
    details: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", sanitize_details(self.details))


@dataclass(frozen=True, slots=True)
class ProxyRelation:
    source_address: str
    target_address: str
    kind: RelationKind
    detection_method: str
    evidence: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", sanitize_details(self.evidence))


@dataclass(frozen=True, slots=True)
class ContractResult:
    address: str
    checksum_address: str
    role: ContractRole
    source_status: SourceStatus
    code_validation_status: CodeValidationStatus
    roles: tuple[ContractRole, ...] = ()
    proxy_resolution_status: ProxyResolutionStatus = ProxyResolutionStatus.NOT_REQUESTED
    runtime_bytecode_keccak: str | None = None
    runtime_bytecode_path: str | None = None
    files: tuple[FileDigest, ...] = ()
    cache_reused: bool = False
    provider_fetched_at: datetime | None = None
    download_attempts: int = 0
    download_duration_seconds: float = 0.0
    warnings: tuple[Diagnostic, ...] = ()
    errors: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        roles = self.roles or (self.role,)
        if self.role not in roles:
            roles = (self.role, *roles)
        object.__setattr__(self, "roles", tuple(dict.fromkeys(roles)))


@dataclass(frozen=True, slots=True)
class RunMetrics:
    cast_invocations: int = 0
    adapter_attempts: int = 0
    cache_downloads_avoided: int = 0
    files_stored: int = 0
    bytes_stored: int = 0
    stage_durations_seconds: Mapping[str, float] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "stage_durations_seconds",
            MappingProxyType(dict(self.stage_durations_seconds)),
        )


@dataclass(frozen=True, slots=True)
class DownloadResult:
    status: OverallStatus
    request: DownloadRequest
    root_address: str
    checksum_address: str
    run_id: str | None = None
    run_directory: Path | None = None
    manifest_path: Path | None = None
    observed_chain_id: int | None = None
    observed_block: BlockObservation | None = None
    contracts: tuple[ContractResult, ...] = ()
    relations: tuple[ProxyRelation, ...] = ()
    metrics: RunMetrics = field(default_factory=RunMetrics)
    warnings: tuple[Diagnostic, ...] = ()
    errors: tuple[Diagnostic, ...] = ()
    independent_verification: IndependentVerificationStatus = (
        IndependentVerificationStatus.NOT_PERFORMED
    )
