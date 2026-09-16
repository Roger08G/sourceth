from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

from .models import ContractResult, Diagnostic, DownloadResult, FileDigest, ProxyRelation

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ManifestContext:
    tool_version: str
    cast_version: str
    provider: str
    started_at: datetime
    completed_at: datetime
    provider_api_url: str | None = None
    provider_browser_url: str | None = None
    provider_identity_sha256: str | None = None
    validation_skip_reason: str | None = None
    effective_proxy_max_depth: int | None = None
    effective_proxy_max_addresses: int | None = None


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _url_origin(value: str | None) -> str | None:
    """Expone solo origen; una ruta de endpoint puede contener datos sensibles."""

    if value is None:
        return None
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if hostname is None:
        return None
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    port = parsed.port
    authority = display_host if port in {None, 443} else f"{display_host}:{port}"
    return f"{parsed.scheme.casefold()}://{authority}"


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc_text(value)
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(child)
            for key, child in sorted(value.items(), key=lambda x: str(x[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_safe(child) for child in value]
    raise TypeError(f"No se puede serializar {type(value).__name__}")


def _diagnostic(value: Diagnostic) -> dict[str, object]:
    return {
        "code": value.code,
        "message": value.message,
        "details": _json_safe(value.details),
    }


def _file(value: FileDigest) -> dict[str, object]:
    return {
        "relative_path": value.relative_path,
        "size_bytes": value.size_bytes,
        "sha256": value.sha256,
    }


def _contract(value: ContractResult) -> dict[str, object]:
    source_available = value.source_status.value in {"downloaded", "reused"}
    return {
        "address": value.address,
        "checksum_address": value.checksum_address,
        "role": value.role.value,
        "roles": [role.value for role in value.roles],
        "source_status": value.source_status.value,
        "code_validation_status": value.code_validation_status.value,
        "proxy_resolution_status": value.proxy_resolution_status.value,
        "runtime_bytecode": {
            "keccak256": value.runtime_bytecode_keccak,
            "path": value.runtime_bytecode_path,
        },
        "source_provenance": {
            "provider_declared": "published_source" if source_available else "not_available",
            "local_integrity": "sha256_recorded" if source_available else "not_available",
            "independent_recompilation": "not_performed",
        },
        "files": [_file(item) for item in sorted(value.files, key=lambda item: item.relative_path)],
        "cache": {
            "reused": value.cache_reused,
            "provider_fetched_at": (
                _utc_text(value.provider_fetched_at) if value.provider_fetched_at else None
            ),
        },
        "download": {
            "adapter_attempts": value.download_attempts,
            "duration_seconds": value.download_duration_seconds,
        },
        "warnings": [_diagnostic(item) for item in value.warnings],
        "errors": [_diagnostic(item) for item in value.errors],
    }


def _relation(value: ProxyRelation) -> dict[str, object]:
    return {
        "source_address": value.source_address,
        "target_address": value.target_address,
        "kind": value.kind.value,
        "detection_method": value.detection_method,
        "evidence": _json_safe(value.evidence),
    }


def build_manifest(result: DownloadResult, context: ManifestContext) -> dict[str, object]:
    """Construye el contrato persistente sin campos ambiguos como ``verified``."""

    request = result.request
    contracts = sorted(
        result.contracts,
        key=lambda item: (0 if item.role.value == "root" else 1, item.address),
    )
    relations = sorted(
        result.relations,
        key=lambda item: (
            item.source_address,
            item.target_address,
            item.kind.value,
            item.detection_method,
        ),
    )
    observed_block: dict[str, object] | None = None
    if result.observed_block is not None:
        observed_block = {
            "number": result.observed_block.number,
            "hash": result.observed_block.hash,
        }
    sources_available = any(
        item.source_status.value in {"downloaded", "reused"} for item in result.contracts
    )
    code_statuses = {item.code_validation_status.value for item in result.contracts}
    if result.request.validation_mode.value == "explorer":
        onchain_code_existence = "skipped"
    elif code_statuses and code_statuses <= {"present", "no_code"}:
        onchain_code_existence = "performed"
    elif code_statuses & {"present", "no_code"}:
        onchain_code_existence = "partial"
    else:
        onchain_code_existence = "failed"

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "sourceth", "version": context.tool_version},
        "cast": {"version": context.cast_version},
        "run": {
            "id": result.run_id,
            "started_at": _utc_text(context.started_at),
            "completed_at": _utc_text(context.completed_at),
            "status": result.status.value,
        },
        "input": {
            "address_original": request.address,
            "address_canonical": result.root_address,
            "address_checksum": result.checksum_address,
            "chain_id_requested": request.chain_id,
            "chain_id_observed": result.observed_chain_id,
        },
        "scope": {
            "one_root_address": True,
            "follow_proxy": request.follow_proxy,
            "max_depth_requested": request.max_depth,
            "max_depth": context.effective_proxy_max_depth,
            "max_addresses": context.effective_proxy_max_addresses,
            "refresh": request.refresh,
        },
        "validation": {
            "mode": request.validation_mode.value,
            "skip_reason": context.validation_skip_reason,
            "observed_block": observed_block,
            "code_existence_only": request.validation_mode.value == "rpc",
        },
        "provider": {
            "name": context.provider,
            "identity_sha256": context.provider_identity_sha256,
            "api_origin": _url_origin(context.provider_api_url),
            "browser_origin": _url_origin(context.provider_browser_url),
            "secrets_persisted": False,
        },
        "contracts": [_contract(item) for item in contracts],
        "relations": [_relation(item) for item in relations],
        "verification": {
            "provider_provenance": (
                "declared_by_explorer" if sources_available else "not_available"
            ),
            "local_file_integrity": "sha256" if sources_available else "not_available",
            "onchain_code_existence": onchain_code_existence,
            "independent_recompilation": result.independent_verification.value,
        },
        "metrics": {
            "cast_invocations": result.metrics.cast_invocations,
            "adapter_attempts": result.metrics.adapter_attempts,
            "cache_downloads_avoided": result.metrics.cache_downloads_avoided,
            "files_stored": result.metrics.files_stored,
            "bytes_stored": result.metrics.bytes_stored,
            "stage_durations_seconds": _json_safe(result.metrics.stage_durations_seconds),
        },
        "warnings": [_diagnostic(item) for item in result.warnings],
        "errors": [_diagnostic(item) for item in result.errors],
    }


def serialize_manifest(manifest: Mapping[str, object]) -> bytes:
    """Serializa con orden estable y salto final."""

    return (
        json.dumps(_json_safe(manifest), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def result_json(result: DownloadResult, manifest: Mapping[str, object] | None = None) -> str:
    """Devuelve el envelope estable que la CLI emite en stdout con ``--json``."""

    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": result.status.value,
        "run_id": result.run_id,
        "run_directory": str(result.run_directory) if result.run_directory else None,
        "manifest_path": str(result.manifest_path) if result.manifest_path else None,
        "root_address": result.root_address,
        "checksum_address": result.checksum_address,
        "warnings": [_diagnostic(item) for item in result.warnings],
        "errors": [_diagnostic(item) for item in result.errors],
    }
    if manifest is not None:
        payload["manifest"] = _json_safe(manifest)
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)
