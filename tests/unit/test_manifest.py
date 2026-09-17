"""Pruebas del contrato determinista de manifest.json."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from src.manifest import (
    SCHEMA_VERSION,
    ManifestContext,
    build_manifest,
    result_json,
    serialize_manifest,
)
from src.models import (
    BlockObservation,
    CodeValidationStatus,
    ContractResult,
    ContractRole,
    Diagnostic,
    DownloadRequest,
    DownloadResult,
    FileDigest,
    OverallStatus,
    ProxyRelation,
    ProxyResolutionStatus,
    RelationKind,
    RunMetrics,
    SourceStatus,
)

ROOT = "0x" + ("1" * 40)
IMPLEMENTATION_A = "0x" + ("2" * 40)
IMPLEMENTATION_B = "0x" + ("3" * 40)
CHECKSUM_ROOT = ROOT
STARTED = datetime(2026, 9, 16, 10, 0, tzinfo=timezone(timedelta(hours=2)))
COMPLETED = datetime(2026, 9, 16, 8, 0, 3, tzinfo=UTC)


def _context(*, skip_reason: str | None = None) -> ManifestContext:
    return ManifestContext(
        tool_version="0.1.0",
        cast_version="cast 1.4.0-stable",
        provider="etherscan",
        started_at=STARTED,
        completed_at=COMPLETED,
        validation_skip_reason=skip_reason,
    )


def _complete_result() -> DownloadResult:
    root_contract = ContractResult(
        address=ROOT,
        checksum_address=CHECKSUM_ROOT,
        role=ContractRole.ROOT,
        source_status=SourceStatus.DOWNLOADED,
        code_validation_status=CodeValidationStatus.PRESENT,
        proxy_resolution_status=ProxyResolutionStatus.RESOLVED,
        runtime_bytecode_keccak="0xruntime",
        runtime_bytecode_path=f"contracts/{ROOT}/runtime-bytecode.hex",
        files=(
            FileDigest("z/Z.sol", 2, "b" * 64),
            FileDigest("A.sol", 1, "a" * 64),
        ),
        provider_fetched_at=datetime(2026, 9, 16, 7, 59, tzinfo=UTC),
    )
    implementation_b = ContractResult(
        address=IMPLEMENTATION_B,
        checksum_address=IMPLEMENTATION_B,
        role=ContractRole.BEACON,
        roles=(ContractRole.BEACON, ContractRole.IMPLEMENTATION),
        source_status=SourceStatus.NOT_VERIFIED,
        code_validation_status=CodeValidationStatus.PRESENT,
        errors=(
            Diagnostic(
                "SOURCE_NOT_VERIFIED",
                "Sin fuentes",
                {"api_key": "must-never-appear", "provider_code": "NOTOK"},
            ),
        ),
    )
    implementation_a = ContractResult(
        address=IMPLEMENTATION_A,
        checksum_address=IMPLEMENTATION_A,
        role=ContractRole.IMPLEMENTATION,
        source_status=SourceStatus.REUSED,
        code_validation_status=CodeValidationStatus.PRESENT,
        cache_reused=True,
        provider_fetched_at=datetime(2026, 9, 15, 12, tzinfo=UTC),
        files=(FileDigest("Impl.sol", 4, "c" * 64),),
    )
    return DownloadResult(
        status=OverallStatus.COMPLETE,
        request=DownloadRequest(
            address=f" {ROOT} ",
            chain_id=1,
            output_dir="downloads",
            validation="rpc",
            block="latest",
            follow_proxy=True,
            max_depth=5,
            refresh=False,
        ),
        root_address=ROOT,
        checksum_address=CHECKSUM_ROOT,
        run_id="run-001",
        run_directory=Path("downloads/1/root/runs/run-001"),
        manifest_path=Path("downloads/1/root/runs/run-001/manifest.json"),
        observed_chain_id=1,
        observed_block=BlockObservation(number=123, hash="0x" + ("f" * 64)),
        contracts=(implementation_b, root_contract, implementation_a),
        relations=(
            ProxyRelation(
                source_address=ROOT,
                target_address=IMPLEMENTATION_B,
                kind=RelationKind.IMPLEMENTATION,
                detection_method="z-method",
                evidence={"slot": "z", "a": 1},
            ),
            ProxyRelation(
                source_address=ROOT,
                target_address=IMPLEMENTATION_A,
                kind=RelationKind.IMPLEMENTATION,
                detection_method="a-method",
                evidence={"slot": "a"},
            ),
        ),
        metrics=RunMetrics(
            cast_invocations=4,
            adapter_attempts=5,
            cache_downloads_avoided=1,
            files_stored=3,
            bytes_stored=7,
            stage_durations_seconds={"z-stage": 2.0, "a-stage": 1.0},
        ),
        warnings=(Diagnostic("NOTICE", "Aviso", {"z": 2, "a": 1}),),
    )


def test_build_manifest_is_deterministic_and_sorts_contracts_relations_and_files() -> None:
    result = _complete_result()

    first = build_manifest(result, _context())
    second = build_manifest(result, _context())

    assert first == second
    assert serialize_manifest(first) == serialize_manifest(second)
    contracts = cast(list[dict[str, object]], first["contracts"])
    assert [item["address"] for item in contracts] == [ROOT, IMPLEMENTATION_A, IMPLEMENTATION_B]
    assert contracts[-1]["role"] == "beacon"
    assert contracts[-1]["roles"] == ["beacon", "implementation"]
    root_files = cast(list[dict[str, object]], contracts[0]["files"])
    assert [item["relative_path"] for item in root_files] == ["A.sol", "z/Z.sol"]
    relations = cast(list[dict[str, object]], first["relations"])
    assert [item["target_address"] for item in relations] == [
        IMPLEMENTATION_A,
        IMPLEMENTATION_B,
    ]


def test_manifest_records_provenance_without_claiming_independent_verification() -> None:
    manifest = build_manifest(_complete_result(), _context())
    verification = cast(dict[str, object], manifest["verification"])
    contracts = cast(list[dict[str, object]], manifest["contracts"])
    root_provenance = cast(dict[str, object], contracts[0]["source_provenance"])
    missing_provenance = cast(dict[str, object], contracts[-1]["source_provenance"])

    assert verification == {
        "provider_provenance": "declared_by_explorer",
        "local_file_integrity": "sha256",
        "onchain_code_existence": "performed",
        "independent_recompilation": "not_performed",
    }
    assert root_provenance["provider_declared"] == "published_source"
    assert root_provenance["local_integrity"] == "sha256_recorded"
    assert root_provenance["independent_recompilation"] == "not_performed"
    assert missing_provenance["provider_declared"] == "not_available"
    assert '"verified":' not in json.dumps(manifest).casefold()


def test_manifest_marks_mixed_onchain_code_checks_as_partial() -> None:
    result = _complete_result()
    failed = replace(
        result.contracts[-1],
        code_validation_status=CodeValidationStatus.FAILED,
    )
    mixed = replace(result, contracts=(*result.contracts[:-1], failed))

    manifest = build_manifest(mixed, _context())

    verification = cast(dict[str, object], manifest["verification"])
    assert verification["onchain_code_existence"] == "partial"


def test_cli_result_json_is_ascii_safe_for_redirected_windows_stdout() -> None:
    result = replace(
        _complete_result(),
        run_directory=Path("downloads/合約/á"),
        manifest_path=Path("downloads/合約/á/manifest.json"),
    )

    payload = result_json(result)

    assert payload.isascii()
    decoded = json.loads(payload)
    assert decoded["run_directory"].endswith("合約\\á") or decoded["run_directory"].endswith(
        "合約/á"
    )


def test_manifest_contains_explicit_schema_scope_block_and_metrics() -> None:
    manifest = build_manifest(_complete_result(), _context())

    assert manifest["schema_version"] == SCHEMA_VERSION
    assert cast(dict[str, object], manifest["run"])["started_at"] == "2026-09-16T08:00:00Z"
    assert cast(dict[str, object], manifest["run"])["completed_at"] == "2026-09-16T08:00:03Z"
    validation = cast(dict[str, object], manifest["validation"])
    assert validation["observed_block"] == {"number": 123, "hash": "0x" + ("f" * 64)}
    assert validation["code_existence_only"] is True
    assert cast(dict[str, object], manifest["scope"])["one_root_address"] is True
    assert cast(dict[str, object], manifest["metrics"])["cast_invocations"] == 4
    assert cast(dict[str, object], manifest["provider"])["secrets_persisted"] is False


def test_manifest_sanitizes_diagnostic_secrets() -> None:
    manifest = build_manifest(_complete_result(), _context())
    serialized = serialize_manifest(manifest).decode("utf-8")

    assert "must-never-appear" not in serialized
    assert "[REDACTED]" in serialized


def test_explorer_manifest_records_skipped_validation_without_observed_block() -> None:
    result = DownloadResult(
        status=OverallStatus.COMPLETE,
        request=DownloadRequest(address=ROOT, chain_id=1, validation="explorer"),
        root_address=ROOT,
        checksum_address=ROOT,
        observed_chain_id=None,
        observed_block=None,
    )

    manifest = build_manifest(result, _context(skip_reason="explorer_only"))
    validation = cast(dict[str, object], manifest["validation"])
    verification = cast(dict[str, object], manifest["verification"])

    assert validation["mode"] == "explorer"
    assert validation["skip_reason"] == "explorer_only"
    assert validation["observed_block"] is None
    assert validation["code_existence_only"] is False
    assert verification["onchain_code_existence"] == "skipped"


def test_serialize_manifest_is_utf8_sorted_and_newline_terminated() -> None:
    payload = {
        "z": "España",
        "a": {"z": 1, "a": 2},
        "path": Path("contracts/Contract.sol"),
        "time": STARTED,
        "status": OverallStatus.COMPLETE,
    }

    serialized = serialize_manifest(payload)

    assert serialized.endswith(b"\n")
    assert "España" in serialized.decode("utf-8")
    assert serialized.index(b'"a"') < serialized.index(b'"z"')
    decoded = cast(dict[str, object], json.loads(serialized))
    assert decoded["path"] == "contracts/Contract.sol"
    assert decoded["time"] == "2026-09-16T08:00:00Z"
    assert decoded["status"] == "complete"
    assert decoded["a"] == {"a": 2, "z": 1}


def test_serialize_manifest_rejects_unknown_object_instead_of_stringifying_it() -> None:
    with pytest.raises(TypeError):
        serialize_manifest({"unsafe": object()})


def test_result_json_is_stable_machine_readable_and_optionally_embeds_manifest() -> None:
    result = _complete_result()
    manifest = build_manifest(result, _context())

    without_manifest = cast(dict[str, object], json.loads(result_json(result)))
    with_manifest_text = result_json(result, manifest)
    with_manifest = cast(dict[str, object], json.loads(with_manifest_text))

    assert without_manifest["schema_version"] == SCHEMA_VERSION
    assert without_manifest["status"] == "complete"
    assert without_manifest["run_id"] == "run-001"
    assert "manifest" not in without_manifest
    assert with_manifest["manifest"] == manifest
    assert result_json(result, manifest) == with_manifest_text


def test_build_manifest_does_not_mutate_result_order() -> None:
    result = _complete_result()
    original_contracts = result.contracts
    original_relations = result.relations

    build_manifest(result, _context())

    assert result.contracts == original_contracts
    assert result.relations == original_relations
