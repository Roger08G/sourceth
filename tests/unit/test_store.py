"""Pruebas offline del staging, publicación y caché local."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from sourceth.config import ResourceLimits
from sourceth.errors import (
    ErrorCode,
    FilesystemOperationError,
    OutputSafetyError,
)
from sourceth.models import OverallStatus
from sourceth.store import CacheHit, RevisionStore, RunWorkspace

ROOT_ADDRESS = "0x" + ("1" * 40)
SECOND_ADDRESS = "0x" + ("2" * 40)
NOW = datetime(2026, 9, 16, 12, 30, tzinfo=UTC)
PROVIDER_IDENTITY = "a" * 64


def _limits(
    *,
    max_files: int = 20,
    max_file_size_bytes: int = 4096,
    max_total_size_bytes: int = 16384,
) -> ResourceLimits:
    return ResourceLimits(
        max_files=max_files,
        max_file_size_bytes=max_file_size_bytes,
        max_total_size_bytes=max_total_size_bytes,
        max_output_bytes=4096,
    )


@pytest.fixture
def store(tmp_path: Path) -> RevisionStore:
    value = RevisionStore(tmp_path / "downloads", _limits())
    value.prepare()
    return value


def _source_tree(base: Path, files: dict[str, bytes]) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for relative, payload in files.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return base


def _cache_entry_from_pointer(store: RevisionStore) -> Path:
    key = store._cache_key("etherscan", PROVIDER_IDENTITY, 1, ROOT_ADDRESS)
    pointer = cast(dict[str, object], json.loads((key / "latest.json").read_text(encoding="utf-8")))
    return key / "entries" / cast(str, pointer["entry_id"])


def test_prepare_creates_only_expected_private_structure(store: RevisionStore) -> None:
    assert store.output_directory.is_dir()
    assert (store.internal_directory / "staging").is_dir()
    assert (store.internal_directory / "cache").is_dir()


def test_create_workspace_is_unique_and_confined(store: RevisionStore) -> None:
    first = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    second = store.create_workspace(1, ROOT_ADDRESS, now=NOW)

    assert first.run_id != second.run_id
    assert first.staging_directory.parent == store.internal_directory / "staging"
    assert first.final_directory.parent.parent.name == ROOT_ADDRESS
    assert first.source_directory(ROOT_ADDRESS).name == "sources"
    first.staging_directory.resolve().relative_to(store.internal_directory.resolve())


@pytest.mark.parametrize("unsafe", ["../escape", "with/slash", "", "..", "address:bad"])
def test_workspace_rejects_unsafe_path_segments(store: RevisionStore, unsafe: str) -> None:
    with pytest.raises(FilesystemOperationError) as raised:
        store.create_workspace(1, unsafe)

    assert raised.value.code is ErrorCode.FILESYSTEM_ERROR


def test_prepare_contract_and_runtime_bytecode_preserve_empty_vs_zero_byte(
    store: RevisionStore,
) -> None:
    workspace = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    sources = store.prepare_contract(workspace, ROOT_ADDRESS)

    empty_path = store.write_runtime_bytecode(workspace, ROOT_ADDRESS, "0x")
    zero_path = store.write_runtime_bytecode(workspace, SECOND_ADDRESS, "0x00")

    assert sources == workspace.source_directory(ROOT_ADDRESS)
    assert (workspace.staging_directory / empty_path).read_text(encoding="ascii") == "0x\n"
    assert (workspace.staging_directory / zero_path).read_text(encoding="ascii") == "0x00\n"


def test_inspect_sources_hashes_and_sorts_without_modifying_content(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(
        tmp_path / "sources",
        {
            "zeta/Contract.vy": b"# exact\r\n",
            "Alpha.sol": b"// SPDX-License-Identifier: MIT\ncontract A {}\n",
            "metadata.json": b'{"language":"Solidity"}\n',
        },
    )
    before = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }

    files = store.inspect_sources(source)

    assert [item.relative_path for item in files] == sorted(before)
    for item in files:
        assert item.size_bytes == len(before[item.relative_path])
        assert item.sha256 == hashlib.sha256(before[item.relative_path]).hexdigest()
    after = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize("with_empty_file", [False, True])
def test_inspect_sources_requires_at_least_one_nonempty_regular_file(
    store: RevisionStore,
    tmp_path: Path,
    with_empty_file: bool,
) -> None:
    source = tmp_path / "sources"
    source.mkdir()
    if with_empty_file:
        (source / "Empty.sol").touch()

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT


def test_inspect_sources_rejects_file_used_as_source_root(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = tmp_path / "not-a-directory"
    source.write_text("content", encoding="utf-8")

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


@pytest.mark.parametrize(
    ("limits", "files"),
    [
        (_limits(max_files=1), {"A.sol": b"a", "B.sol": b"b"}),
        (_limits(max_file_size_bytes=3), {"A.sol": b"four"}),
        (_limits(max_total_size_bytes=5), {"A.sol": b"abc", "B.sol": b"def"}),
    ],
)
def test_inspect_sources_enforces_file_count_and_size_limits(
    tmp_path: Path,
    limits: ResourceLimits,
    files: dict[str, bytes],
) -> None:
    local_store = RevisionStore(tmp_path / "output", limits)
    source = _source_tree(tmp_path / "sources", files)

    with pytest.raises(OutputSafetyError) as raised:
        local_store.inspect_sources(source)

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_inspect_sources_rejects_symlink(store: RevisionStore, tmp_path: Path) -> None:
    source = _source_tree(tmp_path / "sources", {"Real.sol": b"contract Real {}"})
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}", encoding="utf-8")
    link = source / "Linked.sol"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


def test_prepare_rejects_symlinked_internal_directory(tmp_path: Path) -> None:
    output = tmp_path / "downloads"
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    try:
        (output / ".sourceth").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        RevisionStore(output, _limits()).prepare()

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


def test_inspect_sources_rejects_hard_links(store: RevisionStore, tmp_path: Path) -> None:
    source = _source_tree(tmp_path / "sources", {"Original.sol": b"contract A {}"})
    try:
        os.link(source / "Original.sol", source / "Alias.sol")
    except OSError as error:
        pytest.skip(f"hard links no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


def test_inspect_sources_rejects_casefold_collisions_when_filesystem_allows_them(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"Token.sol": b"A"})
    (source / "token.sol").write_bytes(b"B")
    distinct_names = {path.name for path in source.iterdir()}
    if len(distinct_names) != 2:
        pytest.skip("el filesystem no permite crear nombres que solo difieren en mayúsculas")

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


@pytest.mark.skipif(os.name == "nt", reason="Windows interpreta la barra inversa como separador")
def test_inspect_sources_rejects_windows_separator_in_filename(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {r"dir\escape.sol": b"unsafe"})

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


@pytest.mark.skipif(os.name == "nt", reason="Windows no permite crear nombres reservados")
def test_inspect_sources_rejects_windows_reserved_name(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"CON.sol": b"unsafe"})

    with pytest.raises(OutputSafetyError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT


def test_publish_keeps_all_revisions_and_preserves_latest_complete_pointer(
    store: RevisionStore,
) -> None:
    complete = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    complete_dir = store.publish(
        complete,
        b'{"status":"complete"}\n',
        OverallStatus.COMPLETE,
        completed_at=NOW,
    )
    partial = store.create_workspace(1, ROOT_ADDRESS, now=NOW + timedelta(seconds=1))
    partial_dir = store.publish(
        partial,
        b'{"status":"partial"}\n',
        OverallStatus.PARTIAL,
        completed_at=NOW + timedelta(seconds=1),
    )

    latest_path = partial.final_directory.parent.parent / "latest.json"
    latest = cast(dict[str, object], json.loads(latest_path.read_text(encoding="utf-8")))
    assert complete_dir.is_dir()
    assert partial_dir.is_dir()
    assert complete_dir != partial_dir
    assert (complete_dir / "manifest.json").read_bytes() == b'{"status":"complete"}\n'
    assert latest["latest_run_id"] == partial.run_id
    assert latest["latest_status"] == "partial"
    assert latest["latest_complete_run_id"] == complete.run_id


def test_publish_never_overwrites_existing_revision(store: RevisionStore) -> None:
    workspace = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    store.publish(workspace, b"{}\n", OverallStatus.COMPLETE, completed_at=NOW)

    with pytest.raises(FilesystemOperationError) as raised:
        store.publish(workspace, b'{"changed":true}\n', OverallStatus.COMPLETE, completed_at=NOW)

    assert raised.value.code is ErrorCode.FILESYSTEM_ERROR
    assert (workspace.final_directory / "manifest.json").read_bytes() == b"{}\n"


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH portable es una política de Windows")
def test_publish_rejects_nonportable_windows_path_before_moving_staging(
    tmp_path: Path,
) -> None:
    suffix = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:8]
    local_store = RevisionStore(tmp_path.parent / f"d-max-{suffix}", _limits())
    local_store.prepare()
    workspace = local_store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    too_long_final = local_store.output_directory / ("a" * 100) / ("b" * 100) / ("c" * 80)
    forged = RunWorkspace(
        workspace.run_id,
        workspace.chain_id,
        workspace.root_address,
        workspace.staging_directory,
        too_long_final,
    )

    with pytest.raises(OutputSafetyError) as raised:
        local_store.publish(forged, b"{}\n", OverallStatus.COMPLETE, completed_at=NOW)

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert workspace.staging_directory.is_dir()
    assert not too_long_final.exists()


def test_publish_recovers_from_corrupt_latest_pointer(store: RevisionStore) -> None:
    first = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    store.publish(first, b"{}\n", OverallStatus.COMPLETE, completed_at=NOW)
    latest_path = first.final_directory.parent.parent / "latest.json"
    latest_path.write_text("not-json", encoding="utf-8")
    second = store.create_workspace(1, ROOT_ADDRESS, now=NOW + timedelta(seconds=1))

    store.publish(
        second,
        b"{}\n",
        OverallStatus.PARTIAL,
        completed_at=NOW + timedelta(seconds=1),
    )

    pointer = cast(dict[str, object], json.loads(latest_path.read_text(encoding="utf-8")))
    assert pointer["latest_run_id"] == second.run_id
    assert pointer["latest_status"] == "partial"
    assert "latest_complete_run_id" not in pointer


def test_discard_only_removes_owned_staging(store: RevisionStore, tmp_path: Path) -> None:
    workspace = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    store.discard(workspace)
    assert not workspace.staging_directory.exists()

    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    marker = outside / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    forged = RunWorkspace("forged", 1, ROOT_ADDRESS, outside, outside / "final")

    with pytest.raises(FilesystemOperationError):
        store.discard(forged)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_cache_round_trip_validates_integrity_and_restores_exact_bytes(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(
        tmp_path / "sources",
        {"A.sol": b"contract A {}\r\n", "nested/meta.json": b"{}\n"},
    )
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak="0xabc",
    )

    hit = store.cache_lookup(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        ttl_seconds=60,
        expected_runtime_bytecode_keccak="0xabc",
        now=NOW + timedelta(seconds=30),
    )

    assert isinstance(hit, CacheHit)
    assert hit.fetched_at == NOW
    destination = tmp_path / "restored"
    restored = store.cache_restore(hit, destination)
    assert restored == hit.files
    assert (destination / "A.sol").read_bytes() == b"contract A {}\r\n"
    assert (destination / "nested" / "meta.json").read_bytes() == b"{}\n"


def test_cache_expired_disabled_or_runtime_mismatch_is_not_reused(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"A.sol": b"contract A {}"})
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak="0xabc",
    )

    def lookup(ttl: int, expected: str, now: datetime) -> CacheHit | None:
        return store.cache_lookup(
            provider="etherscan",
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            ttl_seconds=ttl,
            expected_runtime_bytecode_keccak=expected,
            now=now,
        )

    assert lookup(0, "0xabc", NOW) is None
    assert lookup(60, "0xabc", NOW + timedelta(seconds=61)) is None
    assert lookup(60, "0xabc", NOW - timedelta(seconds=1)) is None
    assert lookup(60, "0xdifferent", NOW) is None


def test_corrupt_cache_content_or_metadata_is_never_reused(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"A.sol": b"original"})
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak=None,
    )
    entry = _cache_entry_from_pointer(store)
    (entry / "sources" / "A.sol").write_bytes(b"tampered")

    assert (
        store.cache_lookup(
            provider="etherscan",
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            ttl_seconds=60,
            expected_runtime_bytecode_keccak=None,
            now=NOW,
        )
        is None
    )

    (entry / "entry.json").write_text("not-json", encoding="utf-8")
    assert (
        store.cache_lookup(
            provider="etherscan",
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            ttl_seconds=60,
            expected_runtime_bytecode_keccak=None,
            now=NOW,
        )
        is None
    )


def test_malformed_cache_pointer_is_a_miss(store: RevisionStore) -> None:
    key = store._cache_key("etherscan", PROVIDER_IDENTITY, 1, ROOT_ADDRESS)
    key.mkdir(parents=True)
    (key / "latest.json").write_text('{"entry_id": 42}\n', encoding="utf-8")

    assert (
        store.cache_lookup(
            provider="etherscan",
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            ttl_seconds=60,
            expected_runtime_bytecode_keccak=None,
            now=NOW,
        )
        is None
    )


def test_cache_refresh_creates_new_entry_without_deleting_previous_revision(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"A.sol": b"version one"})
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak=None,
    )
    first_entry = _cache_entry_from_pointer(store)
    (source / "A.sol").write_bytes(b"version two")
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW + timedelta(seconds=1),
        runtime_bytecode_keccak=None,
    )
    second_entry = _cache_entry_from_pointer(store)

    assert first_entry != second_entry
    assert first_entry.is_dir()
    assert second_entry.is_dir()
    assert (first_entry / "sources" / "A.sol").read_bytes() == b"version one"
    assert (second_entry / "sources" / "A.sol").read_bytes() == b"version two"


def test_cache_restore_rejects_nonempty_destination(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources", {"A.sol": b"content"})
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak=None,
    )
    hit = store.cache_lookup(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        ttl_seconds=60,
        expected_runtime_bytecode_keccak=None,
        now=NOW,
    )
    assert hit is not None
    destination = _source_tree(tmp_path / "destination", {"existing.txt": b"keep"})

    with pytest.raises(FilesystemOperationError):
        store.cache_restore(hit, destination)
    assert (destination / "existing.txt").read_bytes() == b"keep"


@pytest.mark.parametrize("provider", ["../escape", "with/slash", "", ".."])
def test_cache_key_rejects_unsafe_provider_segment(
    store: RevisionStore,
    provider: str,
) -> None:
    with pytest.raises(FilesystemOperationError):
        store.cache_lookup(
            provider=provider,
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            ttl_seconds=60,
            expected_runtime_bytecode_keccak=None,
            now=NOW,
        )


def test_output_root_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    output = tmp_path / "downloads"
    try:
        output.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        RevisionStore(output, _limits()).prepare()

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT
    assert not any(outside.iterdir())


def test_publish_rejects_symlinked_chain_ancestor(store: RevisionStore, tmp_path: Path) -> None:
    workspace = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    outside = tmp_path / "outside-publish"
    outside.mkdir()
    chain = store.output_directory / "1"
    try:
        chain.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        store.publish(workspace, b"{}\n", OverallStatus.COMPLETE, completed_at=NOW)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT
    assert workspace.staging_directory.is_dir()
    assert not any(outside.iterdir())


def test_publish_rejects_replaced_latest_pointer_before_moving_staging(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    first = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    store.publish(first, b"{}\n", OverallStatus.COMPLETE, completed_at=NOW)
    latest = first.final_directory.parent.parent / "latest.json"
    outside = tmp_path / "outside-latest.json"
    outside.write_text("keep", encoding="utf-8")
    latest.unlink()
    try:
        latest.symlink_to(outside)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")
    second = store.create_workspace(1, ROOT_ADDRESS, now=NOW + timedelta(seconds=1))

    with pytest.raises(OutputSafetyError) as raised:
        store.publish(
            second,
            b"{}\n",
            OverallStatus.COMPLETE,
            completed_at=NOW + timedelta(seconds=1),
        )

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT
    assert second.staging_directory.is_dir()
    assert outside.read_text(encoding="utf-8") == "keep"


def test_cache_store_rejects_symlinked_key_ancestor(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources-safe", {"A.sol": b"contract A {}"})
    key = store._cache_key("etherscan", PROVIDER_IDENTITY, 1, ROOT_ADDRESS)
    outside = tmp_path / "outside-cache"
    outside.mkdir()
    try:
        key.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        store.cache_store(
            provider="etherscan",
            provider_identity=PROVIDER_IDENTITY,
            chain_id=1,
            address=ROOT_ADDRESS,
            source_directory=source,
            provider_fetched_at=NOW,
            runtime_bytecode_keccak=None,
        )

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT
    assert not any(outside.iterdir())


def test_cache_restore_rejects_change_after_lookup_and_cleans_destination(
    store: RevisionStore,
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path / "sources-race", {"A.sol": b"original"})
    store.cache_store(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        source_directory=source,
        provider_fetched_at=NOW,
        runtime_bytecode_keccak=None,
    )
    hit = store.cache_lookup(
        provider="etherscan",
        provider_identity=PROVIDER_IDENTITY,
        chain_id=1,
        address=ROOT_ADDRESS,
        ttl_seconds=60,
        expected_runtime_bytecode_keccak=None,
        now=NOW,
    )
    assert hit is not None
    (hit.entry_directory / "sources" / "A.sol").write_bytes(b"tampered")
    destination = tmp_path / "restored-race"

    with pytest.raises(OutputSafetyError) as raised:
        store.cache_restore(hit, destination)

    assert raised.value.code is ErrorCode.INVALID_PROVIDER_OUTPUT
    assert destination.is_dir()
    assert not any(destination.iterdir())


def test_inspect_sources_propagates_walk_errors(
    store: RevisionStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source_tree(tmp_path / "sources-walk", {"A.sol": b"contract A {}"})

    def failing_walk(*args: object, **kwargs: object) -> object:
        del args
        onerror = kwargs.get("onerror")
        assert callable(onerror)
        onerror(PermissionError("denied"))
        return iter(())

    monkeypatch.setattr(os, "walk", failing_walk)

    with pytest.raises(FilesystemOperationError) as raised:
        store.inspect_sources(source)

    assert raised.value.code is ErrorCode.FILESYSTEM_ERROR


def test_discard_unlinks_replaced_staging_without_deleting_target(
    store: RevisionStore,
) -> None:
    victim = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    survivor = store.create_workspace(1, SECOND_ADDRESS, now=NOW)
    marker = survivor.staging_directory / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    shutil.rmtree(victim.staging_directory)
    try:
        victim.staging_directory.symlink_to(survivor.staging_directory, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    store.discard(victim)

    assert marker.read_text(encoding="utf-8") == "keep"
    assert not victim.staging_directory.is_symlink()


def test_reset_contract_rejects_replaced_staging_without_deleting_target(
    store: RevisionStore,
) -> None:
    victim = store.create_workspace(1, ROOT_ADDRESS, now=NOW)
    survivor = store.create_workspace(1, SECOND_ADDRESS, now=NOW)
    survivor_sources = store.prepare_contract(survivor, ROOT_ADDRESS)
    marker = survivor_sources / "Keep.sol"
    marker.write_text("contract Keep {}", encoding="utf-8")
    shutil.rmtree(victim.staging_directory)
    try:
        victim.staging_directory.symlink_to(survivor.staging_directory, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks no disponibles en este host: {error}")

    with pytest.raises(OutputSafetyError) as raised:
        store.reset_contract_sources(victim, ROOT_ADDRESS)

    assert raised.value.code is ErrorCode.UNSAFE_OUTPUT
    assert marker.read_text(encoding="utf-8") == "contract Keep {}"
