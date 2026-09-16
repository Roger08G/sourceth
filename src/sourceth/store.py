from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from filelock import FileLock
from filelock import Timeout as FileLockTimeout

from .config import ResourceLimits
from .errors import ErrorCode, FilesystemOperationError, OutputSafetyError
from .models import FileDigest, OverallStatus
from .validation import validate_portable_relative_path, validate_runtime_bytecode

_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")
_REPARSE_POINT = 0x0400


@dataclass(frozen=True, slots=True)
class RunWorkspace:
    """Revisión privada que todavía no es visible como resultado terminado."""

    run_id: str
    chain_id: int
    root_address: str
    staging_directory: Path
    final_directory: Path

    def contract_directory(self, address: str) -> Path:
        return self.staging_directory / "contracts" / address

    def source_directory(self, address: str) -> Path:
        return self.contract_directory(address) / "sources"


@dataclass(frozen=True, slots=True)
class CacheHit:
    entry_directory: Path
    fetched_at: datetime
    files: tuple[FileDigest, ...]
    runtime_bytecode_keccak: str | None
    provider_identity: str


def _safe_segment(value: str, *, label: str) -> str:
    if _SAFE_COMPONENT_RE.fullmatch(value) is None or value in {".", ".."}:
        raise FilesystemOperationError(
            ErrorCode.FILESYSTEM_ERROR,
            f"{label} no puede utilizarse como componente de ruta.",
        )
    return value


def _has_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & _REPARSE_POINT)


def _ensure_plain_directory(path: Path, *, create: bool = False) -> None:
    try:
        if create:
            path.mkdir(exist_ok=True, mode=0o700)
        info = path.lstat()
    except OSError as error:
        raise FilesystemOperationError(
            ErrorCode.FILESYSTEM_ERROR,
            "No se pudo preparar un directorio de Sourceth.",
            details={"path": str(path)},
            cause=error,
        ) from error
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or _has_reparse_point(path):
        raise OutputSafetyError(
            ErrorCode.UNSAFE_OUTPUT,
            "Un directorio de salida es un enlace, junction o archivo especial.",
            details={"path": str(path)},
        )


def _ensure_plain_descendant(
    root: Path,
    target: Path,
    *,
    create: bool = False,
    missing_ok: bool = False,
) -> Path | None:
    """Valida todos los componentes sin seguir enlaces ni usar ``parents=True``."""

    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise OutputSafetyError(
            ErrorCode.UNSAFE_OUTPUT,
            "Una ruta de almacenamiento salió de su raíz confiable.",
            details={"path": str(target)},
            cause=error,
        ) from error

    _ensure_plain_directory(root)
    root_resolved = root.resolve(strict=True)
    current = root
    for part in relative.parts:
        current = current / part
        if create:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as error:
                raise FilesystemOperationError(
                    ErrorCode.FILESYSTEM_ERROR,
                    "No se pudo crear un directorio de Sourceth.",
                    details={"path": str(current)},
                    cause=error,
                ) from error
        try:
            _ensure_plain_directory(current)
        except FilesystemOperationError as error:
            if missing_ok and isinstance(error.__cause__, FileNotFoundError):
                return None
            raise
        try:
            current.resolve(strict=True).relative_to(root_resolved)
        except (OSError, ValueError) as error:
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "Un componente de almacenamiento escapó de su raíz confiable.",
                details={"path": str(current)},
                cause=error,
            ) from error
    return target


def _ensure_plain_absolute_directory(path: Path, *, create: bool) -> None:
    """Valida desde el ancla para no perder symlinks al resolver ``--output``."""

    if not path.is_absolute() or not path.anchor:
        raise FilesystemOperationError(
            ErrorCode.FILESYSTEM_ERROR,
            "El directorio de salida no pudo convertirse en una ruta absoluta.",
        )
    anchor = Path(path.anchor)
    result = _ensure_plain_descendant(anchor, path, create=create)
    if result is None:  # pragma: no cover - missing_ok=False
        raise AssertionError("la ruta absoluta no puede quedar ausente")


def _plain_regular_file(path: Path, *, missing_ok: bool = False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise
    except OSError as error:
        raise FilesystemOperationError(
            ErrorCode.FILESYSTEM_ERROR,
            "No se pudo validar un archivo de Sourceth.",
            details={"path": str(path)},
            cause=error,
        ) from error
    if path.is_symlink() or _has_reparse_point(path) or not stat.S_ISREG(info.st_mode):
        raise OutputSafetyError(
            ErrorCode.UNSAFE_OUTPUT,
            "Un archivo de almacenamiento es un enlace o archivo especial.",
            details={"path": str(path)},
        )
    return True


def _atomic_write(path: Path, payload: bytes) -> None:
    """Escribe y sustituye un archivo sin exponer contenido parcial."""

    _ensure_plain_directory(path.parent, create=True)
    # Mantener el nombre temporal corto evita rebasar MAX_PATH en hosts Windows
    # que aún no tienen habilitadas rutas extendidas.
    temporary = path.parent / f".s-{uuid.uuid4().hex[:8]}.tmp"
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as error:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise FilesystemOperationError(
            ErrorCode.FILESYSTEM_ERROR,
            "No se pudo completar una escritura atómica.",
            details={"path": str(path)},
            cause=error,
        ) from error


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp ausente")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp sin zona horaria")
    return parsed.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class RevisionStore:
    """Almacén local sin sobrescrituras silenciosas ni resultados mutables."""

    def __init__(
        self,
        output_directory: Path,
        limits: ResourceLimits,
        *,
        lock_timeout_seconds: float = 10.0,
    ) -> None:
        expanded = output_directory.expanduser()
        self.output_directory = Path(os.path.abspath(expanded))
        self.limits = limits
        self.lock_timeout_seconds = lock_timeout_seconds

    @property
    def internal_directory(self) -> Path:
        return self.output_directory / ".sourceth"

    def prepare(self) -> None:
        _ensure_plain_absolute_directory(self.output_directory, create=True)
        _ensure_plain_descendant(
            self.output_directory,
            self.internal_directory / "staging",
            create=True,
        )
        _ensure_plain_descendant(
            self.output_directory,
            self.internal_directory / "cache",
            create=True,
        )
        _ensure_plain_descendant(
            self.output_directory,
            self.internal_directory / "locks",
            create=True,
        )

    def create_workspace(
        self,
        chain_id: int,
        root_address: str,
        *,
        now: datetime | None = None,
    ) -> RunWorkspace:
        self.prepare()
        chain = _safe_segment(str(chain_id), label="chain_id")
        root = _safe_segment(root_address, label="dirección raíz")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        prefix = current.strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{prefix}-{uuid.uuid4().hex[:12]}"
        staging = self.internal_directory / "staging" / run_id
        final = self.output_directory / chain / root / "runs" / run_id
        try:
            staging.mkdir(mode=0o700)
            (staging / "contracts").mkdir(mode=0o700)
            _ensure_plain_descendant(self.internal_directory / "staging", staging)
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo crear el staging privado.",
                details={"run_id": run_id},
                cause=error,
            ) from error
        return RunWorkspace(run_id, chain_id, root_address, staging, final)

    def prepare_contract(self, workspace: RunWorkspace, address: str) -> Path:
        safe_address = _safe_segment(address, label="dirección de contrato")
        destination = workspace.staging_directory / "contracts" / safe_address / "sources"
        _ensure_plain_descendant(
            self.internal_directory / "staging",
            workspace.staging_directory,
        )
        _ensure_plain_descendant(workspace.staging_directory, destination, create=True)
        return destination

    def reset_contract_sources(self, workspace: RunWorkspace, address: str) -> Path:
        """Retira una salida fallida sin publicar archivos remotos no inspeccionados."""

        safe_address = _safe_segment(address, label="dirección de contrato")
        staging_container = self.internal_directory / "staging"
        _ensure_plain_descendant(staging_container, workspace.staging_directory)
        contract_directory = workspace.contract_directory(safe_address)
        _ensure_plain_descendant(workspace.staging_directory, contract_directory)

        destination = contract_directory / "sources"
        try:
            try:
                info = destination.lstat()
            except FileNotFoundError:
                info = None
            if info is not None:
                if destination.is_symlink():
                    destination.unlink()
                elif _has_reparse_point(destination):
                    if stat.S_ISDIR(info.st_mode):
                        destination.rmdir()
                    else:
                        destination.unlink()
                else:
                    if stat.S_ISDIR(info.st_mode):
                        # No sigue symlinks y no recorre junctions en Python soportado.
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
            destination.mkdir(mode=0o700)
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo limpiar la salida parcial de un contrato.",
                details={"address": safe_address},
                cause=error,
            ) from error
        return destination

    def write_runtime_bytecode(
        self,
        workspace: RunWorkspace,
        address: str,
        bytecode: str,
    ) -> str:
        normalized = validate_runtime_bytecode(bytecode)
        contract_directory = workspace.contract_directory(
            _safe_segment(address, label="dirección de contrato")
        )
        _ensure_plain_descendant(workspace.staging_directory, contract_directory, create=True)
        path = contract_directory / "runtime-bytecode.hex"
        _atomic_write(path, (normalized + "\n").encode("ascii"))
        return path.relative_to(workspace.staging_directory).as_posix()

    def inspect_sources(self, source_directory: Path) -> tuple[FileDigest, ...]:
        """Valida todo el árbol y calcula hashes sin seguir enlaces."""

        _ensure_plain_directory(source_directory)
        root = source_directory.resolve(strict=True)
        seen_casefolded: dict[str, str] = {}
        files: list[FileDigest] = []
        total_size = 0
        nonempty_files = 0

        try:

            def raise_walk_error(error: OSError) -> None:
                raise error

            walker = os.walk(
                root,
                topdown=True,
                onerror=raise_walk_error,
                followlinks=False,
            )
            for current_raw, directories, filenames in walker:
                current = Path(current_raw)
                directories.sort()
                filenames.sort()

                for directory_name in list(directories):
                    child = current / directory_name
                    relative = child.relative_to(root).as_posix()
                    self._validate_entry(child, relative, root=root, expect_directory=True)
                    self._record_collision(relative, seen_casefolded)

                for filename in filenames:
                    child = current / filename
                    relative = child.relative_to(root).as_posix()
                    self._validate_entry(child, relative, root=root, expect_directory=False)
                    self._record_collision(relative, seen_casefolded)
                    info = child.lstat()
                    if info.st_size > self.limits.max_file_size_bytes:
                        raise OutputSafetyError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "Un archivo descargado supera el tamaño máximo.",
                            details={"path": relative, "size_bytes": info.st_size},
                        )
                    total_size += info.st_size
                    if total_size > self.limits.max_total_size_bytes:
                        raise OutputSafetyError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "La descarga supera el tamaño total máximo.",
                            details={"total_size_bytes": total_size},
                        )
                    if info.st_size:
                        nonempty_files += 1
                    files.append(
                        FileDigest(
                            relative_path=relative,
                            size_bytes=info.st_size,
                            sha256=self._sha256_regular_file(child, info),
                        )
                    )
                    if len(files) > self.limits.max_files:
                        raise OutputSafetyError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "La descarga supera el número máximo de archivos.",
                            details={"file_count": len(files)},
                        )
        except OutputSafetyError:
            raise
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo inspeccionar el resultado descargado.",
                cause=error,
            ) from error

        if not files or nonempty_files == 0:
            raise OutputSafetyError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                "Cast no generó ninguna fuente no vacía.",
            )
        return tuple(sorted(files, key=lambda item: item.relative_path))

    def _validate_entry(
        self,
        path: Path,
        relative: str,
        *,
        root: Path,
        expect_directory: bool,
    ) -> None:
        if "\\" in relative:
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "La ruta descargada contiene un separador de Windows no portable.",
                details={"path": relative},
            )
        try:
            portable = validate_portable_relative_path(relative)
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "El proveedor produjo una ruta insegura.",
                details={"path": relative},
                cause=error,
            ) from error
        if portable != relative.replace("\\", "/"):
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "La ruta descargada no es portable.",
                details={"path": relative},
            )
        info = path.lstat()
        if path.is_symlink() or _has_reparse_point(path):
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "La descarga contiene un enlace o junction.",
                details={"path": relative},
            )
        expected = stat.S_ISDIR(info.st_mode) if expect_directory else stat.S_ISREG(info.st_mode)
        if not expected or (not expect_directory and info.st_nlink != 1):
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "La descarga contiene un archivo especial o hard link.",
                details={"path": relative},
            )

    @staticmethod
    def _record_collision(relative: str, seen: dict[str, str]) -> None:
        key = relative.casefold()
        previous = seen.get(key)
        if previous is not None and previous != relative:
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "La descarga contiene rutas que colisionan sin distinguir mayúsculas.",
                details={"path": relative, "conflicts_with": previous},
            )
        seen[key] = relative

    @staticmethod
    def _sha256_regular_file(path: Path, expected: os.stat_result) -> str:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        digest = hashlib.sha256()
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ) != (expected.st_dev, expected.st_ino, expected.st_size):
                raise OutputSafetyError(
                    ErrorCode.UNSAFE_OUTPUT,
                    "Un archivo cambió durante la inspección.",
                    details={"path": path.name},
                )
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
        finally:
            os.close(descriptor)
        return digest.hexdigest()

    def publish(
        self,
        workspace: RunWorkspace,
        manifest: bytes,
        status: OverallStatus,
        *,
        completed_at: datetime,
    ) -> Path:
        """Publica una revisión y actualiza punteros bajo un bloqueo por raíz."""

        staging_root = self.internal_directory / "staging"
        _ensure_plain_descendant(staging_root, workspace.staging_directory)
        _atomic_write(workspace.staging_directory / "manifest.json", manifest)
        self._validate_final_path_lengths(
            workspace.staging_directory,
            workspace.final_directory,
        )
        root_directory = workspace.final_directory.parent.parent
        _ensure_plain_descendant(
            self.output_directory,
            workspace.final_directory.parent,
            create=True,
        )
        lock = FileLock(
            str(self._lock_path("publish", str(workspace.chain_id), workspace.root_address))
        )
        try:
            with lock.acquire(timeout=self.lock_timeout_seconds):
                # Repetir ambas validaciones dentro del bloqueo evita confiar en
                # un ancestro que haya sido sustituido mientras se esperaba.
                _ensure_plain_descendant(staging_root, workspace.staging_directory)
                _ensure_plain_descendant(
                    self.output_directory,
                    workspace.final_directory.parent,
                    create=True,
                )
                try:
                    workspace.final_directory.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise FilesystemOperationError(
                        ErrorCode.FILESYSTEM_ERROR,
                        "El identificador de revisión ya existe; no se sobrescribirá.",
                        details={"run_id": workspace.run_id},
                    )
                latest_path = root_directory / "latest.json"
                pointer: dict[str, object] = {}
                if _plain_regular_file(latest_path, missing_ok=True):
                    try:
                        loaded = json.loads(latest_path.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            pointer = {str(key): value for key, value in loaded.items()}
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        pointer = {}
                os.replace(workspace.staging_directory, workspace.final_directory)

                pointer.update(
                    {
                        "schema_version": 1,
                        "latest_run_id": workspace.run_id,
                        "latest_status": status.value,
                        "updated_at": _utc_text(completed_at),
                    }
                )
                if status is OverallStatus.COMPLETE:
                    pointer["latest_complete_run_id"] = workspace.run_id
                _atomic_write(latest_path, _json_bytes(pointer))
        except FileLockTimeout as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo obtener el bloqueo de publicación.",
                details={"root_address": workspace.root_address},
                cause=error,
            ) from error
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo publicar la revisión terminada.",
                details={"run_id": workspace.run_id},
                cause=error,
            ) from error
        return workspace.final_directory

    @staticmethod
    def _validate_final_path_lengths(staging: Path, final: Path) -> None:
        """Evita publicar árboles inaccesibles bajo MAX_PATH de Windows."""

        if os.name != "nt":
            return
        candidates = [final, final.parent.parent / "latest.json"]
        try:

            def raise_walk_error(error: OSError) -> None:
                raise error

            for current_raw, directories, filenames in os.walk(
                staging,
                onerror=raise_walk_error,
                followlinks=False,
            ):
                current = Path(current_raw)
                for name in (*directories, *filenames):
                    relative = (current / name).relative_to(staging)
                    candidates.append(final / relative)
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo validar la longitud de las rutas finales.",
                cause=error,
            ) from error
        longest = max(candidates, key=lambda path: len(str(path)))
        if len(str(longest)) >= 260:
            raise OutputSafetyError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Una ruta final superaría el límite portable de Windows.",
                details={"path_length": len(str(longest)), "max_path_length": 259},
            )

    def discard(self, workspace: RunWorkspace) -> None:
        """Elimina exclusivamente el staging conocido de esta instancia."""

        staging_root = self.internal_directory / "staging"
        _ensure_plain_descendant(self.output_directory, staging_root)
        candidate = workspace.staging_directory
        try:
            relative = candidate.relative_to(staging_root)
        except ValueError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "Se rechazó limpiar una ruta ajena al staging.",
                cause=error,
            ) from error
        if len(relative.parts) != 1 or relative.name != workspace.run_id:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "Se rechazó limpiar un staging que no es hijo directo conocido.",
            )
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo validar el staging antes de limpiarlo.",
                cause=error,
            ) from error
        if candidate.is_symlink() or _has_reparse_point(candidate):
            try:
                if stat.S_ISDIR(info.st_mode) and candidate.is_junction():
                    candidate.rmdir()
                else:
                    candidate.unlink()
            except OSError as error:
                raise FilesystemOperationError(
                    ErrorCode.FILESYSTEM_ERROR,
                    "No se pudo retirar el enlace que sustituyó al staging.",
                    cause=error,
                ) from error
            return
        if not stat.S_ISDIR(info.st_mode):
            raise OutputSafetyError(
                ErrorCode.UNSAFE_OUTPUT,
                "El staging fue sustituido por un archivo especial.",
            )
        _ensure_plain_descendant(staging_root, candidate)
        if candidate != staging_root:
            shutil.rmtree(candidate)

    def cache_lookup(
        self,
        *,
        provider: str,
        provider_identity: str,
        chain_id: int,
        address: str,
        ttl_seconds: int,
        expected_runtime_bytecode_keccak: str | None,
        now: datetime | None = None,
    ) -> CacheHit | None:
        key_root = self._cache_key(provider, provider_identity, chain_id, address)
        cache_root = self.internal_directory / "cache"
        if _ensure_plain_descendant(cache_root, key_root, missing_ok=True) is None:
            return None
        pointer_path = key_root / "latest.json"
        if ttl_seconds <= 0 or not _plain_regular_file(pointer_path, missing_ok=True):
            return None
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            entry_id = pointer["entry_id"]
            if not isinstance(entry_id, str):
                return None
            entry_directory = key_root / "entries" / _safe_segment(entry_id, label="cache entry")
            if _ensure_plain_descendant(key_root, entry_directory, missing_ok=True) is None:
                return None
            metadata_path = entry_directory / "entry.json"
            if not _plain_regular_file(metadata_path, missing_ok=True):
                return None
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            fetched_at = _parse_utc(metadata["provider_fetched_at"])
            current = (now or datetime.now(UTC)).astimezone(UTC)
            if fetched_at > current or current - fetched_at > timedelta(seconds=ttl_seconds):
                return None
            if (
                metadata.get("provider") != provider
                or metadata.get("provider_identity") != provider_identity
                or metadata.get("chain_id") != chain_id
                or metadata.get("address") != address
            ):
                return None
            recorded_runtime = metadata.get("runtime_bytecode_keccak")
            if expected_runtime_bytecode_keccak is not None and (
                recorded_runtime != expected_runtime_bytecode_keccak
            ):
                return None
            files = self.inspect_sources(entry_directory / "sources")
            recorded_files = metadata.get("files")
            actual_files = [
                {
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                }
                for item in files
            ]
            if recorded_files != actual_files:
                return None
            return CacheHit(
                entry_directory,
                fetched_at,
                files,
                recorded_runtime,
                provider_identity,
            )
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError):
            return None
        except FilesystemOperationError:
            return None

    def cache_restore(self, hit: CacheHit, destination: Path) -> tuple[FileDigest, ...]:
        _ensure_plain_directory(destination, create=True)
        if any(destination.iterdir()):
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "El destino de caché no está vacío.",
            )
        _ensure_plain_descendant(
            self.internal_directory / "cache",
            hit.entry_directory,
        )
        for file in hit.files:
            relative = Path(validate_portable_relative_path(file.relative_path))
            source = hit.entry_directory / "sources" / relative
            target = destination / relative
            _ensure_plain_descendant(destination, target.parent, create=True)
            shutil.copyfile(source, target, follow_symlinks=False)
        restored = self.inspect_sources(destination)
        if restored != hit.files:
            try:
                shutil.rmtree(destination)
                destination.mkdir(mode=0o700)
            except OSError as error:
                raise FilesystemOperationError(
                    ErrorCode.FILESYSTEM_ERROR,
                    "La caché cambió y no se pudo limpiar su copia parcial.",
                    cause=error,
                ) from error
            raise OutputSafetyError(
                ErrorCode.INVALID_PROVIDER_OUTPUT,
                "La caché cambió durante su restauración; se descartó.",
            )
        return restored

    def cache_store(
        self,
        *,
        provider: str,
        provider_identity: str,
        chain_id: int,
        address: str,
        source_directory: Path,
        provider_fetched_at: datetime,
        runtime_bytecode_keccak: str | None,
    ) -> None:
        files = self.inspect_sources(source_directory)
        key_root = self._cache_key(provider, provider_identity, chain_id, address)
        lock = FileLock(
            str(self._lock_path("cache", provider, provider_identity, str(chain_id), address))
        )
        entry_id = uuid.uuid4().hex[:16]
        temporary = self.internal_directory / "staging" / f"cache-{entry_id}"
        final = key_root / "entries" / entry_id
        try:
            with lock.acquire(timeout=self.lock_timeout_seconds):
                _ensure_plain_descendant(
                    self.internal_directory / "cache",
                    key_root,
                    create=True,
                )
                _ensure_plain_descendant(
                    self.internal_directory / "staging",
                    temporary.parent,
                )
                temporary.mkdir(mode=0o700)
                destination = temporary / "sources"
                destination.mkdir(mode=0o700)
                for file in files:
                    relative = Path(validate_portable_relative_path(file.relative_path))
                    target = destination / relative
                    _ensure_plain_descendant(destination, target.parent, create=True)
                    shutil.copyfile(source_directory / relative, target, follow_symlinks=False)
                metadata: dict[str, object] = {
                    "schema_version": 1,
                    "provider": provider,
                    "provider_identity": provider_identity,
                    "chain_id": chain_id,
                    "address": address,
                    "provider_fetched_at": _utc_text(provider_fetched_at),
                    "runtime_bytecode_keccak": runtime_bytecode_keccak,
                    "files": [
                        {
                            "relative_path": item.relative_path,
                            "sha256": item.sha256,
                            "size_bytes": item.size_bytes,
                        }
                        for item in files
                    ],
                }
                _atomic_write(temporary / "entry.json", _json_bytes(metadata))
                _ensure_plain_descendant(key_root, final.parent, create=True)
                os.replace(temporary, final)
                _atomic_write(
                    key_root / "latest.json",
                    _json_bytes({"schema_version": 1, "entry_id": entry_id}),
                )
        except FileLockTimeout as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo bloquear la caché local.",
                cause=error,
            ) from error
        except OSError as error:
            raise FilesystemOperationError(
                ErrorCode.FILESYSTEM_ERROR,
                "No se pudo actualizar la caché local.",
                cause=error,
            ) from error
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def _cache_key(
        self,
        provider: str,
        provider_identity: str,
        chain_id: int,
        address: str,
    ) -> Path:
        safe_provider = _safe_segment(provider, label="proveedor")
        safe_identity = _safe_segment(provider_identity, label="identidad del proveedor")
        safe_chain = _safe_segment(str(chain_id), label="chain_id")
        safe_address = _safe_segment(address, label="dirección")
        digest = hashlib.sha256(
            "\0".join((safe_provider.casefold(), safe_identity, safe_chain, safe_address)).encode(
                "utf-8"
            )
        ).hexdigest()[:32]
        # El inventario conserva y compara la identidad completa; el componente
        # compacto evita rebasar MAX_PATH en Windows y una colisión es cache miss.
        return self.internal_directory / "cache" / f"k-{digest}"

    def _lock_path(self, namespace: str, *identity: str) -> Path:
        locks = self.internal_directory / "locks"
        _ensure_plain_descendant(self.output_directory, locks)
        digest = hashlib.sha256("\0".join(identity).encode("utf-8")).hexdigest()
        return locks / f"{_safe_segment(namespace, label='tipo de bloqueo')}-{digest}.lock"
