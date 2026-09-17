from __future__ import annotations

import contextlib
import ctypes
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import IO, Final, Never, Protocol, cast

from src.errors import ErrorCode, ProcessExecutionError

_READ_CHUNK_SIZE: Final = 64 * 1024
_WAIT_SLICE_SECONDS: Final = 0.05
_SIGKILL: Final = int(cast(int, getattr(signal, "SIGKILL", 9)))
_SIGTERM: Final = int(signal.SIGTERM)
_CREATE_NEW_PROCESS_GROUP: Final = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
_REDACTED: Final = "[REDACTADO]"
_REDACTED_URL: Final = "[URL_REDACTADA]"
_WINDOWS_BOOTSTRAP_SPAWN_FAILURE: Final = 0x5343
_WINDOWS_JOB_BOOTSTRAP: Final = f"""
import subprocess
import sys

if sys.stdin.buffer.read(1) != b"G":
    raise SystemExit(126)
try:
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL)
except OSError:
    raise SystemExit({_WINDOWS_BOOTSTRAP_SPAWN_FAILURE}) from None
raise SystemExit(child.wait())
""".strip()

DEFAULT_INHERITED_ENVIRONMENT: Final[frozenset[str]] = frozenset(
    {
        "APPDATA",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)
DEFAULT_ALLOWED_ENVIRONMENT: Final[frozenset[str]] = DEFAULT_INHERITED_ENVIRONMENT | {
    "ALL_PROXY",
    "ETHERSCAN_API_KEY",
    "ETH_RPC_URL",
    "EXPLORER_API_URL",
    "EXPLORER_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "NO_COLOR",
}
DEFAULT_SECRET_ENVIRONMENT: Final[frozenset[str]] = frozenset(
    {"ALL_PROXY", "ETHERSCAN_API_KEY", "ETH_RPC_URL", "HTTP_PROXY", "HTTPS_PROXY"}
)

_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_ENVIRONMENT_NAME = re.compile(
    r"(?:AUTH|CREDENTIAL|KEY|PASS(?:WORD|WD)?|RPC_URL|SECRET|TOKEN)", re.IGNORECASE
)
_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>]+")
_NAMED_SECRET = re.compile(r"(?i)\b(api[_-]?key|authorization|password|secret|token)=([^&\s]+)")
_BEARER_TOKEN = re.compile(r"(?i)\b(bearer)\s+[^\s,;]+")
_SENSITIVE_ARGUMENTS: Final[frozenset[str]] = frozenset(
    {
        "--api-key",
        "--authorization",
        "--password",
        "--rpc-url",
        "--secret",
        "--token",
    }
)
_FORBIDDEN_WINDOWS_WRAPPERS: Final[frozenset[str]] = frozenset({".bat", ".cmd"})


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Resultado ya acotado y saneado de una invocación externa."""

    argv: tuple[str, ...]
    executable: Path
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    stdout_total_bytes: int
    stderr_total_bytes: int
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    output_limit_exceeded: bool = False
    cleanup_succeeded: bool = True

    @property
    def succeeded(self) -> bool:
        """Indica únicamente que el proceso devolvió cero."""

        return self.returncode == 0 and not self.timed_out and not self.output_limit_exceeded

    def to_dict(self) -> dict[str, object]:
        """Devuelve una representación serializable sin secretos ni entorno."""

        return {
            "argv": list(self.argv),
            "executable": str(self.executable),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "stdout_total_bytes": self.stdout_total_bytes,
            "stderr_total_bytes": self.stderr_total_bytes,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "timed_out": self.timed_out,
            "output_limit_exceeded": self.output_limit_exceeded,
            "cleanup_succeeded": self.cleanup_succeeded,
        }


class ProcessRunnerProtocol(Protocol):
    """Interfaz mínima para inyectar un runner en otros adaptadores."""

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sensitive_values: Iterable[str] = (),
    ) -> ProcessResult: ...


class _BoundedCapture:
    """Drena un pipe sin permitir que su contenido crezca sin límite."""

    __slots__ = ("buffer", "error", "limit", "limit_event", "total_bytes", "truncated")

    def __init__(self, limit: int, limit_event: threading.Event) -> None:
        self.limit = limit
        self.limit_event = limit_event
        self.buffer = bytearray()
        self.total_bytes = 0
        self.truncated = False
        self.error: OSError | None = None

    def drain(self, stream: IO[bytes]) -> None:
        try:
            while True:
                chunk = stream.read(_READ_CHUNK_SIZE)
                if not chunk:
                    return
                self.total_bytes += len(chunk)
                remaining = self.limit - len(self.buffer)
                if remaining > 0:
                    self.buffer.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    self.truncated = True
                    self.limit_event.set()
        except OSError as exc:
            self.error = exc


class _WinApiFunction(Protocol):
    """Superficie tipada mínima para las funciones Win32 usadas aquí."""

    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> object: ...


class _WindowsCtypesModule(Protocol):
    """Atributos de ``ctypes`` que typeshed solo expone en Windows."""

    def WinDLL(self, name: str, *, use_last_error: bool = False) -> object: ...

    def WinError(self, code: int | None = None) -> OSError: ...

    def get_last_error(self) -> int: ...


class _Kernel32(Protocol):
    CreateJobObjectW: _WinApiFunction
    SetInformationJobObject: _WinApiFunction
    OpenProcess: _WinApiFunction
    AssignProcessToJobObject: _WinApiFunction
    TerminateJobObject: _WinApiFunction
    CloseHandle: _WinApiFunction


class _WindowsJob:
    """Job Object con cierre destructivo para contener todo el árbol hijo."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
    _PROCESS_TERMINATE: Final = 0x0001
    _PROCESS_SET_QUOTA: Final = 0x0100

    def __init__(self) -> None:
        if os.name != "nt":  # pragma: no cover - guardia de plataforma
            raise OSError("Los Job Objects solo están disponibles en Windows")

        from ctypes import wintypes

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", wintypes.ULARGE_INTEGER),
                ("WriteOperationCount", wintypes.ULARGE_INTEGER),
                ("OtherOperationCount", wintypes.ULARGE_INTEGER),
                ("ReadTransferCount", wintypes.ULARGE_INTEGER),
                ("WriteTransferCount", wintypes.ULARGE_INTEGER),
                ("OtherTransferCount", wintypes.ULARGE_INTEGER),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        windows_ctypes = cast(_WindowsCtypesModule, ctypes)
        kernel32 = cast(_Kernel32, windows_ctypes.WinDLL("kernel32", use_last_error=True))
        create_job = kernel32.CreateJobObjectW
        set_information = kernel32.SetInformationJobObject
        open_process = kernel32.OpenProcess
        assign_process = kernel32.AssignProcessToJobObject
        terminate_job = kernel32.TerminateJobObject
        close_handle = kernel32.CloseHandle

        create_job.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        create_job.restype = wintypes.HANDLE
        set_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        set_information.restype = wintypes.BOOL
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        assign_process.restype = wintypes.BOOL
        terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminate_job.restype = wintypes.BOOL
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        handle_object = create_job(None, None)
        handle = cast(int | None, handle_object)
        if not handle:
            raise windows_ctypes.WinError(windows_ctypes.get_last_error())

        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        configured = bool(
            set_information(
                handle,
                self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        )
        if not configured:
            error = windows_ctypes.get_last_error()
            close_handle(handle)
            raise windows_ctypes.WinError(error)

        self._handle: int | None = handle
        self._open_process = open_process
        self._assign_process = assign_process
        self._terminate_job = terminate_job
        self._close_handle = close_handle

    def assign(self, process_id: int) -> None:
        if self._handle is None:
            raise OSError("El Job Object ya está cerrado")
        process_handle_object = self._open_process(
            self._PROCESS_TERMINATE | self._PROCESS_SET_QUOTA,
            False,
            process_id,
        )
        process_handle = cast(int | None, process_handle_object)
        if not process_handle:
            windows_ctypes = cast(_WindowsCtypesModule, ctypes)
            raise windows_ctypes.WinError(windows_ctypes.get_last_error())
        try:
            if not bool(self._assign_process(self._handle, process_handle)):
                windows_ctypes = cast(_WindowsCtypesModule, ctypes)
                raise windows_ctypes.WinError(windows_ctypes.get_last_error())
        finally:
            self._close_handle(process_handle)

    def terminate(self) -> bool:
        if self._handle is None:
            return True
        return bool(self._terminate_job(self._handle, 1))

    def close(self) -> bool:
        if self._handle is None:
            return True
        handle = self._handle
        self._handle = None
        return bool(self._close_handle(handle))


class _Sanitizer:
    __slots__ = ("_fragment_patterns", "_secrets")

    def __init__(self, secrets: Iterable[str]) -> None:
        known_secrets = {value for value in secrets if value}
        self._secrets = tuple(sorted(known_secrets, key=len, reverse=True))
        fragments = {
            fragment
            for secret in known_secrets
            for fragment in self._sensitive_url_fragments(secret)
            if fragment not in known_secrets
        }
        self._fragment_patterns = tuple(
            re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(fragment)}(?![A-Za-z0-9_-])")
            for fragment in sorted(fragments, key=len, reverse=True)
        )

    def text(self, value: str) -> str:
        sanitized = value
        for secret in self._secrets:
            sanitized = sanitized.replace(secret, _REDACTED)
        for pattern in self._fragment_patterns:
            sanitized = pattern.sub(_REDACTED, sanitized)
        sanitized = _URL.sub(_REDACTED_URL, sanitized)
        sanitized = _NAMED_SECRET.sub(lambda match: f"{match.group(1)}={_REDACTED}", sanitized)
        return _BEARER_TOKEN.sub(lambda match: f"{match.group(1)} {_REDACTED}", sanitized)

    @classmethod
    def _sensitive_url_fragments(cls, value: str) -> frozenset[str]:
        """Extrae credenciales y tokens sin convertir toda la URL en secretos parciales."""

        if "://" not in value:
            return frozenset()
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            return frozenset()
        if parsed.scheme.casefold() not in {"http", "https", "ws", "wss"} or not parsed.netloc:
            return frozenset()

        fragments: set[str] = set()
        cls._add_url_fragment(fragments, parsed.username)
        cls._add_url_fragment(fragments, parsed.password)

        for raw_segment in parsed.path.split("/"):
            cls._add_url_fragment(fragments, raw_segment)

        for raw_pair in parsed.query.split("&"):
            _raw_name, separator, raw_value = raw_pair.partition("=")
            cls._add_url_fragment(
                fragments,
                raw_value if separator else raw_pair,
                plus_as_space=True,
            )
        return frozenset(fragments)

    @staticmethod
    def _add_url_fragment(
        fragments: set[str],
        raw_value: str | None,
        *,
        plus_as_space: bool = False,
    ) -> None:
        if raw_value is None:
            return
        decoded = (
            urllib.parse.unquote_plus(raw_value)
            if plus_as_space
            else urllib.parse.unquote(raw_value)
        )
        for candidate in (raw_value, decoded):
            if candidate:
                fragments.add(candidate)

    def argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        result: list[str] = []
        redact_next = False
        for argument in argv:
            if redact_next:
                result.append(_REDACTED)
                redact_next = False
                continue
            name, separator, _value = argument.partition("=")
            normalized = name.casefold()
            if normalized in _SENSITIVE_ARGUMENTS:
                result.append(f"{name}={_REDACTED}" if separator else name)
                redact_next = not separator
                continue
            result.append(self.text(argument))
        return tuple(result)


class ProcessRunner:
    """Ejecuta un binario directo en un entorno mínimo y con recursos acotados."""

    def __init__(
        self,
        *,
        timeout: float = 60.0,
        max_stdout_bytes: int = 1024 * 1024,
        max_stderr_bytes: int = 1024 * 1024,
        termination_grace_seconds: float = 1.0,
        environment_allowlist: Iterable[str] = DEFAULT_ALLOWED_ENVIRONMENT,
        inherited_environment: Iterable[str] = DEFAULT_INHERITED_ENVIRONMENT,
        secret_environment: Iterable[str] = DEFAULT_SECRET_ENVIRONMENT,
        host_environment: Mapping[str, str] | None = None,
    ) -> None:
        self._timeout = self._positive_number(timeout, "timeout")
        self._max_stdout_bytes = self._non_negative_integer(max_stdout_bytes, "max_stdout_bytes")
        self._max_stderr_bytes = self._non_negative_integer(max_stderr_bytes, "max_stderr_bytes")
        self._termination_grace_seconds = self._non_negative_number(
            termination_grace_seconds, "termination_grace_seconds"
        )
        self._host_environment = dict(os.environ if host_environment is None else host_environment)
        self._allowed_environment = self._environment_names(environment_allowlist)
        self._inherited_environment = self._environment_names(inherited_environment)
        self._secret_environment = self._environment_names(secret_environment)
        if not self._inherited_environment <= self._allowed_environment:
            self._configuration_failure(
                "Las variables heredadas deben pertenecer a la allowlist del proceso."
            )
        if not self._secret_environment <= self._allowed_environment:
            self._configuration_failure(
                "Las variables secretas deben pertenecer a la allowlist del proceso."
            )

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sensitive_values: Iterable[str] = (),
    ) -> ProcessResult:
        """Ejecuta ``argv`` sin shell y devuelve solo salida saneada.

        Un retorno distinto de cero forma parte de :class:`ProcessResult`; el
        adaptador consumidor conserva así el contexto necesario para clasificarlo.
        Timeout, exceso de salida o imposibilidad de crear/controlar el proceso
        producen :class:`~src.errors.ProcessExecutionError`.
        """

        normalized_argv = self._normalize_argv(argv)
        child_environment, environment_secrets = self._build_environment(env)
        explicit_secrets = self._normalize_sensitive_values(sensitive_values)
        sanitizer = _Sanitizer((*environment_secrets, *explicit_secrets))
        self._reject_sensitive_arguments(
            normalized_argv,
            (*environment_secrets, *explicit_secrets),
        )
        resolved_executable = self.resolve_executable(
            normalized_argv[0],
            search_path=self._environment_value(child_environment, "PATH"),
            path_extensions=self._environment_value(child_environment, "PATHEXT"),
            sanitizer=sanitizer,
        )
        resolved_argv = (str(resolved_executable), *normalized_argv[1:])
        sanitized_argv = sanitizer.argv(resolved_argv)
        effective_timeout = (
            self._timeout if timeout is None else self._positive_number(timeout, "timeout")
        )
        resolved_cwd = self._resolve_cwd(cwd)

        started = time.monotonic()
        limit_event = threading.Event()
        stdout_capture = _BoundedCapture(self._max_stdout_bytes, limit_event)
        stderr_capture = _BoundedCapture(self._max_stderr_bytes, limit_event)
        windows_job: _WindowsJob | None = None
        process: subprocess.Popen[bytes] | None = None

        try:
            if os.name == "nt":
                windows_job = self._create_windows_job(sanitizer)
                # El bootstrap aislado espera un byte antes de crear Cast. Así
                # puede entrar primero en el Job Object y el hijo lo hereda sin
                # la carrera CreateProcess -> AssignProcessToJobObject.
                process = subprocess.Popen(
                    (
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        _WINDOWS_JOB_BOOTSTRAP,
                        *resolved_argv,
                    ),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=resolved_cwd,
                    env=child_environment,
                    shell=False,
                    bufsize=0,
                    creationflags=_CREATE_NEW_PROCESS_GROUP,
                )
                try:
                    windows_job.assign(process.pid)
                    if process.stdin is None:  # pragma: no cover - Popen recibió PIPE
                        raise OSError("No se abrió el canal de arranque controlado")
                    process.stdin.write(b"G")
                    process.stdin.flush()
                    process.stdin.close()
                except OSError as exc:
                    self._terminate_tree(process, windows_job)
                    windows_job = None
                    raise self._execution_error(
                        ErrorCode.DOWNLOAD_FAILED,
                        "No se pudo contener e iniciar el proceso externo en un Job Object.",
                        sanitizer=sanitizer,
                        argv=sanitized_argv,
                        cause=exc,
                    ) from exc
            else:
                process = subprocess.Popen(
                    resolved_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=resolved_cwd,
                    env=child_environment,
                    shell=False,
                    bufsize=0,
                    start_new_session=True,
                )
        except ProcessExecutionError:
            if windows_job is not None:
                windows_job.close()
            raise
        except OSError as exc:
            if windows_job is not None:
                windows_job.close()
            raise self._execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudo iniciar el proceso externo.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                cause=exc,
            ) from exc

        # Popen garantiza ambos pipes con la configuración anterior.
        if process.stdout is None or process.stderr is None:  # pragma: no cover
            self._terminate_tree(process, windows_job)
            self._raise_execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudieron abrir los canales de salida del proceso.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
            )

        stdout_thread = threading.Thread(
            target=stdout_capture.drain,
            args=(process.stdout,),
            name="sourceth-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stderr_capture.drain,
            args=(process.stderr,),
            name="sourceth-stderr",
            daemon=True,
        )
        started_threads: list[threading.Thread] = []
        try:
            stdout_thread.start()
            started_threads.append(stdout_thread)
            stderr_thread.start()
            started_threads.append(stderr_thread)
        except BaseException as exc:
            self._terminate_tree(process, windows_job)
            windows_job = None
            with contextlib.suppress(OSError):
                process.stdout.close()
            with contextlib.suppress(OSError):
                process.stderr.close()
            for thread in started_threads:
                thread.join(timeout=max(self._termination_grace_seconds, 0.1))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise self._execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudo iniciar la captura del proceso externo.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                cause=exc,
            ) from exc

        failure_kind: str | None = None
        cleanup_succeeded = True
        deadline = started + effective_timeout
        try:
            while process.poll() is None:
                if limit_event.is_set():
                    failure_kind = "output_limit"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure_kind = "timeout"
                    break
                limit_event.wait(min(_WAIT_SLICE_SECONDS, remaining))

            if failure_kind is not None:
                cleanup_succeeded = self._terminate_tree(process, windows_job)
                windows_job = None
            else:
                process.wait()
                cleanup_succeeded = self._release_process_group(process.pid, windows_job)
                windows_job = None
        except BaseException:
            cleanup_succeeded = self._terminate_tree(process, windows_job)
            windows_job = None
            raise
        finally:
            if windows_job is not None:
                cleanup_succeeded = windows_job.close() and cleanup_succeeded

        captures_joined = self._join_capture_threads(
            process,
            (stdout_thread, stderr_thread),
            self._termination_grace_seconds + 1.0,
        )
        cleanup_succeeded = captures_joined and cleanup_succeeded
        if limit_event.is_set() and failure_kind is None:
            failure_kind = "output_limit"

        duration = time.monotonic() - started
        result = self._build_result(
            process=process,
            executable=resolved_executable,
            argv=sanitized_argv,
            stdout_capture=stdout_capture,
            stderr_capture=stderr_capture,
            sanitizer=sanitizer,
            duration=duration,
            timed_out=failure_kind == "timeout",
            output_limit_exceeded=failure_kind == "output_limit",
            cleanup_succeeded=cleanup_succeeded,
        )

        if (
            os.name == "nt"
            and failure_kind is None
            and result.returncode == _WINDOWS_BOOTSTRAP_SPAWN_FAILURE
        ):
            self._raise_execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "Windows no pudo crear el ejecutable externo validado.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                result=result,
            )

        if failure_kind == "timeout":
            self._raise_execution_error(
                ErrorCode.DOWNLOAD_TIMEOUT,
                f"El proceso externo superó el timeout de {effective_timeout:g} segundos.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                result=result,
            )
        if failure_kind == "output_limit":
            self._raise_execution_error(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "El proceso externo superó el límite de salida capturada.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                result=result,
            )
        capture_error = stdout_capture.error or stderr_capture.error
        if capture_error is not None:
            raise self._execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "Falló la captura de la salida del proceso externo.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                result=result,
                cause=capture_error,
            ) from capture_error
        if not cleanup_succeeded:
            self._raise_execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudo confirmar la limpieza completa del grupo de procesos.",
                sanitizer=sanitizer,
                argv=sanitized_argv,
                result=result,
            )
        return result

    def resolve_executable(
        self,
        executable: str | os.PathLike[str],
        *,
        search_path: str | None = None,
        path_extensions: str | None = None,
        sanitizer: _Sanitizer | None = None,
    ) -> Path:
        """Resuelve un binario sin aceptar rutas relativas ni wrappers de shell."""

        normalized = self._path_string(executable, "ejecutable")
        active_sanitizer = sanitizer or _Sanitizer(())
        if Path(normalized).suffix.casefold() in _FORBIDDEN_WINDOWS_WRAPPERS:
            self._raise_execution_error(
                ErrorCode.CAST_UNSUPPORTED,
                "No se admiten ejecutables .bat o .cmd.",
                sanitizer=active_sanitizer,
                argv=active_sanitizer.argv((normalized,)),
            )

        explicit_path = Path(normalized)
        windows_path = PureWindowsPath(normalized)
        has_separator = "/" in normalized or "\\" in normalized
        has_drive = bool(windows_path.drive)
        candidate: Path | None
        if explicit_path.is_absolute():
            candidate = explicit_path
        elif has_separator or has_drive:
            self._raise_execution_error(
                ErrorCode.INVALID_CONFIGURATION,
                "La ruta configurada del ejecutable debe ser absoluta.",
                sanitizer=active_sanitizer,
                argv=active_sanitizer.argv((normalized,)),
            )
        else:
            candidate = self._search_path(normalized, search_path, path_extensions)
            if candidate is None:
                self._raise_execution_error(
                    ErrorCode.CAST_NOT_FOUND,
                    "No se encontró el ejecutable externo en un PATH permitido.",
                    sanitizer=active_sanitizer,
                    argv=active_sanitizer.argv((normalized,)),
                )

        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise self._execution_error(
                ErrorCode.CAST_NOT_FOUND,
                "No se pudo resolver el ejecutable configurado.",
                sanitizer=active_sanitizer,
                argv=active_sanitizer.argv((normalized,)),
                cause=exc,
            ) from exc
        if resolved.suffix.casefold() in _FORBIDDEN_WINDOWS_WRAPPERS:
            self._raise_execution_error(
                ErrorCode.CAST_UNSUPPORTED,
                "El ejecutable resuelto es un wrapper .bat o .cmd no admitido.",
                sanitizer=active_sanitizer,
                argv=active_sanitizer.argv((normalized,)),
            )
        if not resolved.is_file() or (os.name != "nt" and not os.access(resolved, os.X_OK)):
            self._raise_execution_error(
                ErrorCode.CAST_NOT_FOUND,
                "La ruta configurada no es un archivo ejecutable.",
                sanitizer=active_sanitizer,
                argv=active_sanitizer.argv((normalized,)),
            )
        return resolved

    def _search_path(
        self,
        executable: str,
        search_path: str | None,
        path_extensions: str | None,
    ) -> Path | None:
        if not search_path:
            return None
        directories: list[Path] = []
        for raw_directory in search_path.split(os.pathsep):
            if not raw_directory:
                continue
            directory = Path(raw_directory)
            if directory.is_absolute():
                directories.append(directory)

        names = [executable]
        if os.name == "nt" and not Path(executable).suffix:
            raw_extensions = path_extensions or ".COM;.EXE;.BAT;.CMD"
            names.extend(
                f"{executable}{extension}"
                for extension in raw_extensions.split(os.pathsep)
                if extension and extension.casefold() not in _FORBIDDEN_WINDOWS_WRAPPERS
            )
        for directory in directories:
            for name in names:
                candidate = directory / name
                if candidate.suffix.casefold() in _FORBIDDEN_WINDOWS_WRAPPERS:
                    continue
                if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                    return candidate
        return None

    def _build_environment(
        self, overrides: Mapping[str, str] | None
    ) -> tuple[dict[str, str], tuple[str, ...]]:
        inherited_by_name: dict[str, tuple[str, str]] = {}
        secret_values: list[str] = []
        for key, value in self._host_environment.items():
            canonical = self._canonical_environment_name(key)
            if canonical not in self._inherited_environment:
                continue
            if not isinstance(value, str) or "\0" in value:
                self._configuration_failure(
                    "El entorno heredado contiene un valor inválido.",
                    details={"environment_name": key},
                )
            inherited_by_name[canonical] = (key, value)
            if (
                canonical in self._secret_environment
                or _SENSITIVE_ENVIRONMENT_NAME.search(key)
                or "://" in value
            ):
                secret_values.append(value)
        child_environment = dict(inherited_by_name.values())
        if overrides is not None:
            for key, value in overrides.items():
                canonical = self._validate_environment_name(key)
                if canonical not in self._allowed_environment:
                    self._configuration_failure(
                        "Se intentó pasar una variable fuera de la allowlist del proceso.",
                        details={"environment_name": key},
                    )
                if not isinstance(value, str) or "\0" in value:
                    self._configuration_failure(
                        "El entorno del proceso contiene un valor inválido.",
                        details={"environment_name": key},
                    )
                previous = inherited_by_name.get(canonical)
                if previous is not None:
                    child_environment.pop(previous[0], None)
                child_environment[key] = value
                if (
                    canonical in self._secret_environment
                    or _SENSITIVE_ENVIRONMENT_NAME.search(key)
                    or "://" in value
                ):
                    secret_values.append(value)
        return child_environment, tuple(secret_values)

    def _normalize_argv(self, argv: Sequence[str | os.PathLike[str]]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or not argv:
            self._configuration_failure("El comando debe ser una lista de argumentos no vacía.")
        normalized: list[str] = []
        for index, argument in enumerate(argv):
            try:
                value = os.fspath(argument)
            except TypeError:
                self._configuration_failure(
                    "El comando contiene un argumento que no es texto.",
                    details={"argument_index": index},
                )
            if not isinstance(value, str) or not value or "\0" in value:
                self._configuration_failure(
                    "El comando contiene un argumento vacío o inválido.",
                    details={"argument_index": index},
                )
            normalized.append(value)
        return tuple(normalized)

    def _resolve_cwd(self, cwd: str | os.PathLike[str] | None) -> Path | None:
        if cwd is None:
            return None
        path = Path(self._path_string(cwd, "directorio de trabajo"))
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise self._execution_error(
                ErrorCode.INVALID_CONFIGURATION,
                "No se pudo resolver el directorio de trabajo del proceso.",
                sanitizer=_Sanitizer(()),
                argv=(),
                cause=exc,
            ) from exc
        if not resolved.is_dir():
            self._configuration_failure("El directorio de trabajo del proceso no es un directorio.")
        return resolved

    def _build_result(
        self,
        *,
        process: subprocess.Popen[bytes],
        executable: Path,
        argv: tuple[str, ...],
        stdout_capture: _BoundedCapture,
        stderr_capture: _BoundedCapture,
        sanitizer: _Sanitizer,
        duration: float,
        timed_out: bool,
        output_limit_exceeded: bool,
        cleanup_succeeded: bool,
    ) -> ProcessResult:
        return ProcessResult(
            argv=argv,
            executable=executable,
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=self._decode_and_sanitize(
                stdout_capture.buffer, sanitizer, self._max_stdout_bytes
            ),
            stderr=self._decode_and_sanitize(
                stderr_capture.buffer, sanitizer, self._max_stderr_bytes
            ),
            duration_seconds=duration,
            stdout_total_bytes=stdout_capture.total_bytes,
            stderr_total_bytes=stderr_capture.total_bytes,
            stdout_truncated=stdout_capture.truncated,
            stderr_truncated=stderr_capture.truncated,
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
            cleanup_succeeded=cleanup_succeeded,
        )

    @staticmethod
    def _decode_and_sanitize(data: bytearray, sanitizer: _Sanitizer, limit: int) -> str:
        sanitized = sanitizer.text(bytes(data).decode("utf-8", errors="replace"))
        encoded = sanitized.encode("utf-8")
        if len(encoded) <= limit:
            return sanitized
        return encoded[:limit].decode("utf-8", errors="ignore")

    def _create_windows_job(self, sanitizer: _Sanitizer) -> _WindowsJob:
        try:
            return _WindowsJob()
        except OSError as exc:
            raise self._execution_error(
                ErrorCode.DOWNLOAD_FAILED,
                "No se pudo crear el contenedor de procesos de Windows.",
                sanitizer=sanitizer,
                argv=(),
                cause=exc,
            ) from exc

    def _terminate_tree(
        self, process: subprocess.Popen[bytes], windows_job: _WindowsJob | None
    ) -> bool:
        cleanup_succeeded = True
        if os.name == "nt":
            if windows_job is not None:
                terminated = windows_job.terminate()
                # Debe cerrarse incluso si TerminateJobObject falla: el flag
                # KILL_ON_JOB_CLOSE es la segunda barrera para todo el árbol.
                closed = windows_job.close()
                cleanup_succeeded = terminated and closed
            else:
                cleanup_succeeded = False
                with contextlib.suppress(OSError):
                    process.kill()
        else:
            cleanup_succeeded = self._stop_posix_process_group(process.pid, leader=process)

        try:
            process.wait(timeout=max(self._termination_grace_seconds, 0.1))
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=max(self._termination_grace_seconds, 0.1))
            except (OSError, subprocess.TimeoutExpired):
                cleanup_succeeded = False
        return cleanup_succeeded and process.poll() is not None

    def _release_process_group(self, process_id: int, windows_job: _WindowsJob | None) -> bool:
        if os.name == "nt":
            return windows_job is not None and windows_job.close()
        return self._stop_posix_process_group(process_id)

    def _stop_posix_process_group(
        self,
        process_id: int,
        *,
        leader: subprocess.Popen[bytes] | None = None,
    ) -> bool:
        """Detiene y confirma el grupo completo, aunque el líder ya haya salido."""

        try:
            self._kill_process_group(process_id, _SIGTERM)
        except ProcessLookupError:
            return True
        except OSError:
            return False

        deadline = time.monotonic() + self._termination_grace_seconds
        while time.monotonic() < deadline:
            if leader is not None:
                # poll() ejecuta waitpid(WNOHANG) en POSIX y evita que el líder
                # zombie mantenga artificialmente vivo el PGID.
                leader.poll()
            try:
                self._kill_process_group(process_id, 0)
            except ProcessLookupError:
                return True
            except OSError:
                return False
            time.sleep(min(_WAIT_SLICE_SECONDS, max(deadline - time.monotonic(), 0.0)))
        try:
            self._kill_process_group(process_id, _SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        # SIGKILL se envió al grupo completo. Confirmar su desaparición evita
        # declarar éxito mientras queda un descendiente vivo o zombie no reaped.
        kill_deadline = time.monotonic() + max(self._termination_grace_seconds, 0.1)
        while time.monotonic() < kill_deadline:
            if leader is not None:
                leader.poll()
            try:
                self._kill_process_group(process_id, 0)
            except ProcessLookupError:
                return True
            except OSError:
                return False
            time.sleep(min(_WAIT_SLICE_SECONDS, max(kill_deadline - time.monotonic(), 0.0)))
        return False

    @staticmethod
    def _kill_process_group(process_id: int, signal_number: int) -> None:
        kill_group = cast(
            Callable[[int, int], None],
            getattr(os, "killpg", None),
        )
        if kill_group is None:  # pragma: no cover - solo se invoca en POSIX
            raise OSError("La plataforma no ofrece killpg")
        kill_group(process_id, signal_number)

    @staticmethod
    def _join_capture_threads(
        process: subprocess.Popen[bytes],
        threads: tuple[threading.Thread, threading.Thread],
        timeout: float,
    ) -> bool:
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(deadline - time.monotonic(), 0.0))
        if any(thread.is_alive() for thread in threads):
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
            for thread in threads:
                thread.join(0.1)
        return not any(thread.is_alive() for thread in threads)

    def _reject_sensitive_arguments(
        self,
        argv: Sequence[str],
        secrets: Iterable[str],
    ) -> None:
        known_secrets = tuple(value for value in secrets if value)
        for index, argument in enumerate(argv[1:], start=1):
            name, _separator, _value = argument.partition("=")
            if name.casefold() in _SENSITIVE_ARGUMENTS or _URL.search(argument):
                self._configuration_failure(
                    "Los secretos y las URLs sensibles deben pasarse mediante "
                    "el entorno controlado.",
                    details={"argument_index": index},
                )
            if any(
                argument == secret or (len(secret) >= 4 and secret in argument)
                for secret in known_secrets
            ):
                self._configuration_failure(
                    "Se detectó un valor sensible en los argumentos del proceso.",
                    details={"argument_index": index},
                )

    def _environment_value(self, environment: Mapping[str, str], name: str) -> str | None:
        canonical = self._canonical_environment_name(name)
        for key, value in environment.items():
            if self._canonical_environment_name(key) == canonical:
                return value
        return None

    def _execution_error(
        self,
        code: ErrorCode,
        message: str,
        *,
        sanitizer: _Sanitizer,
        argv: tuple[str, ...],
        result: ProcessResult | None = None,
        cause: BaseException | None = None,
    ) -> ProcessExecutionError:
        details: dict[str, object] = {"argv": list(argv)}
        if result is not None:
            details["process"] = result.to_dict()
        if cause is not None:
            details["cause"] = sanitizer.text(str(cause))
        return ProcessExecutionError(
            code=code,
            message=sanitizer.text(message),
            details=details,
            retryable=code is ErrorCode.DOWNLOAD_TIMEOUT,
            cause=cause,
        )

    def _raise_execution_error(
        self,
        code: ErrorCode,
        message: str,
        *,
        sanitizer: _Sanitizer,
        argv: tuple[str, ...],
        result: ProcessResult | None = None,
    ) -> Never:
        raise self._execution_error(
            code,
            message,
            sanitizer=sanitizer,
            argv=argv,
            result=result,
        )

    def _configuration_failure(
        self, message: str, *, details: Mapping[str, object] | None = None
    ) -> Never:
        raise ProcessExecutionError(
            code=ErrorCode.INVALID_CONFIGURATION,
            message=message,
            details=details,
            retryable=False,
        )

    def _environment_names(self, names: Iterable[str]) -> frozenset[str]:
        return frozenset(self._validate_environment_name(name) for name in names)

    def _validate_environment_name(self, name: str) -> str:
        if not isinstance(name, str) or not _ENVIRONMENT_NAME.fullmatch(name):
            self._configuration_failure("La allowlist contiene un nombre de entorno inválido.")
        return self._canonical_environment_name(name)

    @staticmethod
    def _canonical_environment_name(name: str) -> str:
        return name.upper() if os.name == "nt" else name

    def _normalize_sensitive_values(self, values: Iterable[str]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            if not isinstance(value, str):
                self._configuration_failure("Los valores sensibles deben ser texto.")
            if value:
                normalized.append(value)
        return tuple(normalized)

    def _path_string(self, value: str | os.PathLike[str], label: str) -> str:
        try:
            normalized = os.fspath(value)
        except TypeError:
            self._configuration_failure(f"El {label} no es una ruta válida.")
        if not isinstance(normalized, str) or not normalized or "\0" in normalized:
            self._configuration_failure(f"El {label} no es una ruta válida.")
        return normalized

    def _positive_number(self, value: float, label: str) -> float:
        if isinstance(value, bool):
            self._configuration_failure(f"{label} debe ser un número positivo.")
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            self._configuration_failure(f"{label} debe ser un número positivo.")
        if normalized <= 0 or not normalized < float("inf"):
            self._configuration_failure(f"{label} debe ser un número positivo y finito.")
        return normalized

    def _non_negative_number(self, value: float, label: str) -> float:
        if isinstance(value, bool):
            self._configuration_failure(f"{label} debe ser un número no negativo.")
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            self._configuration_failure(f"{label} debe ser un número no negativo.")
        if normalized < 0 or not normalized < float("inf"):
            self._configuration_failure(f"{label} debe ser un número no negativo y finito.")
        return normalized

    def _non_negative_integer(self, value: int, label: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            self._configuration_failure(f"{label} debe ser un entero no negativo.")
        return value
