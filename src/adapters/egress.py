from __future__ import annotations

import base64
import contextlib
import hmac
import os
import secrets
import select
import socket
import threading
import time
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Protocol
from urllib.parse import urlsplit

_MAX_HEADER_BYTES: Final = 8 * 1024
_MAX_BLOCKED_TARGETS: Final = 16
_BUFFER_BYTES: Final = 64 * 1024
_POLL_SECONDS: Final = 0.1
_SO_EXCLUSIVEADDRUSE: Final = int(getattr(socket, "SO_EXCLUSIVEADDRUSE", -5))


class EgressGuardProtocol(Protocol):
    """Superficie inyectable que necesita el adaptador de Cast."""

    @property
    def environment(self) -> Mapping[str, str]: ...

    @property
    def blocked_targets(self) -> tuple[str, ...]: ...

    def __enter__(self) -> EgressGuardProtocol: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None: ...


class ExplorerEgressGuard:
    """Proxy CONNECT efímero que solo abre el origen HTTPS configurado.

    Cast 1.8.3 usa la configuración proxy de reqwest. Al entregarle este proxy
    en un entorno hijo limpio, una redirección a otro host no puede completar
    TLS ni recibir el ``Referer`` que contendría la API key.
    """

    def __init__(
        self,
        explorer_api_url: str,
        *,
        connect_timeout_seconds: float = 3.0,
        max_connections: int = 8,
    ) -> None:
        parsed = urlsplit(explorer_api_url)
        if parsed.scheme.casefold() != "https" or parsed.hostname is None:
            raise ValueError("La guardia requiere un endpoint HTTPS con hostname")
        self._allowed_host = self._normalize_host(parsed.hostname)
        self._allowed_port = parsed.port or 443
        if connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds debe ser positivo")
        if max_connections <= 0:
            raise ValueError("max_connections debe ser positivo")
        self._connect_timeout = connect_timeout_seconds
        self._max_connections = max_connections
        self._token = secrets.token_urlsafe(24)
        encoded = base64.b64encode(f"sourceth:{self._token}".encode("ascii")).decode("ascii")
        self._expected_authorization = f"Basic {encoded}"
        self._environment: Mapping[str, str] = MappingProxyType({})
        self._listener: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._sockets: set[socket.socket] = set()
        self._blocked_targets: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._used = False

    @property
    def environment(self) -> Mapping[str, str]:
        if self._listener is None:
            raise RuntimeError("La guardia de salida no está activa")
        return self._environment

    @property
    def blocked_targets(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._blocked_targets))

    def __enter__(self) -> ExplorerEgressGuard:
        if self._used:
            raise RuntimeError("La guardia de salida es de un solo uso")
        self._used = True
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # En Windows SO_REUSEADDR permite listeners rivales sobre el mismo
            # puerto. La exclusividad evita que otro proceso local intercepte
            # el CONNECT autenticado del hijo.
            if os.name == "nt":
                listener.setsockopt(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(self._max_connections)
            listener.settimeout(_POLL_SECONDS)
        except OSError:
            listener.close()
            raise
        self._listener = listener
        port = int(listener.getsockname()[1])
        proxy_url = f"http://sourceth:{self._token}@127.0.0.1:{port}"
        self._environment = MappingProxyType(
            {
                "HTTPS_PROXY": proxy_url,
                "HTTP_PROXY": proxy_url,
                "ALL_PROXY": proxy_url,
                # El entorno de Cast es deliberadamente limpio; una lista no
                # ausente y sin reglas impide recuperar no_proxy del host.
                "NO_PROXY": "__sourceth_force_proxy__.invalid",
            }
        )
        server_thread = threading.Thread(
            target=self._serve,
            name="sourceth-egress",
            daemon=True,
        )
        self._server_thread = server_thread
        try:
            server_thread.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.close()
        server_thread = self._server_thread
        if (
            server_thread is not None
            and server_thread.ident is not None
            and server_thread is not threading.current_thread()
        ):
            server_thread.join(timeout=1.0)
        with self._lock:
            sockets = tuple(self._sockets)
            workers = tuple(self._workers)
        for active in sockets:
            with contextlib.suppress(OSError):
                active.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                active.close()
        deadline = time.monotonic() + self._connect_timeout + 0.5
        for worker in workers:
            if worker.ident is not None and worker is not threading.current_thread():
                worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:  # pragma: no cover - solo se inicia tras bind
            return
        while not self._stop.is_set():
            try:
                client, _peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                if self._stop.is_set():
                    client.close()
                    return
                if len(self._workers) >= self._max_connections:
                    client.close()
                    continue
                self._sockets.add(client)
                worker = threading.Thread(
                    target=self._handle_client,
                    args=(client,),
                    name="sourceth-egress-client",
                    daemon=True,
                )
                self._workers.add(worker)
                try:
                    worker.start()
                except RuntimeError:
                    self._workers.discard(worker)
                    self._sockets.discard(client)
                    client.close()
                    continue

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(self._connect_timeout)
            header = self._read_header(client, timeout_seconds=self._connect_timeout)
            method, authority, _version, headers = self._parse_request(header)
            authorized = hmac.compare_digest(
                headers.get("proxy-authorization", ""),
                self._expected_authorization,
            )
            if method != "CONNECT":
                if authorized:
                    self._record_blocked_target("<non-CONNECT>")
                self._respond(client, 403, "Forbidden")
                return
            host, port = self._parse_authority(authority)
            target = f"{host}:{port}"
            allowed_origin = (
                self._normalize_host(host) == self._allowed_host and port == self._allowed_port
            )
            allowed = authorized and allowed_origin
            if not allowed:
                if authorized and not allowed_origin:
                    self._record_blocked_target(target)
                self._respond(client, 403, "Forbidden")
                return
            upstream = socket.create_connection(
                (self._allowed_host, self._allowed_port),
                timeout=self._connect_timeout,
            )
            upstream.settimeout(self._connect_timeout)
            client.settimeout(self._connect_timeout)
            with self._lock:
                self._sockets.add(upstream)
            self._respond(client, 200, "Connection Established")
            self._relay(client, upstream)
        except (OSError, ValueError):
            with contextlib.suppress(OSError):
                self._respond(client, 502, "Bad Gateway")
        finally:
            for active in (client, upstream):
                if active is None:
                    continue
                with self._lock:
                    self._sockets.discard(active)
                with contextlib.suppress(OSError):
                    active.close()
            current = threading.current_thread()
            with self._lock:
                self._workers.discard(current)

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        peers = {client: upstream, upstream: client}
        readable_sources = set(peers)
        while readable_sources and not self._stop.is_set():
            readable, _, exceptional = select.select(
                tuple(readable_sources),
                (),
                tuple(readable_sources),
                _POLL_SECONDS,
            )
            if exceptional:
                return
            for source in readable:
                try:
                    chunk = source.recv(_BUFFER_BYTES)
                except TimeoutError:
                    continue
                if not chunk:
                    readable_sources.discard(source)
                    with contextlib.suppress(OSError):
                        peers[source].shutdown(socket.SHUT_WR)
                    continue
                peers[source].sendall(chunk)

    @staticmethod
    def _read_header(client: socket.socket, *, timeout_seconds: float) -> bytes:
        payload = bytearray()
        deadline = time.monotonic() + timeout_seconds
        while b"\r\n\r\n" not in payload:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("tiempo de cabecera proxy agotado")
            client.settimeout(remaining)
            chunk = client.recv(min(1024, _MAX_HEADER_BYTES - len(payload)))
            if not chunk:
                raise ValueError("petición proxy incompleta")
            payload.extend(chunk)
            if len(payload) >= _MAX_HEADER_BYTES:
                raise ValueError("cabecera proxy demasiado grande")
        header, _separator, remainder = bytes(payload).partition(b"\r\n\r\n")
        if remainder:
            raise ValueError("datos antes de completar CONNECT")
        return header

    def _record_blocked_target(self, target: str) -> None:
        with self._lock:
            if len(self._blocked_targets) < _MAX_BLOCKED_TARGETS:
                self._blocked_targets.add(target)

    @staticmethod
    def _parse_request(header: bytes) -> tuple[str, str, str, dict[str, str]]:
        try:
            lines = header.decode("ascii").split("\r\n")
            method, authority, version = lines[0].split(" ", 2)
        except (UnicodeError, ValueError, IndexError) as error:
            raise ValueError("petición proxy inválida") from error
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if not separator:
                raise ValueError("cabecera proxy inválida")
            headers[name.strip().casefold()] = value.strip()
        return method, authority, version, headers

    @staticmethod
    def _parse_authority(authority: str) -> tuple[str, int]:
        if authority.startswith("["):
            closing = authority.find("]")
            if closing < 0 or authority[closing + 1 : closing + 2] != ":":
                raise ValueError("authority IPv6 inválida")
            host = authority[1:closing]
            raw_port = authority[closing + 2 :]
        else:
            host, separator, raw_port = authority.rpartition(":")
            if not separator:
                raise ValueError("authority sin puerto")
        port = int(raw_port)
        if not host or not 1 <= port <= 65535:
            raise ValueError("authority inválida")
        return host, port

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.rstrip(".").encode("idna").decode("ascii").casefold()

    @staticmethod
    def _respond(client: socket.socket, status: int, reason: str) -> None:
        client.sendall(f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\r\n".encode("ascii"))


__all__ = ["EgressGuardProtocol", "ExplorerEgressGuard"]
