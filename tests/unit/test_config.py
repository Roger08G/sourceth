"""Pruebas offline para la carga estricta de configuración."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest

from sourceth.config import ConfigOverrides, NetworkConfig, SecretValue, load_config
from sourceth.errors import ConfigurationError, ErrorCode, SourcethError


def test_load_config_uses_documented_defaults_without_process_environment() -> None:
    config = load_config(environ={}, dotenv_path=None, config_path=None)

    assert config.chain_id == 1
    assert config.output_dir == Path("downloads")
    assert config.cast_path == "cast"
    assert config.network.name == "ethereum-mainnet"
    assert config.credentials.rpc_url is None
    assert config.credentials.api_key is None


def test_cli_path_override_is_accepted_as_pathlib_value(tmp_path: Path) -> None:
    output = tmp_path / "custom-output"

    config = load_config(
        ConfigOverrides(output_dir=output),
        environ={},
        dotenv_path=None,
    )

    assert config.output_dir == output


def test_config_precedence_is_cli_then_environment_then_dotenv_then_toml(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    dotenv_path = tmp_path / ".env"
    config_path.write_text(
        'output_dir = "from-toml"\nprocess_timeout_seconds = 11\n',
        encoding="utf-8",
    )
    dotenv_path.write_text(
        "SOURCETH_OUTPUT_DIR=from-dotenv\nSOURCETH_PROCESS_TIMEOUT_SECONDS=12\n",
        encoding="utf-8",
    )

    toml_only = load_config(environ={}, dotenv_path=None, config_path=config_path)
    dotenv = load_config(environ={}, dotenv_path=dotenv_path, config_path=config_path)
    environment = load_config(
        environ={
            "SOURCETH_OUTPUT_DIR": "from-environment",
            "SOURCETH_PROCESS_TIMEOUT_SECONDS": "13",
        },
        dotenv_path=dotenv_path,
        config_path=config_path,
    )
    cli = load_config(
        ConfigOverrides(output_dir="from-cli", process_timeout_seconds=14),
        environ={
            "SOURCETH_OUTPUT_DIR": "from-environment",
            "SOURCETH_PROCESS_TIMEOUT_SECONDS": "13",
        },
        dotenv_path=dotenv_path,
        config_path=config_path,
    )

    assert (toml_only.output_dir, toml_only.process_timeout_seconds) == (Path("from-toml"), 11)
    assert (dotenv.output_dir, dotenv.process_timeout_seconds) == (Path("from-dotenv"), 12)
    assert (environment.output_dir, environment.process_timeout_seconds) == (
        Path("from-environment"),
        13,
    )
    assert (cli.output_dir, cli.process_timeout_seconds) == (Path("from-cli"), 14)


def test_credentials_are_loaded_from_named_environment_without_repr_leak() -> None:
    rpc_secret = "https://rpc.invalid/private-path?token=very-secret"
    api_secret = "api-super-secret"
    environment = {
        "SOURCETH_RPC_URL_ENV": "CUSTOM_RPC",
        "SOURCETH_API_KEY_ENV": "CUSTOM_API",
        "CUSTOM_RPC": rpc_secret,
        "CUSTOM_API": api_secret,
    }

    config = load_config(environ=environment, dotenv_path=None)

    assert config.credentials.rpc_url is not None
    assert config.credentials.api_key is not None
    assert config.credentials.rpc_url.reveal() == rpc_secret
    assert config.credentials.api_key.reveal() == api_secret
    combined_repr = repr(config) + repr(config.credentials) + str(config.credentials.rpc_url)
    assert rpc_secret not in combined_repr
    assert api_secret not in combined_repr
    assert "[REDACTED]" in combined_repr


def test_dotenv_values_do_not_interpolate_other_variables(tmp_path: Path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(
        "ETHERSCAN_API_KEY=$SHOULD_NOT_EXPAND\nETH_RPC_URL=https://rpc.invalid/$TOKEN\n",
        encoding="utf-8",
    )

    config = load_config(
        environ={"SHOULD_NOT_EXPAND": "leaked", "TOKEN": "leaked"},
        dotenv_path=dotenv_path,
    )

    assert config.credentials.api_key is not None
    assert config.credentials.rpc_url is not None
    assert config.credentials.api_key.reveal() == "$SHOULD_NOT_EXPAND"
    assert config.credentials.rpc_url.reveal() == "https://rpc.invalid/$TOKEN"


def test_process_environment_secret_overrides_dotenv_secret(tmp_path: Path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("ETHERSCAN_API_KEY=dotenv-secret\n", encoding="utf-8")

    config = load_config(
        environ={"ETHERSCAN_API_KEY": "process-secret"},
        dotenv_path=dotenv_path,
    )

    assert config.credentials.api_key is not None
    assert config.credentials.api_key.reveal() == "process-secret"
    assert "dotenv-secret" not in repr(config)
    assert "process-secret" not in repr(config)


def test_load_config_does_not_mutate_supplied_or_process_environment() -> None:
    supplied = {"ETHERSCAN_API_KEY": "secret"}
    before_process = dict(os.environ)
    before_supplied = dict(supplied)

    load_config(environ=supplied, dotenv_path=None)

    assert supplied == before_supplied
    assert dict(os.environ) == before_process


def test_custom_network_is_explicitly_registered(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
chain_id = 11155111

[networks.11155111]
name = "sepolia"
provider = "etherscan"
explorer_api_url = "https://api.etherscan.io/v2/api"
explorer_url = "https://sepolia.etherscan.io"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(environ={}, dotenv_path=None, config_path=config_path)

    assert config.chain_id == 11155111
    assert config.network.name == "sepolia"
    assert config.network.provider == "etherscan"
    assert config.network.explorer_api_url == "https://api.etherscan.io/v2/api"
    assert config.network.explorer_url == "https://sepolia.etherscan.io"


@pytest.mark.parametrize(
    "network_body",
    [
        'name = "missing-endpoints"\nprovider = "etherscan"',
        (
            'name = "unsafe"\nprovider = "etherscan"\n'
            'explorer_api_url = "http://api.example.invalid"\n'
            'explorer_url = "https://example.invalid"'
        ),
        (
            'name = "credentials"\nprovider = "etherscan"\n'
            'explorer_api_url = "https://user:pass@example.invalid/api"\n'
            'explorer_url = "https://example.invalid"'
        ),
    ],
)
def test_custom_network_requires_explicit_safe_explorer_urls(
    tmp_path: Path,
    network_body: str,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"chain_id = 5\n\n[networks.5]\n{network_body}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError):
        load_config(environ={}, dotenv_path=None, config_path=config_path)


@pytest.mark.parametrize(
    "url",
    [
        "https://.",
        "https://bad..example.invalid/api",
        "https://-bad.example.invalid/api",
        "https://bad-.example.invalid/api",
        "https://999.999.999.999/api",
        "https://[fe80::1%25zone]/api",
    ],
)
def test_network_endpoints_reject_malformed_hostnames(url: str) -> None:
    with pytest.raises(ConfigurationError):
        NetworkConfig(
            chain_id=5,
            name="test",
            provider="etherscan",
            explorer_api_url=url,
            explorer_url="https://example.invalid",
        )


@pytest.mark.parametrize(
    "payload",
    [
        'networks = "not-a-table"\n',
        '[networks.bad]\nname = "bad"\n',
        '[networks.5]\nunknown = "value"\n',
        "[networks.5]\nname = []\n",
    ],
)
def test_malformed_network_registry_is_rejected(tmp_path: Path, payload: str) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(payload, encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_config(environ={}, dotenv_path=None, config_path=config_path)


def test_unregistered_network_has_distinct_error() -> None:
    with pytest.raises(SourcethError) as raised:
        load_config(ConfigOverrides(chain_id=10), environ={}, dotenv_path=None)

    assert raised.value.code is ErrorCode.NETWORK_NOT_CONFIGURED


def test_unknown_toml_key_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("unexpected = true\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        load_config(environ={}, dotenv_path=None, config_path=config_path)

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION
    assert raised.value.details["keys"] == ["unexpected"]


@pytest.mark.parametrize(
    "overrides",
    [
        ConfigOverrides(chain_id=0),
        ConfigOverrides(process_timeout_seconds=0),
        ConfigOverrides(process_timeout_seconds=float("inf")),
        ConfigOverrides(process_timeout_seconds=float("nan")),
        ConfigOverrides(retry_max_attempts=0),
        ConfigOverrides(retry_base_delay_seconds=2, retry_max_delay_seconds=1),
        ConfigOverrides(retry_jitter_ratio=1.01),
        ConfigOverrides(max_files=0),
        ConfigOverrides(max_file_size_bytes=2, max_total_size_bytes=1),
        ConfigOverrides(proxy_max_depth=0),
        ConfigOverrides(rpc_url_env="BAD-NAME"),
    ],
)
def test_invalid_numeric_and_name_configuration_is_rejected(
    overrides: ConfigOverrides,
) -> None:
    with pytest.raises(ConfigurationError) as raised:
        load_config(overrides, environ={}, dotenv_path=None)

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION


@pytest.mark.parametrize(
    "overrides",
    [
        ConfigOverrides(retry_max_attempts=cast(int, True)),
        ConfigOverrides(process_timeout_seconds=cast(float, True)),
        ConfigOverrides(max_files=cast(int, 1.5)),
    ],
)
def test_runtime_type_confusion_in_overrides_is_rejected(overrides: ConfigOverrides) -> None:
    with pytest.raises(ConfigurationError):
        load_config(overrides, environ={}, dotenv_path=None)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SOURCETH_CHAIN_ID", "0x1"),
        ("SOURCETH_MAX_FILES", "one"),
        ("SOURCETH_PROCESS_TIMEOUT_SECONDS", "never"),
        ("SOURCETH_RETRY_JITTER_RATIO", "nan"),
    ],
)
def test_invalid_environment_configuration_is_rejected(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError):
        load_config(environ={name: value}, dotenv_path=None)


def test_explicit_missing_or_invalid_config_file_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "missing.toml"

    with pytest.raises(ConfigurationError):
        load_config(environ={}, dotenv_path=None, config_path=missing)

    invalid = tmp_path / "invalid.toml"
    invalid.write_text("not = [valid", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(environ={}, dotenv_path=None, config_path=invalid)


def test_dotenv_inside_output_directory_is_rejected(tmp_path: Path) -> None:
    output = tmp_path / "downloads"
    output.mkdir()
    dotenv_path = output / ".env"
    dotenv_path.write_text("ETHERSCAN_API_KEY=secret\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as raised:
        load_config(
            ConfigOverrides(output_dir=output),
            environ={},
            dotenv_path=dotenv_path,
        )

    assert "secret" not in str(raised.value)


def test_default_dotenv_inside_a_previous_download_is_rejected_before_merge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "0x" + ("a" * 40)
    sources = (
        tmp_path.parent
        / "cfg-dl"
        / "1"
        / address
        / "Runs"
        / "old-run"
        / "Contracts"
        / address
        / "Sources"
    )
    sources.mkdir(parents=True)
    (sources / ".env").write_text(
        "SOURCETH_OUTPUT_DIR=elsewhere\nSOURCETH_API_KEY_ENV=HOST_SECRET\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(sources)
    monkeypatch.setattr(
        "sourceth.config.dotenv_values",
        lambda **_kwargs: pytest.fail("el .env descargado no debe llegar a parsearse"),
    )

    with pytest.raises(ConfigurationError) as raised:
        load_config(
            environ={"HOST_SECRET": "must-not-be-selected"},
            config_path=None,
        )

    assert raised.value.code is ErrorCode.INVALID_CONFIGURATION
    assert "fuentes descargadas" in raised.value.message
    assert "must-not-be-selected" not in str(raised.value.to_dict())


def test_dotenv_directory_is_rejected(tmp_path: Path) -> None:
    dotenv_directory = tmp_path / ".env"
    dotenv_directory.mkdir()

    with pytest.raises(ConfigurationError):
        load_config(environ={}, dotenv_path=dotenv_directory)


def test_missing_default_dotenv_is_optional(tmp_path: Path) -> None:
    config = load_config(environ={}, dotenv_path=tmp_path / "missing.env")

    assert config.dotenv_path is None


def test_blank_credentials_are_treated_as_absent() -> None:
    config = load_config(
        environ={"ETH_RPC_URL": "   ", "ETHERSCAN_API_KEY": ""},
        dotenv_path=None,
    )

    assert config.credentials.rpc_url is None
    assert config.credentials.api_key is None


def test_loaded_paths_are_resolved(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    dotenv_path = tmp_path / ".env"
    config_path.write_text("chain_id = 1\n", encoding="utf-8")
    dotenv_path.write_text("# empty\n", encoding="utf-8")

    config = load_config(environ={}, dotenv_path=dotenv_path, config_path=config_path)

    assert config.config_path == config_path.resolve()
    assert config.dotenv_path == dotenv_path.resolve()


def test_secret_value_requires_nonempty_value_and_only_reveals_explicitly() -> None:
    with pytest.raises(ValueError):
        SecretValue("")

    secret = SecretValue("sensitive")
    assert bool(secret)
    assert str(secret) == "[REDACTED]"
    assert "sensitive" not in repr(secret)
    assert secret.reveal() == "sensitive"
