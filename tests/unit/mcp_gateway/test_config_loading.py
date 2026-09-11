# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Configuration is refused rather than repaired.

A gateway that invents a downstream server, a transport, or a permission is
guessing at the operator's intent, and every guess here is a security decision
made by accident. So each malformed shape below must fail startup with a message
that names the problem.
"""

from __future__ import annotations

import pytest

from mcp_gateway.config import ConfigError, load_config


def _write(tmp_path, text: str):
    path = tmp_path / "gateway.yaml"
    path.write_text(text, encoding="utf-8")
    return path


_VALID = """
servers:
  - name: filesystem
    transport: stdio
    command: [mcp-server-filesystem, /data]
    tools:
      allow: [filesystem__read_file]
      deny:  [filesystem__write_file]
"""


def test_a_valid_configuration_loads(tmp_path):
    config = load_config(_write(tmp_path, _VALID))

    server = config.servers[0]
    assert server.name        == "filesystem"
    assert server.command     == ("mcp-server-filesystem", "/data")
    assert server.tools.allow == ("filesystem__read_file",)
    assert server.tools.deny  == ("filesystem__write_file",)


# ---------------------------------------------------------------------------
# deserialization safety
# ---------------------------------------------------------------------------

def test_the_loader_does_not_construct_arbitrary_objects(tmp_path):
    """The full YAML loader can instantiate arbitrary Python types from a file.

    A security component handed a file path must not do that, so the safe loader
    is used. A tag that the unsafe loader would honour has to be an error here,
    not an object.
    """
    hostile = _write(tmp_path, "servers: !!python/object/apply:os.system ['echo pwned']\n")

    with pytest.raises(ConfigError, match="not valid YAML|must define"):
        load_config(hostile)


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------

def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "absent.yaml")


def test_malformed_yaml_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(_write(tmp_path, "servers: [unclosed\n"))


def test_an_empty_file_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="is empty"):
        load_config(_write(tmp_path, "\n"))


def test_a_non_mapping_root_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_config(_write(tmp_path, "- just\n- a list\n"))


def test_an_unknown_top_level_key_is_refused_not_ignored(tmp_path):
    """A silently dropped section is a configuration the operator believes is in
    force and is not."""
    with pytest.raises(ConfigError, match="unsupported top-level key"):
        load_config(_write(tmp_path, _VALID + "\nscanning:\n  mode: fast\n"))


def test_a_missing_servers_list_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="non-empty 'servers'"):
        load_config(_write(tmp_path, "servers: []\n"))


def test_an_unsupported_transport_is_refused(tmp_path):
    """V1 serves stdio. A config asking for another transport is refused rather
    than quietly served over stdio."""
    text = _VALID.replace("transport: stdio", "transport: streamable-http")
    with pytest.raises(ConfigError, match="supports 'stdio' only"):
        load_config(_write(tmp_path, text))


@pytest.mark.parametrize("command", ["command: []", "command: not-a-list", 'command: ["", "x"]'])
def test_a_bad_command_is_refused(tmp_path, command):
    text = _VALID.replace("command: [mcp-server-filesystem, /data]", command)
    with pytest.raises(ConfigError, match="'command' list"):
        load_config(_write(tmp_path, text))


def test_an_unknown_server_key_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="unsupported key"):
        load_config(_write(tmp_path, _VALID + "    shell: true\n"))


def test_a_bare_policy_entry_is_refused_with_two_servers(tmp_path):
    """The ambiguity rule holds when the config comes from a file, not only when
    the objects are built directly."""
    text = """
servers:
  - name: alpha
    command: [a]
    tools:
      allow: [read_file]
  - name: beta
    command: [b]
"""
    with pytest.raises(ConfigError, match="not namespaced|Use alpha__read_file"):
        load_config(_write(tmp_path, text))


def test_a_server_name_with_the_separator_is_refused(tmp_path):
    text = _VALID.replace("name: filesystem", "name: file__system")
    with pytest.raises(ConfigError, match="namespace prefix"):
        load_config(_write(tmp_path, text))


# ---------------------------------------------------------------------------
# the detection API and scan sections
# ---------------------------------------------------------------------------

_WITH_API = """
servers:
  - name: files
    command: [x]
wrapsec:
  base_url: http://localhost:8000
  api_key_env: MY_KEY_VAR
  timeout_s: 5
scan:
  mode: fast
  tool_definitions: true
  max_chars: 4000
"""


def test_the_api_and_scan_sections_load(tmp_path):
    config = load_config(_write(tmp_path, _WITH_API))

    assert config.wrapsec is not None
    assert config.wrapsec.base_url    == "http://localhost:8000"
    assert config.wrapsec.api_key_env == "MY_KEY_VAR"
    assert config.wrapsec.timeout_s   == 5
    assert config.scan.max_chars      == 4000
    assert config.scan.tool_definitions is True


def test_the_sections_are_optional_and_default_sensibly(tmp_path):
    """Absent 'wrapsec' leaves the gateway with nowhere to scan, which startup
    refuses -- it does not silently mean 'scanning off'."""
    config = load_config(_write(tmp_path, "servers:\n  - name: a\n    command: [x]\n"))

    assert config.wrapsec is None
    assert config.scan.mode      == "fast"
    assert config.scan.max_chars == 8000


@pytest.mark.parametrize("bad,match", [
    ("wrapsec:\n  base_url: ''\n",                      "base_url"),
    ("wrapsec:\n  base_url: http://x\n  timeout_s: 0\n", "timeout_s must be positive"),
    ("wrapsec:\n  base_url: http://x\n  timeout_s: x\n", "integer number of seconds"),
    ("wrapsec:\n  base_url: http://x\n  nope: 1\n",      "unsupported key"),
    ("wrapsec: not-a-mapping\n",                         "must be a mapping"),
])
def test_a_bad_api_section_is_refused(tmp_path, bad, match):
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path, "servers:\n  - name: a\n    command: [x]\n" + bad))


@pytest.mark.parametrize("bad,match", [
    ("scan:\n  mode: full\n",             "fast detection path"),
    ("scan:\n  max_chars: 0\n",           "max_chars must be positive"),
    ("scan:\n  max_chars: nope\n",        "max_chars must be an integer"),
    ("scan:\n  tool_definitions: maybe\n", "must be true or false"),
    ("scan:\n  unknown: 1\n",             "unsupported key"),
    ("scan: not-a-mapping\n",             "must be a mapping"),
])
def test_a_bad_scan_section_is_refused(tmp_path, bad, match):
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path, "servers:\n  - name: a\n    command: [x]\n" + bad))


def test_a_bad_env_mapping_is_refused(tmp_path):
    text = "servers:\n  - name: a\n    command: [x]\n    env:\n      KEY: 5\n"
    with pytest.raises(ConfigError, match="'env' must be a mapping"):
        load_config(_write(tmp_path, text))


def test_a_bad_cwd_is_refused(tmp_path):
    text = "servers:\n  - name: a\n    command: [x]\n    cwd: 5\n"
    with pytest.raises(ConfigError, match="'cwd' must be a string"):
        load_config(_write(tmp_path, text))


def test_a_bad_tools_section_is_refused(tmp_path):
    text = "servers:\n  - name: a\n    command: [x]\n    tools: nope\n"
    with pytest.raises(ConfigError, match="'tools' must be a mapping"):
        load_config(_write(tmp_path, text))


def test_an_unknown_tools_key_is_refused(tmp_path):
    text = "servers:\n  - name: a\n    command: [x]\n    tools:\n      maybe: [x]\n"
    with pytest.raises(ConfigError, match="'tools' has unsupported key"):
        load_config(_write(tmp_path, text))


def test_a_non_string_policy_entry_is_refused(tmp_path):
    text = "servers:\n  - name: a\n    command: [x]\n    tools:\n      allow: [5]\n"
    with pytest.raises(ConfigError, match="must be a list of non-empty strings"):
        load_config(_write(tmp_path, text))


def test_a_non_mapping_server_entry_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_config(_write(tmp_path, "servers:\n  - just-a-string\n"))
