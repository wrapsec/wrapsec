# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Gateway configuration, and the validation that makes routing unambiguous.

No security decision is hidden in here. Configuration parsing DOES enforce the
invariants routing depends on, and it does so by REFUSING a bad configuration
rather than by repairing one: a silently corrected server name is a routing
surprise waiting to happen.

FILE FORMAT. YAML, read with the safe loader only. Just enough of the file is
understood to connect downstream servers and apply their tool policy; an
unrecognised section is refused rather than ignored, so a later phase adding its
own section is a deliberate change here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Configured server names are the namespace prefix, so they are held to a
# stricter charset than tool names are.
#
# UNDERSCORE IS EXCLUDED deliberately. The exposed name is
# `<server>__<tool>`, and a prefix that could itself contain `__` would make
# that string ambiguous to read. Routing never parses the exposed name (see
# routing.py), so this is about the name being HONEST rather than about
# resolution depending on it.
#
# Dot and dash are allowed because a server name is often a hostname-ish label.
_SERVER_NAME = re.compile(r"^[A-Za-z0-9.-]{1,64}$")

# The separator between the configured server name and the downstream tool name.
NAMESPACE_SEPARATOR = "__"

# SEP-986 bounds the composed name. The MCP package does not ENFORCE this on
# names it receives, but a name the gateway PUBLISHES should conform.
MAX_TOOL_NAME_LENGTH = 128


class ConfigError(ValueError):
    """The configuration cannot be used as written."""


@dataclass(frozen=True)
class ToolPolicy:
    """Allow/deny for one downstream server.

    Entries are namespaced (`filesystem__read_file`). A bare entry is accepted
    only when exactly one server is configured, which is the single case where it
    cannot be ambiguous; see `validate_against`.
    """

    allow: tuple[str, ...] = ()
    deny:  tuple[str, ...] = ()


@dataclass(frozen=True)
class ServerConfig:
    """One downstream MCP server, as the operator declared it."""

    name:    str
    command: tuple[str, ...]
    env:     dict[str, str] = field(default_factory=dict)
    cwd:     str | None     = None
    tools:   ToolPolicy     = field(default_factory=ToolPolicy)

    def __post_init__(self) -> None:
        if not _SERVER_NAME.match(self.name):
            raise ConfigError(
                f"server name {self.name!r} is not usable as a namespace prefix. "
                f"Allowed: letters, digits, dot and dash, 1-64 characters. "
                f"Underscore is excluded because {NAMESPACE_SEPARATOR!r} separates "
                f"the prefix from the tool name."
            )
        if not self.command:
            raise ConfigError(f"server {self.name!r} has no command to launch")


@dataclass(frozen=True)
class WrapSecConfig:
    """How to reach the detection API.

    The credential is NOT here. `api_key_env` names an environment variable, so
    a configuration file can be committed, shared, or mounted without carrying a
    key. Reading the value is deferred until startup, where an unset variable is
    a refusal rather than an anonymous scan.
    """

    base_url:    str
    api_key_env: str = "WRAPSEC_API_KEY"
    timeout_s:   int = 10

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ConfigError("wrapsec.base_url is required")
        if not self.api_key_env:
            raise ConfigError("wrapsec.api_key_env must name an environment variable")
        if self.timeout_s <= 0:
            raise ConfigError(f"wrapsec.timeout_s must be positive, got {self.timeout_s}")


@dataclass(frozen=True)
class ScanConfig:
    """What is inspected, and the bound past which content is refused.

    `max_chars` is a SECURITY LIMIT, not a truncation instruction: content over
    it is blocked rather than partially scanned, because a verdict taken on the
    first N characters does not cover what was sent and yet looks like one that
    does.
    """

    mode:             str  = "fast"
    tool_definitions: bool = True
    results:          bool = True
    call_arguments:   bool = True
    max_chars:        int  = 8000

    def __post_init__(self) -> None:
        if self.mode != "fast":
            raise ConfigError(
                f"scan.mode {self.mode!r} is not available; this build runs the "
                f"fast detection path, which is the one suited to a synchronous "
                f"tool-call loop"
            )
        if self.max_chars <= 0:
            raise ConfigError(f"scan.max_chars must be positive, got {self.max_chars}")

    @property
    def inspects_anything(self) -> bool:
        """Whether any boundary is actually examined.

        A configuration with every switch off is the security-disabled mode
        under another name: the gateway would hold an enforcing interceptor,
        report itself as enforcing, and inspect nothing.
        """
        return bool(self.tool_definitions or self.results or self.call_arguments)

    def describe(self) -> str:
        """The effective posture, for the startup record.

        Derived from the resolved configuration rather than from the file, so it
        reflects what is in force including defaults the file never mentioned. An
        operator should be able to read what is enforced, not infer it from what
        was omitted.
        """
        inspected = [
            name for name, on in (
                ("tool-definitions", self.tool_definitions),
                ("tool-results",     self.results),
                ("call-arguments",   self.call_arguments),
            ) if on
        ]
        return (
            f"mode={self.mode} "
            f"inspecting={','.join(inspected) if inspected else 'NOTHING'} "
            f"max_chars={self.max_chars}"
        )


@dataclass(frozen=True)
class GatewayConfig:
    """The whole gateway configuration."""

    servers:  tuple[ServerConfig, ...]
    wrapsec:  WrapSecConfig | None = None
    scan:     ScanConfig = field(default_factory=ScanConfig)

    def __post_init__(self) -> None:
        if not self.servers:
            raise ConfigError("no downstream MCP servers are configured")

        seen: set[str] = set()
        for server in self.servers:
            if server.name in seen:
                # Two servers under one name would produce colliding exposed
                # names for every tool they share. Caught here, at startup,
                # rather than as a routing surprise later.
                raise ConfigError(
                    f"server name {server.name!r} is configured more than once; "
                    f"names are the routing namespace and must be unique"
                )
            seen.add(server.name)

        self.validate_against()

    def validate_against(self) -> None:
        """Reject a policy entry that cannot be resolved unambiguously."""
        single = len(self.servers) == 1
        for server in self.servers:
            for kind, entries in (("allow", server.tools.allow), ("deny", server.tools.deny)):
                for entry in entries:
                    if NAMESPACE_SEPARATOR in entry:
                        continue
                    if single:
                        # Unambiguous: there is only one server it could name.
                        continue
                    raise ConfigError(
                        f"{kind} entry {entry!r} on server {server.name!r} is not "
                        f"namespaced, and {len(self.servers)} servers are configured. "
                        f"Use {server.name}{NAMESPACE_SEPARATOR}{entry}. A bare name is "
                        f"refused rather than guessed: a permission that silently "
                        f"matched a tool on another server would be a privilege bug "
                        f"wearing a typo."
                    )

    def by_name(self, name: str) -> ServerConfig | None:
        for server in self.servers:
            if server.name == name:
                return server
        return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
#
# Only the sections Phase 1 needs are accepted. An unknown top-level key is
# REFUSED rather than ignored: a configuration whose keys are silently dropped is
# a configuration the operator believes is in force and is not. Later phases add
# their own sections to `_KNOWN_TOP_LEVEL` as they land.
_KNOWN_TOP_LEVEL = frozenset({"servers", "wrapsec", "scan"})

# V1 ships stdio only. A config naming another transport is refused rather than
# quietly served over stdio: the operator asked for something this build does not
# do, and guessing which half of that request to honour is not safe.
_SUPPORTED_TRANSPORT = "stdio"


def load_config(path: str | Path) -> GatewayConfig:
    """Read and validate the gateway configuration file.

    Every failure is a startup refusal with a message naming the file and the
    problem. There are no defaults for downstream servers, policy or
    credentials: a security gateway that invents what to connect to, or what to
    permit, is guessing at the operator's intent.
    """
    import yaml  # declared in requirements-mcp.txt

    file = Path(path)
    try:
        raw = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {str(file)!r}: {exc}") from exc

    try:
        # safe_load only. The full loader can construct arbitrary objects, and a
        # security component must not do that with a file path it was handed.
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"configuration {str(file)!r} is not valid YAML: {exc}") from exc

    if parsed is None:
        raise ConfigError(f"configuration {str(file)!r} is empty")
    if not isinstance(parsed, dict):
        raise ConfigError(
            f"configuration {str(file)!r} must be a mapping, got {type(parsed).__name__}"
        )

    unknown = sorted(set(parsed) - _KNOWN_TOP_LEVEL)
    if unknown:
        raise ConfigError(
            f"configuration {str(file)!r} has unsupported top-level key(s): "
            f"{', '.join(unknown)}. Supported: {', '.join(sorted(_KNOWN_TOP_LEVEL))}."
        )

    servers_raw = parsed.get("servers")
    if not isinstance(servers_raw, list) or not servers_raw:
        raise ConfigError(
            f"configuration {str(file)!r} must define a non-empty 'servers' list"
        )

    return GatewayConfig(
        servers = tuple(
            _server_from(entry, index, file) for index, entry in enumerate(servers_raw)
        ),
        wrapsec = _wrapsec_from(parsed.get("wrapsec"), file),
        scan    = _scan_from(parsed.get("scan"), file),
    )


def _wrapsec_from(raw: object, file: Path) -> WrapSecConfig | None:
    """The detection API section. Absent means the gateway has nowhere to scan,
    which startup refuses rather than treating as 'scanning off'."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError(f"'wrapsec' in {str(file)!r} must be a mapping")

    unknown = sorted(set(raw) - {"base_url", "api_key_env", "timeout_s"})
    if unknown:
        raise ConfigError(f"'wrapsec' has unsupported key(s): {', '.join(unknown)}")

    base_url = raw.get("base_url")
    if not isinstance(base_url, str) or not base_url:
        raise ConfigError("wrapsec.base_url must be a non-empty string")

    api_key_env = raw.get("api_key_env", "WRAPSEC_API_KEY")
    if not isinstance(api_key_env, str) or not api_key_env:
        raise ConfigError("wrapsec.api_key_env must be a non-empty string")
    if api_key_env.lower().startswith(("wsk_", "sk-")):
        # A key pasted where a variable NAME belongs. Refused rather than used,
        # because the alternative is a credential living in a config file.
        raise ConfigError(
            "wrapsec.api_key_env names an ENVIRONMENT VARIABLE, not a key; it "
            "looks like a credential was pasted here"
        )

    timeout = raw.get("timeout_s", 10)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ConfigError("wrapsec.timeout_s must be an integer number of seconds")

    return WrapSecConfig(base_url=base_url, api_key_env=api_key_env, timeout_s=timeout)


def _scan_from(raw: object, file: Path) -> ScanConfig:
    if raw is None:
        return ScanConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"'scan' in {str(file)!r} must be a mapping")

    unknown = sorted(set(raw) - {"mode", "tool_definitions", "results",
                                "call_arguments", "max_chars"})
    if unknown:
        raise ConfigError(f"'scan' has unsupported key(s): {', '.join(unknown)}")

    mode = raw.get("mode", "fast")
    if not isinstance(mode, str):
        raise ConfigError("scan.mode must be a string")

    definitions = raw.get("tool_definitions", True)
    if not isinstance(definitions, bool):
        raise ConfigError("scan.tool_definitions must be true or false")

    results = raw.get("results", True)
    if not isinstance(results, bool):
        raise ConfigError("scan.results must be true or false")

    call_arguments = raw.get("call_arguments", True)
    if not isinstance(call_arguments, bool):
        raise ConfigError("scan.call_arguments must be true or false")

    max_chars = raw.get("max_chars", 8000)
    if not isinstance(max_chars, int) or isinstance(max_chars, bool):
        raise ConfigError("scan.max_chars must be an integer")

    return ScanConfig(mode=mode, tool_definitions=definitions, results=results,
                      call_arguments=call_arguments, max_chars=max_chars)


def _server_from(entry: object, index: int, file: Path) -> ServerConfig:
    """One `servers[]` element, strictly typed."""
    where = f"servers[{index}] in {str(file)!r}"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where} must be a mapping, got {type(entry).__name__}")

    allowed = {"name", "transport", "command", "env", "cwd", "tools"}
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise ConfigError(f"{where} has unsupported key(s): {', '.join(unknown)}")

    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{where} needs a non-empty string 'name'")

    transport = entry.get("transport", _SUPPORTED_TRANSPORT)
    if transport != _SUPPORTED_TRANSPORT:
        raise ConfigError(
            f"{where} requests transport {transport!r}; this build supports "
            f"{_SUPPORTED_TRANSPORT!r} only"
        )

    command = entry.get("command")
    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part for part in command
    ):
        raise ConfigError(
            f"{where} needs a non-empty 'command' list of strings"
        )

    env_raw = entry.get("env") or {}
    if not isinstance(env_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env_raw.items()
    ):
        raise ConfigError(f"{where} 'env' must be a mapping of string to string")

    cwd = entry.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise ConfigError(f"{where} 'cwd' must be a string")

    return ServerConfig(
        name    = name,
        command = tuple(command),
        env     = dict(env_raw),
        cwd     = cwd,
        tools   = _policy_from(entry.get("tools"), where),
    )


def _policy_from(raw: object, where: str) -> ToolPolicy:
    if raw is None:
        return ToolPolicy()
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} 'tools' must be a mapping")

    unknown = sorted(set(raw) - {"allow", "deny"})
    if unknown:
        raise ConfigError(f"{where} 'tools' has unsupported key(s): {', '.join(unknown)}")

    def _entries(key: str) -> tuple[str, ...]:
        value = raw.get(key)
        if value is None:
            return ()
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ConfigError(f"{where} 'tools.{key}' must be a list of non-empty strings")
        return tuple(value)

    return ToolPolicy(allow=_entries("allow"), deny=_entries("deny"))
