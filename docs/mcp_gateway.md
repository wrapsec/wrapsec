# WrapSec MCP Gateway

Version: 1.0
Transport: stdio
Module: `python -m mcp_gateway`

The MCP gateway sits between an agent and the MCP servers it uses. The agent
connects to the gateway instead of connecting to each server directly; the
gateway connects onward to the servers, and inspects what crosses in both
directions.

---

## Scope

**This is a security sidecar, not a general MCP hosting or remote-transport
platform.** It exists to inspect one agent's tool traffic. It does not host
servers for other clients, does not expose a network listener, does not
multiplex connections, and does not offer a remote transport. A deployment that
needs those things needs a different component.

**Native provider function calling is outside this version.** When an agent
calls tools through a model provider's own function-calling interface rather
than through MCP, that traffic never reaches this gateway. Scanning it is a
separate integration, through the scan API or the SDK helpers described in
`docs/api.md`.

---

## Architecture

```
   agent (MCP client)
        |  stdio: one client, one gateway process
        v
   +-------------------------------------------------+
   |  gateway                                         |
   |                                                  |
   |   routing table      exposed name -> server      |
   |   interceptors       definitions / calls / results
   |   scanner  ----------------------------------------> WrapSec scan API
   |                                                  |    (fail closed)
   +-------------------------------------------------+
        |            |            |
        v            v            v
   downstream    downstream   downstream      each spawned as a child
    server A      server B     server C       process, stdio, at startup
```

Four properties shape everything else:

- **One client per gateway process.** The stdio transport claims the process's
  own standard input and output, so a second concurrent connection is not
  possible. Two agents mean two gateway processes, each with its own downstream
  child processes and its own correlation identifiers. Isolation between agents
  comes from the runtime model, not from bookkeeping.
- **Downstream servers are children of the gateway.** They are spawned from the
  configuration at startup and live for the process lifetime. The gateway
  launches them; the agent never does.
- **The agent sees namespaced tool names.** A tool `read_file` on a server
  configured as `filesystem` is published as `filesystem__read_file`.
- **The namespaced name is never parsed.** It is built as a lookup key and
  resolved by exact match against a structured routing table. See "Name
  handling" below for why this matters.

### Module map

| Module | Responsibility |
|---|---|
| `mcp_gateway/__main__.py` | Entry point and startup ordering |
| `mcp_gateway/config.py` | Configuration parsing and validation |
| `mcp_gateway/session.py` | Downstream connections; refused ask channels |
| `mcp_gateway/routing.py` | Exposed name to server resolution |
| `mcp_gateway/proxy.py` | The MCP surface the agent talks to |
| `mcp_gateway/interceptors/` | The inspection at each boundary |
| `mcp_gateway/scanner.py` | The single path to the detection API |
| `mcp_gateway/decision.py` | How a refusal is delivered to an agent |
| `mcp_gateway/correlation.py` | Session, run, turn and trace identifiers |
| `mcp_gateway/mcp_compat.py` | The only module that touches the protocol SDK |

---

## Installation

The gateway runs from the source checkout. On the machine that will run it:

```bash
pip install -r requirements-mcp.txt   # protocol SDK (pinned) and PyYAML
pip install -e sdk/python/            # the client used to reach the scan API
```

It does not need the full application requirements: no web framework, no
database driver, no model runtime. It is a client of the WrapSec API over HTTP,
not a copy of it.

The protocol SDK is pinned exactly rather than floored. The gateway builds
against the low-level server API, parts of which the SDK marks provisional, and
an unbounded floor would let an enforcement dependency move under a green build.
Raising the pin is a deliberate compatibility change that must pass the gateway
test suite.

At startup the gateway probes the installed SDK for every API it depends on. A
missing or changed API is a refusal to start, not a warning: a gateway that runs
with an enforcement path quietly disabled is worse than one that will not run,
because the agent keeps working and nobody learns that enforcement stopped. A
version that differs from the verified pin but still exposes every API logs a
warning and starts.

---

## Configuration

The gateway reads one YAML file, named by `WRAPSEC_MCP_CONFIG`. There is no
default path and no default configuration: an unset variable is a startup
refusal, because a security component that guesses which servers to connect to
or what to permit is inventing the operator's intent.

```yaml
wrapsec:
  base_url: http://localhost:8000
  api_key_env: WRAPSEC_API_KEY
  timeout_s: 10

scan:
  mode: fast
  tool_definitions: true
  results: true
  call_arguments: true
  max_chars: 8000

servers:
  - name: filesystem
    command: ["python", "-m", "some_filesystem_server"]
    cwd: /srv/workspace
    env:
      ROOT: /srv/workspace
    tools:
      allow:
        - filesystem__read_file
        - filesystem__list_directory
  - name: tickets
    command: ["node", "/opt/tickets/server.js"]
    tools:
      deny:
        - tickets__delete_project
```

### `wrapsec`

| Key | Default | Meaning |
|---|---|---|
| `base_url` | required | Where the scan API is reachable |
| `api_key_env` | `WRAPSEC_API_KEY` | The **name of an environment variable** holding the API key |
| `timeout_s` | `10` | Per-scan HTTP timeout, in seconds |

`api_key_env` names a variable; it is not the key. The value is read at startup,
so a configuration file can be committed, shared or mounted without carrying a
credential. A value that looks like a pasted key is refused rather than used. An
unset variable is a startup refusal: the gateway will not scan unauthenticated.

Omitting the whole `wrapsec` section leaves the gateway with no detection
endpoint, which startup refuses outside development. It is not a way to turn
scanning off.

### `scan`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `fast` | Detection path. `fast` is the only accepted value in this version |
| `tool_definitions` | `true` | Inspect tool definitions before publishing them |
| `results` | `true` | Inspect tool results before returning them |
| `call_arguments` | `true` | Inspect call arguments before forwarding them |
| `max_chars` | `8000` | Bound past which content is blocked rather than scanned |

`mode: fast` runs the deterministic detection path: rules plus the always-on
classifier, no semantic model call. That is the path suited to a synchronous
tool-call loop, where every scan is latency the agent pays inline. Any other
value is refused rather than silently downgraded.

Switching an individual boundary off is permitted: an operator who has vetted a
server's tool definitions out of band may reasonably scan only results.
Switching **every** boundary off is refused outside development, because the
gateway would then hold an enforcing configuration, report itself as enforcing,
and inspect nothing.

### `servers`

Each entry describes one downstream server.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | The namespace prefix. Letters, digits, dot and dash, 1 to 64 characters |
| `command` | yes | A non-empty list of strings; argument vector, not a shell string |
| `transport` | no | `stdio` only; any other value is refused |
| `cwd` | no | Working directory for the child process |
| `env` | no | Environment mapping for the child process |
| `tools` | no | `allow` and `deny` lists |

Underscore is excluded from server names deliberately. The exposed name is
`<server>__<tool>`, and a prefix that could itself contain `__` would make that
string ambiguous to read. Routing never parses the exposed name, so this is
about the published name being honest, not about resolution depending on it.

`command` is an argument vector. It is passed to the process launcher directly,
with no shell, so shell metacharacters in it are not interpreted.

**`env` replaces the child's environment; it does not merge into it.** This has a
consequence worth knowing before deploying:

- **`env` omitted or empty:** the downstream server inherits the gateway's entire
  environment, **including the WrapSec API key** and anything else the gateway was
  started with.
- **`env` present and non-empty:** the child receives exactly that mapping and
  nothing else, so a server that needs `PATH` or `HOME` must be given them.

Set `env` explicitly for any downstream server you do not fully trust. A tool
server that can read the gateway's environment can read the credential the
gateway scans with.

Duplicate server names are refused: names are the routing namespace and two
servers under one name would produce colliding exposed names.

### Policy entries

Entries are namespaced as the agent sees them (`filesystem__read_file`). A bare
entry (`read_file`) is accepted only when exactly one server is configured,
which is the single case where it cannot be ambiguous. With two or more servers,
a bare entry is refused at startup rather than guessed: a permission that
silently matched a tool on another server would be a privilege bug wearing a
typo.

`deny` is evaluated first and is decisive. An omitted `allow` list is no
restriction; a **present** one is exhaustive, so anything not named is refused
and adding a tool downstream does not silently widen what an agent may call.
Matching is exact, with no prefix, substring or case-insensitive comparison.

### Unknown keys

An unrecognised key at any level is refused, at the top level, inside `wrapsec`,
inside `scan`, inside a server entry and inside `tools`. A configuration whose
keys are silently dropped is a configuration the operator believes is in force
and is not. The file is read with the safe YAML loader only.

---

## Running it

```bash
export WRAPSEC_MCP_CONFIG=/etc/wrapsec/mcp-gateway.yaml
export WRAPSEC_API_KEY=wsk_live_...
python -m mcp_gateway
```

The agent spawns that command and speaks MCP over its standard input and output.
Configure it in the agent's own MCP server list the way any stdio server is
configured: a command, arguments, and environment.

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `WRAPSEC_MCP_CONFIG` | none | Path to the configuration file. Unset is a refusal |
| `WRAPSEC_ENV` | `production` | `development` relaxes the enforcement requirement |
| The variable named by `api_key_env` | none | The API key. Unset is a refusal |

### Startup order

The order is a security property, not a convenience. Each step can refuse, and
nothing is served by a process that did not complete all of them:

1. verify the protocol SDK exposes every API the controls depend on;
2. load and validate the configuration;
3. require enforcement, unless `WRAPSEC_ENV=development`;
4. connect every downstream server and build the routing table;
5. serve.

A downstream server that cannot be started aborts startup rather than producing
a partial tool set, because an agent that silently loses a capability gives the
operator no signal beyond a missing tool.

Any refusal exits with status `2` and a message on standard error naming the
problem. Every diagnostic goes to standard error: standard output carries
protocol frames, and a log line written there would corrupt the stream.

### Tools that are not published

Two conditions cause a tool to be withheld at startup, both logged with the
reason:

- the composed name exceeds 128 characters, or contains characters outside
  `A-Za-z0-9._-`, or collides with a name another server already published. Such
  a tool is rejected rather than renamed, truncated or escaped: truncation
  manufactures collisions, and a reversible encoding over an unvalidated,
  attacker-influenceable string is a parser.
- a tool whose own name reads as another configured server's namespace, for
  example a server `evil` publishing a tool literally named
  `filesystem__read_file`. That composes to `evil__filesystem__read_file`, which
  routes correctly but misattributes the tool to anyone reading the list. This
  one refuses **startup** rather than skipping the tool, and it is not
  configurable: an opt-out is a setting an attacker would like enabled, and the
  condition it suppresses is one an operator cannot see by reading the tool list.

---

## Supported MCP operations

| Operation | Served | Notes |
|---|---|---|
| `tools/list` | yes | Every definition inspected before publication |
| `tools/call` | yes | Arguments inspected, result inspected |
| `ping` | yes | Registered by the SDK; carries no content |
| `server/discover` | yes | Registered by the SDK; returns protocol capabilities only, never tool definitions |
| `resources/*` | no | No handler registered |
| `prompts/*` | no | No handler registered |
| `completion/*` | no | No handler registered |
| `logging/*` | no | No handler registered |

Resources and prompts are not proxied. Each is another channel by which server
text reaches a model, and forwarding a channel that nothing inspects is not a
default this version takes. A request for a method with no
registered handler is answered `METHOD_NOT_FOUND` by the protocol runner; it is
not relayed downstream.

The two inspected methods are the ones registered by the gateway, and both pass
through the interceptor seam on every path. Capability discovery is derived from
what is registered and carries no downstream content, so it is not an inspection
bypass.

---

## Security controls

### 1. Tool-definition scanning

A tool definition is instructions the model reads and acts on. It arrives from a
server the gateway does not control, and the agent treats it as trusted context
simply because it came through the tool channel. That is the whole attack: text
placed in a description is read with the authority of the tool list, not with
the suspicion given to a document.

Every definition is scanned before it is published. What is sent to the detector
is the prose a model actually reads: the name, the title, the description, and
the human-readable strings inside the input schema, including `description` and
`title` at any nesting depth up to twelve levels. Schema structure such as
types, required lists and formats is not prose and is not sent. Parts are joined
with newlines, so an injection cannot be assembled across a boundary that did
not exist in the original.

A refused definition is **withheld entirely**, not published with a warning
attached. An agent that can see a blocked description has already read it.
Publishing it with the description stripped would still put an attacker-chosen
name into the context, and a placeholder would tell the agent a tool exists that
it cannot use. Nothing is said to the agent about why a tool is absent.

Definitions are classified as external content when scanned, so a deployment
running source-aware posture judges them more strictly than text a user typed.

### 2. Tool-definition change detection

Each judged definition is fingerprinted: a SHA-256 over its name, title,
description and full input schema, serialised with sorted keys so a server that
merely reorders its output does not read as a change. The schema is covered as
well as the prose, because a parameter that changes type, or a new required
field, changes what the tool does even when every description is identical.

- An **unchanged** definition keeps its earlier verdict without being rescanned.
  One withheld earlier stays withheld. Identical content cannot have a different
  verdict, and an agent that lists tools every turn would otherwise pay a scan
  per tool per turn in its own latency path.
- A **changed** definition is recorded as a change and then re-inspected. Change
  alone does not block: the record says the tool changed underneath an agent that
  had already been told what it does, and the block, if any, comes from what the
  new text says.

Fingerprints are per gateway process, which is per agent connection. They
describe what **this** agent was told and are not shared with a connection that
was told something else.

### 3. Tool-call validation

Two controls, in this order:

1. **Policy.** Is this tool permitted at all. Runs first because it is decisive
   and free: a denied tool never reaches the detector, the network, or the
   downstream server.
2. **Arguments.** Is what the agent is sending safe to send.

Which server's policy applies comes from the resolved route, not from reading
the exposed name apart.

### 4. Argument scanning

The whole arguments object is serialised and scanned as one unit. Arguments nest
arbitrarily, so picking out the strings at the top level would miss a payload one
level down, and picking them out recursively would still miss one placed in a
dictionary **key**. Serialising sends structure to the detector as well, which is
noise rather than signal, and that cost is accepted for coverage that has no gaps
to reason about.

Arguments are classified as user prompt when scanned, because they originate
with the agent acting for the user rather than with a downstream server.

A sanitize verdict on arguments is treated as allow. Rewriting what the agent
asked for would send the downstream server a call the agent did not make, and
the gateway cannot tell whether the redacted form still means what was intended.

When a call is allowed, it is invoked downstream under the tool's **original**
name. The namespace prefix never leaves the gateway process.

### 5. Tool-result scanning

The primary control. A tool result is content the agent asked for and will act
on, produced by a server the gateway does not control and shaped by whatever the
tool read: a file, a web page, a database row. Indirect prompt injection lives
here, as text that was never typed by the user arriving in the model's context
carrying the authority of "the tool said so".

Every readable part of a result is judged together as one block:

- text blocks;
- a resource link's name, title, description **and its URI**. The URI is not
  prose, but it is attacker-chosen and it is the payload in an exfiltration or
  phishing lure, so it is judged rather than passed as metadata;
- an embedded resource's text and URI;
- **structured content**, rendered exactly as the protocol renders it into the
  model-facing text block. A server is free to return the content blocks empty
  and put everything in the structured field, and scanning only the blocks would
  leave a one-step bypass.

Parts are joined with newlines, so a payload split across two blocks is caught
and one result costs one scan rather than one per block.

A blocked result is refused **whole**. The blocks arrived together from one call
the gateway has just judged malicious, and forwarding the image while refusing
the text hands the agent half an attacker-controlled payload. A sanitized result
is returned as a single text block carrying the redacted text; non-text blocks
go with the originals, because they were not judged and the result has already
been found to need redaction.

Results are classified as tool output when scanned.

### 6. Server-initiated ask channels

Two channels by which a downstream server can ask the agent's model to do
something. Both are refused, because this version does not inspect either one,
and forwarding would hand a downstream server a way to run inference on content
the gateway never scanned.

- **Legacy sampling.** The gateway supplies a callback that refuses, so the
  request is answered rather than served.
- **The modern replacement**, in which the same ask arrives inside a tool
  result. The SDK guard that rejects it is left at its secure default, and the
  resulting error is converted into a refusal.

On the current build the second channel is closed by construction as well: the
gateway's downstream connections negotiate protocol revision `2025-11-25`, and
that answer shape is only valid at `2026-07-28`. The guard is therefore defence
in depth rather than the control doing the work. A test pins the negotiated
revision, so an SDK that later negotiates higher fails the suite instead of
silently making the channel reachable.

Refusing an ask does not break the connection. The tool call that carried it
still completes.

### 7. The size bound

`max_chars` is a security limit, not a truncation instruction. Content over the
bound is **blocked**, not partially scanned. A verdict taken on the first N
characters does not cover what was sent and yet looks like one that does, which
is worse than no verdict.

### 8. Fail-closed behaviour

If the detection API is unreachable, times out, returns an error, or reports a
detector fault, the content has not been inspected. The gateway cannot tell a
clean payload from a hostile one at that point, so it refuses.

The consequence is worth stating plainly: **with the API down, the gateway
publishes no tools and forwards no results.** Availability is traded for the
guarantee that unjudged content never reaches the agent.

The record distinguishes the two cases. A block says the content was judged
dangerous; a failure says the control did not run. Both refuse, but only one is
evidence about the content, and the text the agent receives never reports a
judgement as an outage or an outage as a judgement.

### 9. Name handling

Downstream tool names are unconstrained by the protocol: the type is a bare
string with no pattern and no length limit, the SDK's charset rule is advisory
and is applied only to locally registered tools, and underscore is legal inside
a tool name so `__` can appear anywhere.

So a downstream server may publish `evil__tool`, `a/b c`, a 300-character name,
or a name that impersonates another configured server's namespace. The gateway
therefore **builds** a composed key and never **interprets** one. Routing is an
exact lookup in a structured map, with no prefix stripping, no nearest match and
no search across servers. A miss is a refusal, never an approximation.

A name crafted to resemble another namespace still resolves to the server that
published it. The startup shadowing check described above defends the tool list
a human or an agent **reads**, which is a separate concern from where a call
goes.

---

## What the agent sees when something is refused

A refusal comes back as a valid tool result with the error flag set, never as a
protocol fault. An agent that receives a transport error will often retry, and a
retry loop against a security control is indistinguishable from an attack on it.

```
[WrapSec] The content was refused by a security policy. Trace: mcp_<id>. Do not retry this operation.
```

Four rules govern that text:

- **Never echo the blocked content.** The refusal is delivered into the same
  context the content was going to reach, so quoting it to explain the block
  would complete the injection the block prevented.
- **Carry a trace identifier**, so an operator can find the decision behind a
  refusal without trusting the agent to report it.
- **Tell the agent not to retry.** A model that reads "blocked" without that
  instruction frequently tries a reworded call, which is exactly what an
  injection payload wants.
- **Say nothing about detector internals.** Scores, layer names and matched
  patterns are an oracle for tuning an evasion. They belong in the audit record.

The messages an agent can receive:

| Situation | Text |
|---|---|
| Content judged and refused | The content was refused by a security policy. |
| No route for the requested name | The requested tool is not available through this gateway. |
| Denied by policy | This tool is not permitted by security policy. |
| A refused ask channel | The tool attempted an operation this gateway does not support. |
| Downstream unreachable | The tool could not be reached. |
| Downstream response unreadable | The tool returned a response this gateway could not use. |
| A check could not run | The operation was refused because a security check could not run. |

Detector verdict names are deliberately not rendered, and the message is not
keyed on which detector fired: a per-detector message would let a prober learn
which class of payload trips the control.

A withheld **tool definition** produces no agent-facing message at all. The tool
is simply absent from the list.

---

## Audit and run correlation

Every scan the gateway issues is audited by the API like any other scan, and
carries four identifiers so one agent's activity can be reconstructed
afterwards.

| Identifier | Answers |
|---|---|
| `session_id` | Which agent connection was this |
| `run_id` | Which gateway execution was this |
| `turn_index` | Where in that run did it happen |
| `trace_id` | Which single security decision was it |

The gateway assigns all four rather than deriving them from protocol state. The
newest protocol revision has no session at all, so anything read from the
protocol would work on one connection and produce nothing on another.

Session and run are separate values even though they cover the same span on
stdio, where one client is one process. They mean different things to the
timeline that reads them, so if a later transport multiplexes connections the
existing records already say the right thing.

**A turn is one agent request, not one scan.** A single `tools/call` produces two
decisions, one on the arguments and one on the result, and both carry the same
turn index. A timeline can then read "turn 3: call to `files__read`, arguments
allowed, result blocked" instead of leaving an investigator to re-associate rows
by hand. Every definition judged while serving one `tools/list` likewise shares
one index.

The run is readable through `GET /v1/agent-runs/{run_id}`, documented in
`docs/api.md`, and rendered by the dashboard. The `run_id` and `session_id` for
a process are logged once at startup so an operator can find the run later.

These fields are correlation metadata only. Nothing is authorized on them, and
every value is minted inside the gateway process rather than accepted from
outside.

---

## Security model

**What the gateway assumes it can trust:** its own configuration file, the
environment it was started with, and the WrapSec API it authenticates to.

**What it treats as hostile:** everything a downstream server sends. Tool names,
titles, descriptions, input schemas, results, resource links and structured
content are all attacker-influenceable data. It also treats tool arguments as
content to be judged, because an agent under injection is an agent whose calls
were chosen by an attacker.

**What it defends:**

| Threat | Control |
|---|---|
| Malicious instructions in a tool description | Definitions scanned before publication; refused ones withheld |
| A tool that changes after the agent was told what it does | Fingerprint comparison per connection, recorded and re-inspected |
| Indirect prompt injection in tool output | Results scanned whole, including structured content and link URIs |
| A payload hidden in a nested argument or a dictionary key | Whole arguments object serialised and scanned |
| A server impersonating another server's namespace | Startup refusal; routing is exact lookup, never name parsing |
| Reaching a tool the operator did not permit | Deny list, then exhaustive allow list, exact match |
| A server asking the agent's model to run inference | Both ask channels refused |
| A detection outage silently disabling the control | Every failure is a block; startup refuses without enforcement |
| An oversized payload slipping past a partial scan | Content over the bound is blocked, not truncated |
| A downstream server reading the gateway's credential | Operator sets `env` per server; see the warning above |

**What it does not defend.** The gateway inspects content. It is not a network
control: a URL in an argument is scanned as text like anything else, and nothing
here decides where a downstream tool may connect. A tool can reach the network
without a URL ever passing through its arguments, so egress belongs at the
network boundary, and calling this an egress control would be false. A
downstream server is a child process with the environment and working directory
the configuration gave it, and with an omitted `env` that environment is the
gateway's own; process isolation, filesystem scope, credential scope and network
policy are the operator's job, not the gateway's.

---

## Limitations

Stated plainly, because a limit an operator does not know about is a limit they
cannot compensate for.

- **Binary payloads are not scanned.** Images, audio and blobs in a tool result
  are forwarded as they arrived. They are not judged, and that is a limit of
  this version rather than a statement that they are safe. Binary content inside
  a result that is blocked for other reasons is refused along with it.
- **Definition-change events are not yet in the server-side audit.** A change is
  logged and held in the process, but it is not persisted to the audit trail,
  so it does not survive the process and cannot be queried through the API.
- **One agent per process.** The stdio transport permits a single client, so
  concurrency means more gateway processes. There is no shared state between
  them, including the definition fingerprints.
- **Downstream connections negotiate protocol revision `2025-11-25`.** That is a
  property of the SDK rather than a choice expressed here, and it is pinned by a
  test so a change is visible.
- **No egress control.** See above.
- **Fast detection only.** The semantic detection path is not available to the
  gateway, because a synchronous tool-call loop cannot absorb its latency.
- **Availability follows the detection API.** Fail-closed means an API outage
  stops tool traffic rather than passing it uninspected.

---

## Verification

The gateway carries a unit suite under `tests/unit/mcp_gateway/`, run by
`make test`, and is inside the enforced type-check and coverage gates.

An acceptance harness under `tests/acceptance/mcp_gateway/` proves the whole
chain against a live API and a real database: an MCP client through the gateway
to a downstream server that returns a poisoned result, with the decision read
back from the run timeline. It needs a running stack and takes minutes rather
than seconds, so it is run deliberately rather than on every change. See the
README beside it.
