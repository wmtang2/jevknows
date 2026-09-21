# jevknows — Jev injection guard for coding agents

Screen the content a coding agent loads — web fetches, file reads — for
malicious, agent-directed instructions (prompt injection), and **stop the
load** when one is detected. Judgments are made by
[Jev](https://docs.typesafe.ai), TypeSafe's System One model, called through
the [TypeSafe Python SDK](https://docs.typesafe.ai/sdk/python.md): the model
returns typed probabilities, plain code enforces the policy.

Web pages and files can carry instructions aimed at the AI agent reading
them: "ignore all previous instructions", hidden directives to exfiltrate API
keys, payloads concealed in HTML comments and invisible characters. Keyword
filters miss these because the attack is semantic. Jev judges the meaning;
your code decides.

Ports:

| Agent | Coverage | Setup |
| --- | --- | --- |
| [ZCode](zcode/README.md) | Deterministic: every `WebFetch` and `Read` is intercepted before it runs | [zcode/README.md](zcode/README.md) |
| [OpenAI Codex CLI](codex/README.md) | Deterministic for shell commands (URL targets pre-judged before curl/wget runs) and MCP tools; advisory for hosted tools via AGENTS.md | [codex/README.md](codex/README.md) |
| [Any MCP client](mcp/README.md) — VS Code, Cursor, Claude Code/Desktop, ZCode, Codex, Gemini CLI, … | Advisory: guard exposed as MCP tools (`check_url`/`check_file`/`check_text`) plus an instructions policy; the agent's built-in tools are not interceptable | [mcp/README.md](mcp/README.md) |

The engine is one Python script; any agent with a pre-tool-use hook can run
it as-is.

## How it works

Where the agent has a pre-tool-use hook (ZCode, Codex), the hook runs the
guard **before** a load happens and denies the call on detection. Everywhere
else the same checks run as MCP tools the agent is instructed to call
first — a BLOCKED verdict replaces the content. The judgment flow is
identical:

```
load requested (WebFetch / Read / shell fetch / MCP read)
        │
        ▼
guard.py --hook          reads the content (file bytes or URL prefetch)
        │
        ▼
one Jev call             three Noul questions over the same state, in parallel
        │
   any signal ≥ threshold? ──yes──► hook denies ──► load is BLOCKED
        │no
        ▼
   hook exits 0 ──► the tool call proceeds as normal
```

The three judgments:

| Signal | Meaning |
| --- | --- |
| `agent_directive` | The content tries to instruct the agent processing it |
| `harmful_intent` | Those instructions push toward consequential or harmful actions (exfiltrate secrets, modify files, disable safety rules) |
| `concealed_directive` | Instructions hidden from human view but aimed at machines (invisible characters, comments, encoded payloads) |

**Policy — deny when ANY signal ≥ `JEV_GUARD_THRESHOLD` (default 0.80).**
The question wording distinguishes content that *instructs* the agent from
content that merely *discusses* injection (security articles, research, test
fixtures), which is the usual source of false positives.

Content larger than one chunk is screened in full: it is split into
**overlapping chunks** of `JEV_GUARD_MAX_CHARS` (2k overlap, so a payload
straddling a chunk boundary stays whole in the next chunk), every chunk is
judged, and any chunk over the threshold blocks the load. Reports include
chunk coverage — `10/14 chunks [PARTIAL coverage]` when the
`JEV_GUARD_MAX_CHUNKS` cap is hit.

Binary files are skipped without a judgment. Guard errors (missing API key,
network outage, timeout) **fail open** by default so a broken guard can never
brick your session — see [Configuration](#configuration) for fail-closed mode.

## Repository layout

```
jevknows/
├── README.md                        ← you are here (engine, results, config)
├── LICENSE                          (GPL-3.0)
├── zcode/                           ZCode port
│   ├── README.md                    setup: skill install + hook config
│   └── jev-injection-guard/         the skill directory
│       ├── SKILL.md                 agent-facing operational docs
│       ├── scripts/guard.py
│       └── tests/
├── codex/                           OpenAI Codex CLI port
│   ├── README.md                    setup: config.toml hook + AGENTS.md advisory
│   ├── scripts/guard.py
│   └── tests/
└── mcp/                             universal MCP port (any MCP client)
    ├── README.md                    setup for VS Code, Cursor, Claude, Codex, ZCode, …
    ├── scripts/
    │   ├── guard.py                 engine + manual CLI (same logic as other ports)
    │   └── mcp_server.py            MCP server: check_url / check_file / check_text
    └── tests/
        ├── mcp_smoke.py             end-to-end MCP client test
        ├── benign.md
        └── injected.md
```

## Requirements

- A supported coding agent (ZCode or Codex CLI for the hook ports; any
  MCP-capable client for the MCP port)
- Python 3.10+ (tested on 3.13)
- A TypeSafe API key (create one in the TypeSafe console)
- `typesafe-sdk` (plus `mcp` for the MCP port; installed into a local venv —
  see the port READMEs)

## Manual judging

All ports expose the same CLI, independent of any hook:

```bash
$GUARD --file <path>       # judge a file
$GUARD --url  <url>        # fetch and judge a web page
echo "<content>" | $GUARD --text
```

Manual mode prints a JSON report and exits `0` (clean), `2` (malicious
instruction detected), or `1` (guard error):

```json
{
  "source": {"tool": "manual", "path": "page.md"},
  "signals": {"agent_directive": 0.03, "harmful_intent": 0.01, "concealed_directive": 0.02},
  "threshold": 0.8,
  "decision": "allow",
  "reason": "no signal reached the threshold",
  "request_id": "req_..."
}
```

In hook mode stdout is always empty (hook runners parse stdout as strict
JSON); all logging goes to stderr.

## Tested against live content

Results from 2026-09-20 (model `jev-latest`), running `guard.py --url` plus
the full ZCode `PreToolUse` hook path against real URLs. Signals are the
three Noul probabilities (agent_directive / harmful_intent /
concealed_directive):

| URL | Content | agent / harmful / concealed | Decision |
| --- | --- | --- | --- |
| [`tests/injected.md` hosted on GitHub](https://raw.githubusercontent.com/wmtang2/jevknows/main/zcode/jev-injection-guard/tests/injected.md) | Deployed attack: exfiltration directive hidden in an HTML comment | 0.46 / **0.99** / **0.96** | **BLOCK** (hook exit 2) |
| [`garak` promptinject probe](https://raw.githubusercontent.com/NVIDIA/garak/main/garak/probes/promptinject.py) | Real attack strings stored as data in research code | 0.05 / 0.44 / 0.09 | allow |
| [`agentdojo` attack corpus](https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/attacks/important_instructions_attacks.py) | Live attacks from ETH Zurich's agent benchmark | 0.19 / 0.46 / 0.10 | allow |
| [gandalf.lakera.ai](https://gandalf.lakera.ai/) | Prompt injection game (client-rendered app shell) | 0.03 / 0.06 / 0.13 | allow |
| [example.com](https://example.com) | Benign control | 0.01 / 0.03 / 0.03 | allow |
| [this README](https://raw.githubusercontent.com/wmtang2/jevknows/main/README.md) | Describes injections without enacting them | 0.05 / 0.10 / 0.15 | allow |

Observations:

- The signal bands separate cleanly: benign content ≤ 0.15, research corpora
  0.44–0.46, deployed attack ≥ 0.96. The default threshold (0.80) sits inside
  that gap.
- The two corpora are **not** truncation false negatives (both files are under
  10 KB): Jev scores them as attack content *stored as data*, not instructions
  addressed at the agent reading them — the same discuss-vs-instruct
  distinction that keeps security writeups loadable. If you want research
  corpora flagged as well, `JEV_GUARD_THRESHOLD=0.4` catches both while every
  control above stays under 0.15.
- Gandalf is a client-rendered app: its instructions aren't in the
  server-rendered HTML, so there was nothing to detect in the fetched text.
- These are single-run snapshots — probabilities vary between runs and models.
  Treat them as indicative and re-run on your own traffic before trusting any
  threshold.

## Configuration

All via environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | — (required) | Jev access; without it the guard fails open |
| `JEV_GUARD_THRESHOLD` | `0.80` | Deny when any signal ≥ this, in any chunk |
| `JEV_GUARD_MAX_CHARS` | `60000` | Chunk size screened per Jev call |
| `JEV_GUARD_MAX_CHUNKS` | `10` | Max chunks screened per load (600 KB at defaults); beyond it coverage is partial |
| `JEV_GUARD_MAX_BYTES` | `10485760` | Raw read cap per load (10 MB) |
| `JEV_GUARD_FAIL_MODE` | `open` | `block` = deny loads when the guard errors |
| `JEV_GUARD_SKIP` | — | Comma-separated globs never judged (e.g. `**/tests/*,**/*.min.js`) |
| `JEV_GUARD_MOCK` | — | `clean`/`malicious` skips the API (wiring tests only) |

## Tuning and troubleshooting

- **Too many false positives** — raise `JEV_GUARD_THRESHOLD` (0.85–0.9), and
  run a manual judgment first to see which signal fires. Use `JEV_GUARD_SKIP`
  for paths that are noise by construction (minified bundles, fixtures).
- **Missed injection** — lower the threshold; check the manual report: if even
  `harmful_intent` is low, the content is probably genuinely benign.
- **Hook never runs** — each agent registers hooks differently (ZCode:
  `hooks.enabled: true` in `.zcode/config.json`; Codex: `[[hooks.PreToolUse]]`
  in `config.toml` plus a one-time trust review via `/hooks`). See the port
  READMEs, and check the agent's hook log for outcome and duration.
- **Everything is denied** — you set `JEV_GUARD_FAIL_MODE=block` without a
  working `TYPESAFE_API_KEY`. Unset it or fix the key.
- **Wire-testing** — `JEV_GUARD_MOCK=malicious` + hook JSON on stdin must
  exit 2; `JEV_GUARD_MOCK=clean` must exit 0. No API calls are made in mock
  mode.

## Limitations

- **A judgment is not a sandbox.** Signals are calibrated probabilities, not
  proof. Validate the guard on your own traffic, tune the threshold to your
  consequences, and treat the `request_id` as your audit handle.
- **Coverage is capped, not unbounded.** Large content is screened in
  overlapping chunks — every chunk must pass, so payloads cannot hide at
  chunk boundaries — up to `JEV_GUARD_MAX_CHUNKS` chunks (600 KB at
  defaults) and `JEV_GUARD_MAX_BYTES` raw (10 MB). Past those caps the
  remainder is unscreened and the guard says so (`PARTIAL coverage`).
  Chunking multiplies Jev calls for large content (one per ~60 KB); tune
  the caps to your budget.
- **Fail-open by default.** Availability is prioritized over enforcement; set
  `JEV_GUARD_FAIL_MODE=block` only once the key and network are dependable.
- **Port-specific gaps** — ZCode covers `WebFetch`/`Read` fully but not
  `Bash`/`Grep` output; Codex cannot intercept hosted tools or plain file
  reads (advisory AGENTS.md instead); MCP clients have no interception at
  all and are advisory by construction (guard tools + instructions policy).
  Details in each port's README.

## License

GPL-3.0 — see [LICENSE](LICENSE).
