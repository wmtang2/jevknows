# jevknows — Jev injection guard for ZCode

Screen every piece of content loaded into [ZCode](https://zcode.dev) — web
fetches, file reads — for malicious, agent-directed instructions
(prompt injection), and **stop the load** when one is detected. Judgments are
made by [Jev](https://docs.typesafe.ai), TypeSafe's System One model, called
through the [TypeSafe Python SDK](https://docs.typesafe.ai/sdk/python.md):
the model returns typed probabilities, your code decides.

Web pages and files can carry instructions aimed at the AI agent reading them:
"ignore all previous instructions", hidden directives to exfiltrate API keys,
or payloads concealed in HTML comments and invisible characters. Keyword
filters miss these because the attack is semantic. Jev judges the meaning;
plain Python enforces the policy.

## How it works

A ZCode `PreToolUse` hook runs the guard **before** every `WebFetch` and
`Read` in the workspace:

```
Read/WebFetch requested
        │
        ▼
guard.py --hook          reads the content (file bytes or URL prefetch)
        │
        ▼
one Jev call             three Noul questions over the same state, in parallel
        │
   any signal ≥ threshold? ──yes──► hook exits 2 ──► load is DENIED
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

Binary files are skipped without a judgment. Guard errors (missing API key,
network outage, timeout) **fail open** by default so a broken guard can never
brick your session — see [Configuration](#configuration) for fail-closed mode.

## Repository layout

```
jevknows/
├── README.md
├── LICENSE                          (GPL-3.0)
└── jev-injection-guard/             ← the skill directory
    ├── SKILL.md                     (skill definition; triggers on injection review/tuning)
    ├── scripts/
    │   └── guard.py                 (the guard: hook mode + manual CLI)
    └── tests/
        ├── benign.md                (clean fixture)
        └── injected.md              (simulated injection in an HTML comment)
```

## Requirements

- [ZCode](https://zcode.dev) with hook support (hooks in `.zcode/config.json`)
- Python 3.10+ (tested on 3.13)
- A TypeSafe API key (create one in the TypeSafe console)
- `typesafe-sdk` (installed into a local venv below)

## Setup

### 1. Get the skill

Either copy the skill directory into your workspace's skills folder:

```bash
# from a checkout of this repo
cp -r jev-injection-guard <your-workspace>/.agents/skills/
```

or let the skills CLI do it:

```bash
npx skills add wmtang2/jevknows --skill jev-injection-guard -y
```

### 2. Create a venv with the TypeSafe SDK

In the **workspace root** (the same directory ZCode opens — hooks resolve
paths against `${ZCODE_PROJECT_DIR}`):

```bash
python -m venv .venv
# Windows:
.venv/Scripts/python -m pip install typesafe-sdk
# Linux/macOS:
.venv/bin/python -m pip install typesafe-sdk
```

### 3. Set your API key

```bash
# Git Bash / Linux / macOS
export TYPESAFE_API_KEY="tsk_..."
# PowerShell (this session) / persistent
$env:TYPESAFE_API_KEY = "tsk_..."
setx TYPESAFE_API_KEY "tsk_..."
```

Without it the guard fails open (allows everything, logs a warning). Web apps
should keep the key server-side; never ship it to a browser.

### 4. Register the hook

Add a `hooks` block to `<workspace>/.zcode/config.json` (create the file if
it doesn't exist). Configuration-file hooks are disabled by default — the
`"enabled": true` line is what switches the runner on:

```json
{
  "hooks": {
    "enabled": true,
    "events": {
      "PreToolUse": [
        {
          "matcher": "WebFetch|Read",
          "hooks": [
            {
              "type": "process",
              "command": "${ZCODE_PROJECT_DIR}/.venv/Scripts/python.exe",
              "args": [
                "${ZCODE_PROJECT_DIR}/.agents/skills/jev-injection-guard/scripts/guard.py",
                "--hook"
              ],
              "timeoutMs": 60000,
              "statusMessage": "Jev injection guard: screening content before load"
            }
          ]
        }
      ]
    }
  }
}
```

On Linux/macOS change the command to `${ZCODE_PROJECT_DIR}/.venv/bin/python`.
If you installed the skill globally (`~/.agents/skills/`), hardcode that
absolute path instead — `${ZCODE_PROJECT_DIR}` only resolves workspace paths.

### 5. Restart ZCode and verify

Hook configuration is read at session start. In a new session, the hook log
should show the guard running on each `WebFetch`/`Read` (see
[Troubleshooting](#troubleshooting)).

## Test it

Wire-test without spending API tokens (`JEV_GUARD_MOCK` short-circuits Jev):

```bash
PY=.venv/Scripts/python            # .venv/bin/python on POSIX
GUARD=.agents/skills/jev-injection-guard/scripts/guard.py

# must exit 2 (deny):
echo '{"tool_name":"Read","tool_input":{"file_path":"anything.txt"},"cwd":"."}' \
  | JEV_GUARD_MOCK=malicious $PY $GUARD --hook
# must exit 0 (allow):
echo '{"tool_name":"Read","tool_input":{"file_path":"anything.txt"},"cwd":"."}' \
  | JEV_GUARD_MOCK=clean $PY $GUARD --hook
```

Then test live against the bundled fixtures — the injected fixture contains a
realistic "ignore previous instructions / exfiltrate SSH key" payload hidden
in an HTML comment:

```bash
$PY $GUARD --file jev-injection-guard/tests/injected.md   # decision: block
$PY $GUARD --file jev-injection-guard/tests/benign.md     # decision: allow
```

## Usage

Once the hook is registered, enforcement is automatic: every `WebFetch` and
`Read` in the workspace is screened, and malicious loads are denied with the
fired signals and a `request_id` in the ZCode log. Each screened load adds a
short Jev round-trip (typically 1–3 s).

You can also judge content manually — useful for `Bash`/`Grep` output, which
the hook cannot see (see [Limitations](#limitations)):

```bash
$PY $GUARD --file <path>       # judge a file
$PY $GUARD --url  <url>        # fetch and judge a web page
echo "<content>" | $PY $GUARD --text
```

Manual mode prints a JSON report:

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

Exit codes: `0` = clean, `2` = malicious instruction detected, `1` = guard
error. In hook mode stdout is always empty (the hook runner parses stdout as
strict JSON); all logging goes to stderr.

## Configuration

All via environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | — (required) | Jev access; without it the guard fails open |
| `JEV_GUARD_THRESHOLD` | `0.80` | Deny when any signal ≥ this |
| `JEV_GUARD_MAX_CHARS` | `60000` | Content sent to Jev is truncated here |
| `JEV_GUARD_FAIL_MODE` | `open` | `block` = deny loads when the guard errors |
| `JEV_GUARD_SKIP` | — | Comma-separated globs never judged (e.g. `**/tests/*,**/*.min.js`) |
| `JEV_GUARD_MOCK` | — | `clean`/`malicious` skips the API (wiring tests only) |

## Tuning and troubleshooting

- **Too many false positives** — raise `JEV_GUARD_THRESHOLD` (0.85–0.9), and
  run a manual judgment first to see which signal fires. Use `JEV_GUARD_SKIP`
  for paths that are noise by construction (minified bundles, fixtures).
- **Missed injection** — lower the threshold; check the manual report: if even
  `harmful_intent` is low, the content is probably genuinely benign.
- **Hook never runs** — configuration-file hooks need `"enabled": true` in the
  `hooks` block; verify the matcher case (`WebFetch|Read`, case-sensitive);
  check that the venv path exists. Hook runs are recorded in the ZCode log
  with outcome and duration.
- **Everything is denied** — you set `JEV_GUARD_FAIL_MODE=block` without a
  working `TYPESAFE_API_KEY`. Unset it or fix the key.
- **Wire-testing** — `JEV_GUARD_MOCK=malicious` + hook JSON on stdin must
  exit 2; `JEV_GUARD_MOCK=clean` must exit 0. No API calls are made in mock
  mode.

## Limitations

- **`Bash` and `Grep` output is not guarded.** A `PreToolUse` hook runs before
  a tool executes, so there is no content to judge yet; only `WebFetch` and
  `Read` expose their target deterministically. Pipe suspicious command output
  through `guard.py --text`.
- **Truncation.** Only the first `JEV_GUARD_MAX_CHARS` characters are judged;
  payloads past that point are not screened.
- **A judgment is not a sandbox.** Signals are calibrated probabilities, not
  proof. Validate the guard on your own traffic, tune the threshold to your
  consequences, and treat the `request_id` as your audit handle.
- **Fail-open by default.** Availability is prioritized over enforcement; set
  `JEV_GUARD_FAIL_MODE=block` only once the key and network are dependable.

## License

GPL-3.0 — see [LICENSE](LICENSE).
