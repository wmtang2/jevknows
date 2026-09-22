# ZCode port

Jev injection guard for [ZCode](https://zcode.dev): a `PreToolUse` hook that
runs before every `WebFetch` and `Read` in the workspace, judges the content
with Jev, and **denies the load** (hook exit 2) when malicious,
agent-directed instructions are detected. ZCode can intercept both tools
before they run, so this port gives deterministic coverage of exactly the two
surfaces that carry untrusted content.

The skill directory is [`jev-injection-guard/`](jev-injection-guard/) — its
`SKILL.md` documents operation, tuning, and manual judging for the agent.

## Setup

### 1. Get the skill

Copy the skill directory into your workspace's skills folder:

```bash
# from a checkout of this repo
cp -r zcode/jev-injection-guard <your-workspace>/.agents/skills/
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
export TYPESAFE_API_KEY="tsk_..."     # from the TypeSafe console
```

Without it the guard fails open (allows everything, logs a warning).

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
should show the guard running on each `WebFetch`/`Read`, and a blocked load
denies the tool call with the fired signals and `request_ids`.

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

Then test live against the bundled fixtures:

```bash
$PY $GUARD --file jev-injection-guard/tests/injected.md   # decision: block
$PY $GUARD --file jev-injection-guard/tests/benign.md     # decision: allow
```

If you copied the skill into a workspace, run the same commands from there —
the paths above are relative to a checkout of this repo.
