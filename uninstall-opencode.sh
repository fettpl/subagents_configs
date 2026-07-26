#!/bin/sh
set -eu
OPENCODE_HOME=${OPENCODE_HOME:-"$HOME/.config/opencode"}
export OPENCODE_HOME
python3 - <<'PY'
import base64, hashlib, json, os, pathlib, shutil, time

home = pathlib.Path(os.environ["OPENCODE_HOME"]).expanduser()
state_file = home / ".subagents_configs-opencode-state.json"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def backup(path):
    stamp = time.strftime("%Y%m%d%H%M%S")
    target = path.with_name(path.name + ".subagents_configs.bak-" + stamp)
    index = 1
    while target.exists():
        target = path.with_name(path.name + ".subagents_configs.bak-" + stamp + f"-{index}")
        index += 1
    shutil.copy2(path, target)
    print("backup:", target)

try:
    state = json.loads(state_file.read_text())
except (FileNotFoundError, json.JSONDecodeError):
    print("No OpenCode installer state; nothing removed safely")
    state = {}

for item in state.get("files", {}).values():
    path = pathlib.Path(item["target"])
    if not path.exists() or digest(path) != item["installed_hash"]:
        print("preserved modified/missing:", path)
    elif item["ownership"] == "created":
        path.unlink()
        print("removed:", path)
    elif item["ownership"] == "replaced" and item.get("backup"):
        shutil.copy2(item["backup"], path)
        print("restored:", path)
    else:
        print("preserved pre-existing:", path)

global_state = state.get("global", {})
path = pathlib.Path(global_state["target"]) if global_state.get("target") else None
if path and path.exists() and global_state.get("ownership") == "managed":
    block = global_state["block"].encode()
    data = path.read_bytes()
    position = data.find(block)
    if position >= 0:
        backup(path)
        original = base64.b64decode(global_state.get("original_segment", ""))
        updated = data[:position] + original + data[position + len(block):]
        if not base64.b64decode(global_state.get("before", "")) and not updated.strip():
            path.unlink()
        else:
            path.write_bytes(updated)
        print("removed exact managed block:", path)
    else:
        print("preserved AGENTS.md: managed block changed or missing")

state_file.unlink(missing_ok=True)
PY
echo "OpenCode subagents uninstalled from $OPENCODE_HOME"
