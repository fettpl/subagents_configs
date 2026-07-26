#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OPENCODE_HOME=${OPENCODE_HOME:-"$HOME/.config/opencode"}
export SCRIPT_DIR OPENCODE_HOME
python3 - <<'PY'
import base64, hashlib, json, os, pathlib, shutil, time

src = pathlib.Path(os.environ["SCRIPT_DIR"])
home = pathlib.Path(os.environ["OPENCODE_HOME"]).expanduser()
state_file = home / ".subagents_configs-opencode-state.json"
routing = home / "OPENCODE_SUBAGENT_ROUTING.md"
instructions = home / "AGENTS.md"
begin = b"# BEGIN subagents_configs opencode"
end = b"# END subagents_configs opencode"

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
    return str(target)

try:
    old_state = json.loads(state_file.read_text())
except (FileNotFoundError, json.JSONDecodeError):
    old_state = {"files": {}}

sources = sorted((src / "opencode" / "agents").glob("*.md"))
for path in sources:
    text = path.read_text()
    if not text.startswith("---\n") or "\nmode: subagent\n" not in text:
        raise SystemExit(f"error: invalid OpenCode agent frontmatter: {path}")
print("OpenCode agent validation passed")

home.mkdir(parents=True, exist_ok=True)
current = {}

def install(source, target, key):
    target.parent.mkdir(parents=True, exist_ok=True)
    source_hash = digest(source)
    ownership, saved_backup = "created", None
    identical = False
    if target.exists():
        if digest(target) == source_hash:
            ownership, identical = "preexisting", True
            print("unchanged:", target)
        else:
            ownership, saved_backup = "replaced", backup(target)
            shutil.copy2(source, target)
            print("installed:", target)
    else:
        shutil.copy2(source, target)
        print("installed:", target)
    prior = old_state.get("files", {}).get(key)
    if identical and prior and prior.get("installed_hash") == source_hash:
        ownership = prior.get("ownership", ownership)
        saved_backup = prior.get("backup")
    current[key] = {"target": str(target), "installed_hash": source_hash, "ownership": ownership, "backup": saved_backup}

for source in sources:
    install(source, home / "agents" / source.name, "agents/" + source.name)
install(src / "rules" / "OPENCODE_SUBAGENT_ROUTING.md", routing, "routing")

block = begin + b"\n@" + str(routing).encode() + b"\n" + end
old = instructions.read_bytes() if instructions.exists() else b""
start = old.find(begin)
finish = old.find(end, start)
original = old[start:finish + len(end)] if start >= 0 and finish >= start else b""
updated = old[:start] + block + old[finish + len(end):] if start >= 0 and finish >= start else old + (b"\n\n" if old else b"") + block + b"\n"
global_state = {"target": str(instructions), "block": block.decode(), "before": base64.b64encode(old).decode(), "original_segment": base64.b64encode(original).decode(), "ownership": "unchanged"}
prior_global = old_state.get("global", {})
if prior_global.get("block") == block.decode() and prior_global.get("ownership") == "managed":
    global_state = prior_global
if updated != old:
    global_state["ownership"] = "managed"
    global_state["backup"] = backup(instructions) if instructions.exists() else None
    instructions.write_bytes(updated)
    print("updated:", instructions)

state_file.write_text(json.dumps({"files": current, "global": global_state}, indent=2) + "\n")
PY
echo "OpenCode subagents installed under $OPENCODE_HOME"
echo "Restart OpenCode to load the new agents and instructions"
