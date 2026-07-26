#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CODEX_HOME=${CODEX_HOME:-"$HOME/.codex"}
export SCRIPT_DIR CODEX_HOME
python3 - <<'PY'
import base64,hashlib,json,os,pathlib,shutil,time
src=pathlib.Path(os.environ['SCRIPT_DIR']); home=pathlib.Path(os.environ['CODEX_HOME']).expanduser()
agents=home/'agents'; routing=home/'SUBAGENT_ROUTING.md'; gf=home/'AGENTS.md'; sf=home/'.subagents_configs-state.json'
begin,finish=b'# BEGIN subagents_configs',b'# END subagents_configs'
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def backup(p):
 stamp=time.strftime('%Y%m%d%H%M%S'); out=p.with_name(p.name+'.subagents_configs.bak-'+stamp); n=1
 while out.exists(): out=p.with_name(p.name+'.subagents_configs.bak-'+stamp+f'-{n}'); n+=1
 shutil.copy2(p,out); print('backup:',out); return str(out)
try: oldstate=json.loads(sf.read_text())
except (FileNotFoundError,json.JSONDecodeError): oldstate={'files':{}}
# Validate every source before touching destinations or state.
try:
 import tomllib
 for p in sorted((src/'agents').glob('*.toml')):
  with p.open('rb') as f: tomllib.load(f)
 print('TOML validation passed')
except ImportError: print('TOML validation skipped: Python tomllib is unavailable')
# Preflight config before touching any destination. An exact standard header is
# safe to recognize textually; all other existing configs require a TOML parser.
config=home/'config.toml'; config_block=(
 b'[features.multi_agent_v2]\n'
 b'hide_spawn_agent_metadata = false\n'
 b'tool_namespace = "agents"\n')
if config.exists():
 data=config.read_bytes()
 import re
 exact_header=re.compile(r'^\s*\[\s*features\s*\.\s*multi_agent_v2\s*\]\s*(?:#.*)?$')
 def has_exact_header(raw):
  if b'"""' in raw or b"'''" in raw: return False
  try: text=raw.decode('utf-8')
  except UnicodeDecodeError: return False
  return any(exact_header.fullmatch(line) for line in text.splitlines())
 if has_exact_header(data):
  config_has_table=True
 else:
  try:
   try: import tomllib as toml
   except ImportError: import tomli as toml
  except ImportError:
   raise SystemExit('error: cannot inspect config.toml without Python 3.11+ tomllib or tomli; no files were changed')
  try:
   parsed=toml.loads(data.decode('utf-8'))
  except Exception as e:
   raise SystemExit(f'error: config.toml is invalid TOML ({e}); no files were changed')
  features=parsed.get('features')
  config_has_table=isinstance(features,dict) and 'multi_agent_v2' in features
else: data=b''; config_has_table=False
home.mkdir(parents=True,exist_ok=True)
current={}
def install(s,t,k):
 t.parent.mkdir(parents=True,exist_ok=True); sh=h(s); own='created'; bp=None
 identical=False
 if t.exists():
  if h(t)==sh: own='preexisting'; identical=True; print('unchanged:',t)
  else: own='replaced'; bp=backup(t); shutil.copy2(s,t); print('installed:',t)
 else: shutil.copy2(s,t); print('installed:',t)
 prior=oldstate.get('files',{}).get(k)
 if identical and prior and prior.get('installed_hash')==sh: own=prior.get('ownership',own); bp=prior.get('backup')
 current[k]={'target':str(t),'installed_hash':sh,'ownership':own,'backup':bp}
for s in sorted((src/'agents').glob('*.toml')): install(s,agents/s.name,'agents/'+s.name)
install(src/'rules/SUBAGENT_ROUTING.md',routing,'routing')
# Enable the multi-agent feature only when the user's config does not define it.
# This file is intentionally not recorded in installer state: uninstall leaves
# the block in place because ownership cannot be proven safely after edits.
if config.exists():
 if not config_has_table:
  backup(config)
  config.write_bytes(data+(b'' if not data or data.endswith(b'\n') else b'\n')+config_block)
  print('updated:',config)
 else: print('unchanged:',config)
else:
 config.parent.mkdir(parents=True,exist_ok=True)
 config.write_bytes(config_block)
 print('created:',config)
# Remove package-owned files no longer present in this checkout, but never touch modified files.
for key,item in oldstate.get('files',{}).items():
 if key in current: continue
 t=pathlib.Path(item['target'])
 if t.exists() and h(t)==item['installed_hash']:
  if item['ownership']=='created': t.unlink(); print('removed stale:',t)
  elif item['ownership']=='replaced' and item.get('backup'): shutil.copy2(item['backup'],t); print('restored stale:',t)
 else: print('preserved stale modified/missing:',t)
block=begin+b'\n@'+str(routing).encode()+b'\n'+finish; old=gf.read_bytes() if gf.exists() else b''; a=old.find(begin); b=old.find(finish,a)
original_segment=old[a:b+len(finish)] if a>=0 and b>=a else b''
updated=old[:a]+block+old[b+len(finish):] if a>=0 and b>=a else old+(b'\n\n' if old else b'')+block+b'\n'
prior_g=oldstate.get('global',{})
g={'target':str(gf),'block':block.decode(),'before':base64.b64encode(old).decode(),'original_segment':base64.b64encode(original_segment).decode(),'ownership':'unchanged'}
if prior_g.get('block')==block.decode() and prior_g.get('ownership')=='managed': g=prior_g
if updated!=old:
 g['ownership']='managed'; g['backup']=backup(gf) if gf.exists() else None; gf.write_bytes(updated); print('updated:',gf)
json.dump({'files':current,'global':g},sf.open('w'),indent=2); sf.write_text(sf.read_text()+'\n')
PY
echo "Codex subagents installed under $CODEX_HOME"
echo "Restart Codex to load the new agents and instructions"
