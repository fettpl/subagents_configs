#!/bin/sh
set -eu
CODEX_HOME=${CODEX_HOME:-"$HOME/.codex"}
export CODEX_HOME
python3 - <<'PY'
import base64,hashlib,json,os,pathlib,shutil,time
home=pathlib.Path(os.environ['CODEX_HOME']).expanduser(); sf=home/'.subagents_configs-state.json'
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def backup(p):
 stamp=time.strftime('%Y%m%d%H%M%S'); out=p.with_name(p.name+'.subagents_configs.bak-'+stamp); n=1
 while out.exists(): out=p.with_name(p.name+'.subagents_configs.bak-'+stamp+f'-{n}'); n+=1
 shutil.copy2(p,out); print('backup:',out)
try: state=json.loads(sf.read_text())
except (FileNotFoundError,json.JSONDecodeError): print('No Codex installer state; nothing removed safely'); state={}
for item in state.get('files',{}).values():
 p=pathlib.Path(item['target'])
 if not p.exists() or h(p)!=item['installed_hash']: print('preserved modified/missing:',p); continue
 if item['ownership']=='created': p.unlink(); print('removed:',p)
 elif item['ownership']=='replaced' and item.get('backup'): shutil.copy2(item['backup'],p); print('restored:',p)
 else: print('preserved pre-existing:',p)
g=state.get('global',{}); p=pathlib.Path(g['target']) if g.get('target') else None
if p and p.exists() and g.get('ownership')=='managed':
 block=g['block'].encode(); data=p.read_bytes(); pos=data.find(block)
 if pos>=0:
  backup(p); before=base64.b64decode(g.get('before','')); a=before.find(block[:len(b'# BEGIN subagents_configs')]); e=before.find(b'# END subagents_configs',a)
  expected=before[:a]+block+before[e+len(b'# END subagents_configs'):] if a>=0 and e>=a else before+(b'\n\n' if before else b'')+block+b'\n'
  original=base64.b64decode(g.get('original_segment',''))
  p.write_bytes(before if before and data==expected else data[:pos]+original+data[pos+len(block):]); print('removed exact managed block:',p)
 else: print('preserved AGENTS.md: managed block changed or missing')
sf.unlink(missing_ok=True)
PY
echo "Codex subagents uninstalled from $CODEX_HOME"
