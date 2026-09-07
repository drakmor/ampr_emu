"""Discover emulator candidates. Filenames are hints, never proof of capability."""
from pathlib import Path
import sys,re,hashlib

def bundled(name):
 if getattr(sys,'frozen',False):return Path(sys._MEIPASS)/name
 return Path(__file__).resolve().parent/'macos'/name

def emu_directory():
 if getattr(sys,'frozen',False):
  exe=Path(sys.executable).resolve()
  for p in exe.parents:
   if p.suffix=='.app':return p.parent.parent/'emus'
 return Path(__file__).resolve().parent/'macos'/'emus'

def digest(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def inspect(path):
 path=Path(path).resolve();name=path.name.lower();pack=None;record=None
 if not name.startswith('libsceampr.sprx') and name not in {'recording-debug.sprx','runtime-pack.sprx'}:raise ValueError('Select a libSceAmpr.sprx emulator file, not a different SPRX library.')
 if 'nopack' in name or 'no-pack' in name:pack=False
 elif 'pack' in name:pack=True
 if 'debug' in name:record=True
 elif 'test-pack' in name or 'test-nopack' in name:record=False
 version=re.search(r'\d+(?:\.\d+)+',name)
 return {'path':str(path),'name':path.name,'sha256':digest(path),'pack':pack,'record':record,'version':version.group() if version else 'unknown','confirmed':False}

def candidates(extra=()):
 found=[];seen=set()
 defaults=[(bundled('recording-debug.sprx'),True,True),(bundled('runtime-pack.sprx'),True,False)]
 known={
  'b44a986f2fa9903e74a34cbbd4681e899cd99196613652cd073ed11f2ca947c2':(True,True),
  '69e6c4d5e4f5fb83c9e01815db5861c4c75734acbf4595cafa50d4c218116d1a':(True,False),
 }
 directory=emu_directory()
 paths=list(directory.glob('libSceAmpr.sprx*')) if directory.exists() else []
 paths+=list(map(Path,extra))
 paths += [p for p,_,_ in defaults if p.is_file()]
 for p in paths:
  if not p.is_file() or str(p.resolve()) in seen:continue
  seen.add(str(p.resolve()));item=inspect(p)
  if item['sha256'] in known:
   item['pack'],item['record']=known[item['sha256']];item['confirmed']=True;item['pool_mib']=384
  found.append(item)
 def version(x):return tuple(int(v) for v in re.findall(r'\d+',x['version']))
 return sorted(found,key=version,reverse=True)
