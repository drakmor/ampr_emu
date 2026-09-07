"""Project lifecycle for the Mac front end. All operations are journalled.
Game assets are never deleted to save space. Finalisation builds a new game,
keeps the complete original in the chosen work folder, then publishes it.
"""
from pathlib import Path
from datetime import datetime
import argparse, json, shutil, os, hashlib, time, uuid, tempfile, tomllib
SCHEMA=2
# Runtime-generated logs are not immutable game assets. This affects comparisons
# only, not copying, archiving or deletion.
MUTABLE_LOGS={'ampr_emu.log','dlc_emu.log'}
def mutable_log(rel):return rel.lower() in MUTABLE_LOGS
CONTROL=['fakelib/libSceAmpr.sprx','ampr_emu.index','ampr_emu.index.tmp','ampr_emu.index.bak','ampr_commands.bin','ampr_emu.log']
def now():return datetime.now().isoformat(timespec='seconds')
def sha(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def atomic_json(path,data):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(path.name+'.writing')
 with tmp.open('w') as f:
  json.dump(data,f,indent=2);f.flush();os.fsync(f.fileno())
 tmp.replace(path)
def same_volume(a,b):return Path(a).stat().st_dev==Path(b).stat().st_dev
def contained(path,parent):
 path=Path(path).resolve();parent=Path(parent).resolve();return path==parent or parent in path.parents

def files(root):
 root=Path(root);result={}
 for p in root.rglob('*'):
  if p.is_symlink():raise ValueError('Symbolic links are not supported in game folders: '+str(p))
  if p.is_file() and not p.name.startswith('._') and p.name!='.DS_Store':
   s=p.stat();result[p.relative_to(root).as_posix()]={'size':s.st_size,'mtime_ns':s.st_mtime_ns}
 return result

def byte_copy(src,dst,progress=None):
 dst=Path(dst);dst.parent.mkdir(parents=True,exist_ok=True)
 h=hashlib.sha256()
 with Path(src).open('rb') as a,dst.open('wb') as b:
  while chunk:=a.read(4*1024*1024):
   b.write(chunk);h.update(chunk)
   if progress:progress(len(chunk))
  b.flush();os.fsync(b.fileno())
 # Read back the copied file before using it in a transactional replacement.
 if sha(dst)!=h.hexdigest():raise IOError('Copy verification failed: '+str(dst))
 shutil.copystat(src,dst)

from ampr_progress import Progress

def copy_tree(src,dst):
 src=Path(src);dst=Path(dst)
 if dst.exists():raise ValueError('Destination already exists: '+str(dst))
 inventory=files(src);progress=Progress('Copying original',sum(v['size'] for v in inventory.values()));dst.mkdir(parents=True)
 for p in src.rglob('*'):
  if p.is_dir():(dst/p.relative_to(src)).mkdir(parents=True,exist_ok=True)
 for rel in inventory:byte_copy(src/rel,dst/rel,progress)
 return inventory

def validate_inventory(root,expected,strict=False):
 got={k:v for k,v in files(root).items() if not mutable_log(k)}
 expected={k:v for k,v in expected.items() if not mutable_log(k)}
 if strict and set(got)!=set(expected):raise ValueError('Folder contents changed: '+str(root))
 for rel,v in expected.items():
  if rel not in got or got[rel]['size']!=v['size']:raise ValueError('File missing or size changed: '+str(Path(root)/rel))

def create(game,work):
 game=Path(game).resolve();work=Path(work).resolve()
 if not (game/'eboot.bin').is_file():raise ValueError('Choose the game folder containing eboot.bin.')
 if contained(work,game):raise ValueError('Choose a working folder outside the game folder.')

 work.mkdir(parents=True,exist_ok=True);p=work/(game.name+'.json')
 if p.exists() and json.loads(p.read_text()).get('phase')!='recovered':raise ValueError('A project with this game name already exists here. Use Open Project or choose another working folder.')
 ident=uuid.uuid4().hex;store=work/'.ampr-projects'/ident;store.mkdir(parents=True)
 inventory=files(game)
 data={'schema':SCHEMA,'id':ident,'name':game.name,'project_file':str(p),'game':str(game),'work':str(work),'store':str(store),'created':now(),'updated':now(),'phase':'created','running':None,'completed':[], 'paths':{'trace':'','toml':'','output':''},'original_files':inventory,'controls':{},'created_files':[],'created_dirs':[],'events':[]}
 for rel in CONTROL:
  source=game/rel
  if source.exists():
   dest=store/'controls'/rel;byte_copy(source,dest);data['controls'][rel]={'exists':True,'sha256':sha(dest)}
  else:data['controls'][rel]={'exists':False}
 atomic_json(p,data);return p

class Project:
 def __init__(self,path):
  self.path=Path(path).resolve();self.d=json.loads(self.path.read_text())
  if self.d.get('schema')!=SCHEMA:raise ValueError('This file is not a supported AMPR project.')
  if str(self.path)!=self.d['project_file']:raise ValueError('The project file was moved. Put it back at '+self.d['project_file'])
  self.game=Path(self.d['game']);self.work=Path(self.d['work']);self.store=Path(self.d['store'])
 @property
 def index_path(self):return Path(self.d.get('paths',{}).get('index') or self.game/'ampr_emu.index')
 def save(self):self.d['updated']=now();atomic_json(self.path,self.d)
 def note(self,event):self.d['events'].append({'at':now(),'event':event});self.save()
 def issues(self):
  problems=[]
  for p in [self.work,self.store]:
   if not p.is_dir():problems.append('Missing folder: '+str(p))
  if self.can_resume_publication():problems.append('PAK creation finished but output publication was interrupted. Click Continue to reuse the existing PAKs without repacking.')
  elif self.d.get('transaction') in {'assembling','assembled'}:problems.append('PAK assembly was interrupted. Close the old app, then click Continue to retry using the existing PAK output. Original files have not yet been replaced.')
  elif self.d.get('transaction') in {'original-moved','original-restored','published'}:problems.append('Original already moved to its backup. Click Continue to finish publishing the existing PAK game. No repacking is needed.')
  elif self.d.get('running'):problems.append('Interrupted operation: '+self.d['running']+'. It is not marked complete. Use Recover if preparation/finalisation was interrupted. Build/verification can be restarted in a new output folder.')
  if self.d['phase']=='complete':
   for k in ['backup','game']:
    if not Path(self.d[k]).is_dir():problems.append('Missing '+k+' folder: '+self.d[k])
   if Path(self.d.get('backup','')).is_dir():
    try:validate_inventory(self.d['backup'],self.d['original_files'],True)
    except Exception as e:problems.append(str(e))
  elif self.d.get('transaction') not in {'original-moved','original-restored','published'} and not (self.game/'eboot.bin').exists():problems.append('Game folder missing: '+str(self.game))
  for rel,v in self.d['controls'].items():
   if v['exists'] and not (self.store/'controls'/rel).is_file():problems.append('Recovery file missing: '+rel)
  for key,label in [('trace','Recording folder'),('toml','TOML'),('output','PAK output')]:
   value=self.d['paths'].get(key)
   if value and not Path(value).exists() and (key!='toml' or 'profile' in self.d['completed']):problems.append(label+' not found: '+value)
  return problems
 def verify_controls(self):
  for rel,v in self.d['controls'].items():
   if v['exists'] and sha(self.store/'controls'/rel)!=v['sha256']:raise ValueError('Recovery backup missing or changed: '+rel)
 def unique_old(self,path):
  if not path.exists():return
  dest=path.with_name(path.name+'.old');i=1
  while dest.exists():dest=path.with_name(path.name+f'.old.{i}');i+=1
  self.d['created_files'].append(dest.relative_to(self.game).as_posix());self.save();byte_copy(path,dest)
 def prepare(self,debug,index_only=False,emulator_only=False):
  if self.d['phase'] in {'complete','recovered'}:raise ValueError('Create a new project for another preparation cycle.')
  if (self.game/'ampr_assets.index').exists() and not emulator_only:raise ValueError('Do not rebuild the file IDs of an existing PAK game. Use emulator-only update or a complete original game.')
  self.verify_controls()
  if not index_only:
   source=Path(debug)
   if not source.is_file():raise ValueError('Selected emulator file is missing.')
   folder=self.game/'fakelib'
   if not folder.exists():self.d['created_dirs'].append('fakelib');self.save();folder.mkdir()
   self.unique_old(folder/'libSceAmpr.sprx');byte_copy(source,folder/'libSceAmpr.sprx')
  if not emulator_only:
   self.unique_old(self.game/'ampr_emu.index')
   from build_ampr_index import build_index_local
   if build_index_local(self.game,self.game/'ampr_emu.index',False)!=0:raise ValueError('Index generation failed. Recover is available.')
   self.d['paths']['index']=str(self.game/'ampr_emu.index')
  self.d['phase']='prepared';self.d['completed']=list(dict.fromkeys(self.d['completed']+['prepared']));self.note('Emulator updated' if emulator_only else ('Game emulator installed and index rebuilt' if not index_only else 'Index created'))
 def archive(self):
  dest=Path(self.d['paths']['trace']).resolve()
  if contained(dest,self.game):raise ValueError('The recording archive must be outside the game folder.')
  for n in ['ampr_commands.bin','ampr_emu.index']:
   if not (self.index_path if n=='ampr_emu.index' else self.game/n).is_file():raise ValueError('Missing '+n+'. No recording was saved.')
  dest.mkdir(parents=True,exist_ok=True);run=dest/('run-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));self.track(run);run.mkdir()
  for n in ['ampr_commands.bin','ampr_emu.index','ampr_emu.log']:
   source=self.index_path if n=='ampr_emu.index' else self.game/n
   if source.is_file():self.track(run/n);byte_copy(source,run/n)
  self.d.setdefault('recordings',[]).append(str(run));self.d['completed']=list(dict.fromkeys(self.d['completed']+['recording']));self.note('Recording saved: '+str(run));print('Recording saved to '+str(run),flush=True)
 def check_profile(self):
  from ampr_pack_format import RuntimeSettings,parse_size
  from ampr_pack import load_config
  load_config(Path(self.d['paths']['toml']))
  config=tomllib.loads(Path(self.d['paths']['toml']).read_text());rt=config.get('runtime',{})
  settings=RuntimeSettings(parse_size(rt.get('decoded_cache_bytes',64*2**20)),parse_size(rt.get('physical_cache_bytes',64*2**20)),rt.get('workers',4),rt.get('latency_reserve_workers',1));settings.validate()
  if not rt:raise ValueError('This TOML has no [runtime] settings. Use a current generated profile with runtime settings.')
  if config.get('pack',{}).get('index_name','ampr_assets.index')!='ampr_assets.index':raise ValueError('The guided app requires index_name = ampr_assets.index.')
  # Upstream guide: 64 MiB pipeline + 32 MiB reserve + 1 MiB/worker,
  # caches, resident indexes and 8 MiB additional headroom.
  import re
  text=Path(self.d['paths']['toml']).read_text();m=re.search(r'Projected resident pack index: ([\d.]+) MiB',text)
  projected=float(m.group(1)) if m else None
  pool=self.d.get('emulators',{}).get('pak',{}).get('pool_mib',384)
  base=96+settings.workers+(settings.decoded_cache_bytes+settings.physical_cache_bytes)/2**20+8
  estimate=base+(projected or 0)+self.index_path.stat().st_size/2**20
  result={'pool_mib':pool,'fixed_and_headroom_mib':base,'projected_index_mib':projected,'estimated_total_mib':estimate if projected is not None else None,'within_estimate':estimate<=pool if projected is not None else None,'message':f'Estimated memory fits the selected {pool} MiB runtime pool. Actual index size will be checked after building.' if projected is not None and estimate<=pool else (f'Estimated memory exceeds {pool} MiB. Reduce cache sizes/workers before building.' if projected is not None else 'No index estimate in this TOML. The actual index must fit before finalisation.')}
  self.d['profile_check']=result;self.save();print(json.dumps(result,indent=2),flush=True)
  if projected is not None and estimate>pool:raise ValueError(result['message'])
  return result
 def stamp(self,verified=True):
  from ampr_pack_format import load_manifest,read_runtime_settings
  cfg=tomllib.loads(Path(self.d['paths']['toml']).read_text());out=Path(self.d['paths']['output']);index=out/cfg.get('pack',{}).get('index_name','ampr_assets.index')
  if index.name!='ampr_assets.index':raise ValueError('This guided runtime expects index_name = ampr_assets.index.')
  m=load_manifest(index);settings=read_runtime_settings(Path(str(index)+'.runtime'),m.build_id)
  # read_runtime_settings can return None when no sidecar exists; guided output requires one.
  if settings is None:raise ValueError('Runtime configuration missing.')
  budget=96+settings.workers+(settings.decoded_cache_bytes+settings.physical_cache_bytes+index.stat().st_size+self.index_path.stat().st_size)/2**20+8
  pool=self.d.get('emulators',{}).get('pak',{}).get('pool_mib',384)
  if budget>pool:raise ValueError(f'Actual memory estimate {budget:.1f} MiB exceeds the selected {pool} MiB pool. Do not finalise. Adjust runtime settings and verify again.')
  names=[m.pack_name(i) for i in range(len(m.packs))]+[index.name,index.name+'.runtime',index.name+'.crc']
  for name in names:
   if Path(name).name!=name:raise ValueError('Unexpected nested pack filename: '+name)
  self.d['receipt']={'verified':verified,'source_index':sha(self.index_path),'manifest':sha(index),'files':{n:{'size':(out/n).stat().st_size,'mtime_ns':(out/n).stat().st_mtime_ns} for n in names},'source_files':files(self.game),'budget_mib':budget,'output':str(out)}
  self.d['phase']='verified' if verified else 'built_unverified';self.d['completed']=list(dict.fromkeys(self.d['completed']+[self.d['phase']]));self.note('PAK verification complete' if verified else 'Byte verification skipped by user');print(f'Runtime budget estimate {budget:.1f} / {pool} MiB. Byte verification: {verified}.',flush=True)
 def validate_receipt(self):
  r=self.d.get('receipt')
  if not r:raise ValueError('No recorded PAK build. Verify the set or explicitly choose Skip verification first.')
  out=Path(self.d['paths']['output'])
  if str(out)!=r['output']:raise ValueError('PAK output path changed after verification.')
  if sha(self.index_path)!=r['source_index']:raise ValueError('Game index changed since verification.')
  if sha(out/'ampr_assets.index')!=r['manifest']:raise ValueError('PAK index changed since verification.')
  for n,v in r['files'].items():
   s=(out/n).stat()
   if s.st_size!=v['size'] or s.st_mtime_ns!=v['mtime_ns']:raise ValueError('PAK file changed: '+n)
  cur=files(self.game)
  for rel,v in r['source_files'].items():
   if rel=='ampr_commands.bin' or mutable_log(rel):continue
   if rel not in cur or cur[rel]!=v:raise ValueError('Source changed since verification: '+rel)
  return out,r
 def restore_controls(self,root):
  root=Path(root);self.verify_controls()
  # Caller preserves the complete altered game before restoring controls.
  for rel,v in self.d['controls'].items():
   p=root/rel
   if v['exists']:byte_copy(self.store/'controls'/rel,p)
   elif p.is_file():p.unlink()
  for rel in self.d['created_files']:
   p=root/rel
   if p.is_file():p.unlink()
  for rel in reversed(self.d['created_dirs']):
   p=root/rel
   if p.is_dir() and not any(p.iterdir()):p.rmdir()
 def return_moved_paks(self):
  # Restore only journalled names. Record each destination before its rename so
  # a crash between rename and save remains recoverable.
  moves=self.d.get('pak_moves',[])
  for item in reversed(moves):
   src=Path(item['source']);dest=Path(item['destination'])
   if not dest.exists() and self.d.get('phase')=='complete':dest=self.game/dest.name
   if not dest.exists() and self.d.get('transaction')=='published':dest=self.game/dest.name
   if dest.exists():
    if src.exists():raise ValueError('Both PAK locations exist. Nothing overwritten: '+str(src))
    src.parent.mkdir(parents=True,exist_ok=True)
    if same_volume(dest.parent,src.parent):dest.rename(src)
    else:
     byte_copy(dest,src);dest.unlink()
   elif not src.exists():raise ValueError('Journalled PAK file is missing: '+str(src))
  self.d['pak_moves']=[];self.save()
 def retry_assembly(self):
  if self.d.get('transaction') not in {'assembling','assembled'}:return
  backup=Path(self.d['backup']) if self.d.get('backup') else None
  if not self.game.is_dir() or (backup and backup.exists()):raise ValueError('Original may already have moved. Use Recovery before retrying.')
  self.return_moved_paks()
  # Retain old incomplete copies; never promote an unverified old copy to source.
  previous=self.d.get('stage')
  if previous and Path(previous).exists():
   old=Path(previous)
   if old==Path(self.d['paths']['output'])/self.game.name:
    retained=old.with_name(old.name+'.incomplete-'+uuid.uuid4().hex[:8]);old.rename(retained)
   else:retained=old
   self.d.setdefault('retained_partial_folders',[]).append(str(retained))
  self.d['transaction']=None;self.d['running']=None;self.save()
 def complete(self,runtime):
  if self.d['phase']=='complete':raise ValueError('This project is already complete.')
  if self.d.get('transaction') in {'original-moved','original-restored','published'}:
   self.publish_assembled_game();return
  self.retry_assembly()
  self.verify_controls();out,r=self.validate_receipt()
  if r['budget_mib']>self.d.get('emulators',{}).get('pak',{}).get('pool_mib',384):raise ValueError('The selected runtime pool is smaller than the recorded budget. Adjust the profile and rebuild.')
  if not Path(runtime).is_file():raise ValueError('Bundled PAK runtime missing.')
  if self.d.get('transaction'):raise ValueError('Completion was interrupted. Use Recover before starting again.')
  from ampr_pack_format import load_manifest,FILE_FLAG_PACKED
  m=load_manifest(out/'ampr_assets.index');packed=set()
  for i,rec in enumerate(m.files,1):
   if rec.flags & FILE_FLAG_PACKED:
    rel=m.file_path(i).removeprefix('/app0/')
    if Path(rel).is_absolute() or '..' in Path(rel).parts:raise ValueError('Invalid manifest path.')
    if rel in {'eboot.bin','ampr_emu.index'} or rel.startswith(('fakelib/','sce_sys/','sce_module/')):raise ValueError('Profile packs a required loose file: '+rel)
    packed.add(rel)
  # Copy all actual loose files, including unindexed extras. Do not copy recording logs or
  # setup-created backups into the PAK game. The complete original backup retains them until restored.
  excluded=set(self.d['created_files'])|{'ampr_commands.bin','ampr_emu.log','ampr_emu.index.tmp','ampr_emu.index.bak'}
  loose={k:v for k,v in files(self.game).items() if k not in packed and k not in excluded and not k.startswith('.ampr-mac-recovery/')}
  collisions=set(loose)&set(r['files'])
  if collisions:raise ValueError('Loose game filenames conflict with PAK output: '+', '.join(sorted(collisions)))
  backup=self.work/'Original game'/self.game.name
  stage=out/self.game.name
  hold=self.game.parent/('.'+self.game.name+'.ampr-original-'+self.d['id'][:8])
  original_backup=backup;n=1
  while backup.exists():backup=original_backup.with_name(original_backup.name+f' ({n})');n+=1
  if any(p.exists() for p in [stage,hold]):raise ValueError('A staging folder already exists. Use Recover to resolve an interrupted completion first.')
  backup.parent.mkdir(parents=True,exist_ok=True)
  cross=not same_volume(self.work,self.game.parent)
  amount=sum(v['size'] for v in loose.values())
  if shutil.disk_usage(out).free<amount+64*2**20:raise ValueError('Not enough space in PAK Output for the remaining loose files. Nothing moved.')
  if not same_volume(out,self.game.parent) and shutil.disk_usage(self.game).free<amount+sum(v['size'] for v in r['files'].values())+64*2**20:raise ValueError('Not enough space on the game drive for the finished PAK game. Nothing moved.')
  if cross and shutil.disk_usage(self.work).free<sum(v['size'] for v in files(self.game).values())+64*2**20:raise ValueError('Not enough space in the working-folder drive for the complete original backup. Nothing moved.')
  self.d.update({'backup':str(backup),'stage':str(stage),'hold':str(hold),'transaction':'assembling'});self.save()
  stage.mkdir();progress=Progress('Copying loose files',amount)
  for rel in loose:
   target=stage/rel;target.parent.mkdir(parents=True,exist_ok=True)
   # The optional PAK verification is a separate step. Do not reread every
   # copied loose file during finalisation.
   with (self.game/rel).open('rb') as source,target.open('wb') as dest:
    while chunk:=source.read(4*1024*1024):dest.write(chunk);progress(len(chunk))
    dest.flush();os.fsync(dest.fileno())
   shutil.copystat(self.game/rel,target)
  for name in r['files']:
   if (stage/name).exists():raise ValueError('Loose file conflicts with PAK output: '+name)
   self.d.setdefault('pak_moves',[]).append({'source':str(out/name),'destination':str(stage/name)});self.save()
   (out/name).rename(stage/name)
  print('PAK files moved into the complete game folder. No duplicate PAK copy was made.',flush=True)
  byte_copy(runtime,stage/'fakelib/libSceAmpr.sprx')
  byte_copy(self.index_path,stage/'ampr_emu.index')
  (stage/'.ampr-project-id').write_text(self.d['id'])
  self.d['transaction']='assembled';self.save()
  if cross:
   copy_tree(self.game,backup);self.d['transaction']='backup-copied';self.save()
   self.game.rename(hold)
  else:self.game.rename(backup)
  self.d['transaction']='original-moved';self.save()
  self.publish_assembled_game()
 def publish_assembled_game(self):
  # Resume the journalled finalisation after the original has moved. No repack,
  # no source receipt validation against the now-vacant original game path.
  backup=Path(self.d['backup']);stage=Path(self.d['stage']);hold=Path(self.d['hold'])
  self.verify_controls()
  if not backup.is_dir():raise ValueError('Original backup missing: '+str(backup))
  if self.d['transaction']=='original-moved':
   self.restore_controls(backup)
  validate_inventory(backup,self.d['original_files'],True)
  candidate=self.game if self.game.exists() else stage
  marker=candidate/'.ampr-project-id'
  if not marker.is_file() or marker.read_text()!=self.d['id']:raise ValueError('PAK game does not belong to this project: '+str(candidate))
  receipt=self.d['receipt']
  validate_inventory(candidate,receipt['files'])
  if sha(candidate/'ampr_assets.index')!=receipt['manifest']:raise ValueError('PAK index changed since assembly.')
  if sha(candidate/'ampr_emu.index')!=receipt['source_index']:raise ValueError('Game index changed since assembly.')
  if not (candidate/'fakelib/libSceAmpr.sprx').is_file():raise ValueError('Assembled PAK runtime is missing.')
  if not self.game.exists():
   self.d['transaction']='original-restored';self.save()
   if same_volume(stage.parent,self.game.parent):stage.rename(self.game)
   else:
    print('PAK Output and the game are on different volumes. The completed game must be transferred.',flush=True)
    publication=self.game.parent/('.'+self.game.name+'.ampr-publish-'+self.d['id'][:8])
    if publication.exists():
     # Keep an interrupted transfer and use a new destination, without overwriting.
     publication=publication.with_name(publication.name+'-'+uuid.uuid4().hex[:8])
    self.d['publication_stage']=str(publication);self.save()
    copy_tree(stage,publication);publication.rename(self.game)
  self.d['transaction']='published';self.save()
  for item in self.d.get('pak_moves',[]):item['destination']=str(self.game/Path(item['destination']).name)
  self.save()
  if stage.exists() and stage!=self.game:shutil.rmtree(stage)
  if hold.exists():shutil.rmtree(hold)
  self.d['phase']='complete';self.d['transaction']=None;self.d['completed']=list(dict.fromkeys(self.d['completed']+['complete']));self.note('Complete PAK game published with non-recording runtime; complete original backup retained')
  print('COMPLETE. PAK game: '+str(self.game)+'\nOriginal backup: '+str(backup),flush=True)
 def recover_full_original(self,backup,archive,clean=False):
  # Journal recovery itself: even a second interruption must be resumable.
  state=self.d.get('recovery')
  if not state:
   state={'step':'copying','restore':str(self.game.parent/('.'+self.game.name+'.ampr-restore-'+uuid.uuid4().hex[:8])), 'hold':str(self.game.parent/('.'+self.game.name+'.ampr-recovered-'+uuid.uuid4().hex[:8])), 'archive':str(archive/self.game.name)}
   state['move_original']=clean and same_volume(backup.parent,self.game.parent)
   self.d['recovery']=state;self.save()
  restore=Path(state['restore']);hold=Path(state['hold']);saved=Path(state['archive'])
  if state['step']=='copying':
   if self.game.exists() and (self.game/'.ampr-project-id').read_text()!=self.d['id']:raise ValueError('Target folder no longer belongs to this project. Nothing replaced.')
   if restore.exists() and not state.get('move_original'):
    # Retain any incomplete copy and start a fresh verified copy.
    restore=restore.with_name(restore.name+'-'+uuid.uuid4().hex[:6]);state['restore']=str(restore);self.save()
   if state.get('move_original'):
    if not restore.exists():backup.rename(restore)
   else:copy_tree(backup,restore)
   self.restore_controls(restore);validate_inventory(restore,self.d['original_files'],True)
   state['step']='ready';self.save()
  if state['step']=='ready':
   if restore.exists():
    if self.game.exists():
     if (self.game/'.ampr-project-id').read_text()!=self.d['id']:raise ValueError('Target folder changed during recovery.')
     self.game.rename(hold)
    restore.rename(self.game)
   # Covers a crash immediately after the publication rename.
   validate_inventory(self.game,self.d['original_files'],True)
   state['step']='restored';self.save()
  if state['step']=='restored' and clean:
   # The superseded PAK game stays here only until targeted cleanup succeeds.
   self.d['discard_pak_game']=str(hold);state['step']='done';self.save()
  if state['step']=='restored':
   if hold.exists():
    saved.parent.mkdir(parents=True,exist_ok=True)
    if same_volume(hold.parent,saved.parent):hold.rename(saved)
    else:
     if saved.exists():
      saved=saved.with_name(saved.name+'-'+uuid.uuid4().hex[:6]);state['archive']=str(saved);self.save()
     copy_tree(hold,saved)
   state['step']='archived';self.save()
  if state['step']=='archived':
   if hold.exists():shutil.rmtree(hold)
   self.d['recovered_pak_game']=str(saved)
   state['step']='done';self.save()
 def recover(self,clean=False):
  if clean and self.d.get('cleanup_plan'):
   self.finish_cleanup();return
  if self.d['phase']=='recovered':raise ValueError('This project has already been recovered.')
  if self.d.get('transaction') in {'assembling','assembled'}:self.return_moved_paks()
  self.verify_controls();backup=Path(self.d['backup']) if self.d.get('backup') else None
  stage=Path(self.d['stage']) if self.d.get('stage') else None;hold=Path(self.d['hold']) if self.d.get('hold') else None
  archive=self.work/'Recovered files'/datetime.now().strftime('%Y%m%d-%H%M%S-%f');archive.mkdir(parents=True)
  # During an interrupted cross-volume copy the active original still exists and is authoritative.
  original_away=(clean and self.d.get('recovery')) or backup and backup.exists() and (self.d.get('recovery') or self.d['phase']=='complete' or self.d.get('transaction') in {'original-moved','original-restored','published'} or (not self.game.exists()))
  if original_away:
   if backup.exists() and (self.d['phase']=='complete' or self.d.get('transaction') in {'original-restored','published'}):
    validate_inventory(backup,self.d['original_files'],True)
   self.recover_full_original(backup,archive,clean)
  else:
   if not self.game.exists() and hold and hold.exists():hold.rename(self.game)
   if not self.game.exists():raise ValueError('Original game folder missing. Recovery stopped.')
   validate_inventory(self.game,{k:v for k,v in self.d['original_files'].items() if k not in CONTROL},False)
   for rel in set(CONTROL+self.d['created_files']):
    p=self.game/rel
    if p.is_file():byte_copy(p,archive/'changed-files'/rel)
   self.restore_controls(self.game)
  if clean:
   validate_inventory(self.game,self.d['original_files'],True)
   self.plan_cleanup(archive);self.finish_cleanup();return
  if stage and stage.exists():
   # Partial staging is retained in place, never mistaken for an original backup.
   print('Partial PAK staging retained at '+str(stage),flush=True)
  self.d['phase']='recovered';self.d['transaction']=None;self.d['running']=None;self.d.pop('pending_checkpoint',None);self.d['history']=[];self.d['guide']={'step':'route','mode':'manual'};self.note('Original game restored; PAK outputs and archives retained')
  print('RECOVERED. Original game is back at '+str(self.game),flush=True)

 def plan_cleanup(self,archive):
  # Capture exact files, never recursively delete a user-selected work folder.
  targets={};dirs=set();protected=set();records=self.d.get('history',[])+([self.d['pending_checkpoint']] if self.d.get('pending_checkpoint') else [])
  generated=set(self.d.get('cleanup_owned_files',[]))
  for record in records:generated.update(record.get('artifacts',[]))
  for record in records:protected.update(set(record.get('restore_files',{}))-generated)
  def add(path,tree=False):
   path=Path(path).absolute()
   if path==self.path or path.is_symlink() or contained(path,self.game) or contained(self.game,path):return
   if str(path) in protected:return
   if path.is_file():
    st=path.stat();targets[str(path)]={'size':st.st_size,'mtime_ns':st.st_mtime_ns};dirs.add(str(path.parent))
   elif path.is_dir():
    dirs.add(str(path))
    if tree:
     for f in path.rglob('*'):
      if f.is_symlink():continue
      if f.is_file():add(f)
      elif f.is_dir():dirs.add(str(f))
  # Restore imported profile files to their earliest captured version.
  restores={}
  for record in records:
   for dest,src in record.get('restore_files',{}).items():
    if dest not in generated:restores.setdefault(dest,src)
  for dest,src in restores.items():byte_copy(src,dest)
  for record in records:
   for name in record.get('artifacts',[]):add(name)
  for run in self.d.get('recordings',[]):
   for name in ['ampr_commands.bin','ampr_emu.index','ampr_emu.log']:add(Path(run)/name)
   add(run)
  for name in self.d.get('cleanup_owned_files',[]):add(name)
  for name in self.d.get('build_run',{}).get('published',[]):add(name)
  def generated_game(path):
   path=Path(path)
   known=set(self.d['original_files'])|set(self.d.get('receipt',{}).get('files',{}))|set(CONTROL)|set(self.d.get('created_files',[]))|{'.ampr-project-id'}
   if path.is_dir():
    add(path)
    for f in path.rglob('*'):
     if f.is_dir():add(f)
     elif f.relative_to(path).as_posix() in known:add(f)
  # These locations are private, journalled transaction folders, not user roots.
  for key in ['discard_pak_game','publication_stage','stage','hold']:
   value=self.d.get(key)
   if value:
    path=Path(value)
    owned=(path.name.startswith('.'+self.game.name+'.ampr-') or (key=='stage' and path==Path(self.d['paths']['output'])/self.game.name))
    if owned:generated_game(path)
  for value in self.d.get('retained_partial_folders',[]):
   path=Path(value)
   if path.name.startswith('.'+self.game.name+'.ampr-') or path.name.startswith(self.game.name+'.incomplete-'):generated_game(path)
  buildstage=self.d.get('build_run',{}).get('stage')
  if buildstage and Path(buildstage).name.startswith('.ampr-building-'):add(buildstage,True)
  # Any remaining backup is redundant only now that the original is restored.
  if self.d.get('backup'):
   backup=Path(self.d['backup'])
   if backup.exists():validate_inventory(backup,self.d['original_files'],True);add(backup,True)
  add(archive,True)
  if self.store==self.work/'.ampr-projects'/self.d['id']:add(self.store,True)
  for name in list(dirs):
   parent=Path(name).parent
   if parent!=self.work and contained(parent,self.work):dirs.add(str(parent))
  self.d['cleanup_plan']={'files':targets,'dirs':sorted(dirs,key=lambda x:len(Path(x).parts),reverse=True),'preserved':[]};self.save()
 def finish_cleanup(self):
  # Resume cleanup after interruption without depending on already removed controls.
  validate_inventory(self.game,self.d['original_files'],True)
  plan=self.d['cleanup_plan'];preserved=[]
  for name,v in plan['files'].items():
   path=Path(name)
   if path.is_symlink():preserved.append(name);continue
   if path.exists():
    st=path.stat()
    if st.st_size!=v['size'] or st.st_mtime_ns!=v['mtime_ns']:preserved.append(name);continue
    path.unlink()
  for name in plan['dirs']:
   path=Path(name)
   if path==self.work or path==self.game or path.is_symlink():continue
   try:path.rmdir()
   except (OSError,FileNotFoundError):pass
  keep={k:self.d[k] for k in ['schema','id','name','project_file','game','work','store','created']}
  self.d={**keep,'phase':'recovered','running':None,'transaction':None,'completed':[], 'paths':{'trace':'','toml':'','output':'','index':''},'original_files':{},'controls':{},'created_files':[],'created_dirs':[],'events':[], 'history':[], 'guide':{'step':'game','mode':'manual'},'recovery_policy':'restore-and-clean','preserved_changed_files':preserved}
  self.note('Original restored. Project-generated files and progress removed. Start a new project.')
  if preserved:print('Files changed since cleanup planning were preserved: '+', '.join(preserved),flush=True)
  print('RECOVERED. Original game restored. Project reset; no PAK archive was created.',flush=True)

 def checkpoint(self,key,controls=False):
  import copy
  if self.d.get('pending_checkpoint'):return
  folder=self.store/'steps'/uuid.uuid4().hex;folder.mkdir(parents=True)
  record={'step':key,'folder':str(folder),'before':copy.deepcopy({k:v for k,v in self.d.items() if k not in {'history','pending_checkpoint','original_files'}}),'controls':{},'artifacts':[]}
  if controls:
   for rel in dict.fromkeys(CONTROL+self.d.get('created_files',[])):
    path=self.game/rel
    if path.is_file():
     byte_copy(path,folder/'files'/rel);record['controls'][rel]=True
    else:record['controls'][rel]=False
  # Do not recursively embed old snapshots in the new snapshot.
  record['before'].pop('history',None);record['before'].pop('pending_checkpoint',None)
  if key=='generate':
   toml=Path(self.d['paths']['toml'])
   for file in [toml,toml.with_suffix('.report.md'),toml.with_suffix('.metrics.json')]:
    if file.is_file():
     saved=folder/'profile'/file.name;byte_copy(file,saved);record.setdefault('restore_files',{})[str(file)]=str(saved)
    else:record['artifacts'].append(str(file))
  self.d['pending_checkpoint']=record;self.save()
 def track(self,path):
  if self.d.get('pending_checkpoint'):
   self.d['pending_checkpoint']['artifacts'].append(str(Path(path).resolve()));self.save()
 def commit_step(self,next_step=None):
  item=self.d.pop('pending_checkpoint',None)
  if item:self.d.setdefault('history',[]).append(item)
  if next_step:self.d.setdefault('guide',{})['step']=next_step
  self.d['running']=None;self.save()
 def undo_step(self):
  record=self.d.get('pending_checkpoint')
  pending=bool(record)
  if not record:
   history=self.d.get('history',[])
   if not history:raise ValueError('There is no completed step to undo.')
   record=history[-1]
  saved_history=self.d.get('history',[]);original_files=self.d['original_files']
  if self.d['phase']=='complete' or self.d.get('transaction'):
   partial=Path(self.d['stage']) if self.d.get('stage') else None
   self.recover()
   recovered=self.d.get('recovered_pak_game')
   if recovered and self.d.get('pak_moves'):
    for item in self.d['pak_moves']:item['destination']=str(Path(recovered)/Path(item['destination']).name)
    self.return_moved_paks()
   if partial and partial.exists() and partial.parent==self.game.parent and partial.name.startswith('.'+self.game.name+'.ampr-new-'):shutil.rmtree(partial)
  # Remove only generated artifacts explicitly recorded by this operation.
  for name in reversed(record.get('artifacts',[])):
   path=Path(name)
   if contained(path,self.game):raise ValueError('Refusing to delete game files as generated output.')
   if path.is_dir():
    try:path.rmdir()
    except OSError:pass  # Other data in a directory is retained.
   elif path.is_file():path.unlink()
  for dest,source in record.get('restore_files',{}).items():byte_copy(source,dest)
  before=record['before']
  for rel,exists in record.get('controls',{}).items():
   target=self.game/rel
   if exists:byte_copy(Path(record['folder'])/'files'/rel,target)
   elif target.is_file():target.unlink()
  for rel in set(self.d.get('created_files',[]))-set(before.get('created_files',[])):
   target=self.game/rel
   if target.is_file():target.unlink()
  for rel in reversed(self.d.get('created_dirs',[])):
   if rel not in before.get('created_dirs',[]):
    try:(self.game/rel).rmdir()
    except OSError:pass
  history=saved_history
  before['original_files']=original_files
  if not pending:history=history[:-1]
  self.d=before;self.d['history']=history;self.d['running']=None
  self.d.setdefault('guide',{})['step']=record['step'];self.save()
  print('Previous step restored. Original assets were not removed.',flush=True)
 def generate_profile(self):
  import ampr_pack_profile as profiler
  from ampr_pack_gui import build_profile_command
  original_write=profiler._write_text
  def write(path,text,overwrite):
   path=Path(path).resolve()
   if contained(path,self.game):raise ValueError('Profile outputs must stay outside the game.')
   record=self.d.get('pending_checkpoint')
   if record:
    if path.is_file() and str(path) not in record.get('restore_files',{}):
     saved=Path(record['folder'])/'profile'/path.name;byte_copy(path,saved);record.setdefault('restore_files',{})[str(path)]=str(saved);self.save()
    elif not path.exists():self.track(path)
    self.track(path.with_name(f'.{path.name}.tmp-{os.getpid()}'))
   original_write(path,text,overwrite)
  profiler._write_text=write
  try:
   args=build_profile_command(Path(self.d['paths']['trace']),Path(self.d['paths']['toml']))[2:]
   if profiler.main(args)!=0:raise ValueError('Profile generation did not finish.')
  finally:profiler._write_text=original_write
 def build_paks(self):
  from ampr_pack import main as pack_main
  out=Path(self.d['paths']['output']).resolve()
  if contained(out,self.game) or contained(self.game,out):raise ValueError('Choose a separate PAK output folder outside the game.')
  out.mkdir(parents=True,exist_ok=True)
  if any(p.name not in {'.DS_Store'} and not p.name.startswith('._') for p in out.iterdir()):raise ValueError('PAK output must be empty. Choose another folder or undo this project’s previous build.')
  stage=out.parent/('.ampr-building-'+uuid.uuid4().hex)
  self.d['build_run']={'stage':str(stage),'output':str(out),'published':[]};self.save()
  stage.mkdir()
  result=pack_main(['pack','--root',str(self.game),'--ampr-index',str(self.index_path),'--output',str(stage),'--config',self.d['paths']['toml']])
  if result!=0:raise ValueError('PAK build did not complete.')
  self.d['build_run']['pack_finished']=True;self.save()
  self.publish_build()
 def can_resume_publication(self):
  run=self.d.get('build_run') or {}
  if not run or run.get('finished'):return False
  try:
   cfg=tomllib.loads(Path(self.d['paths']['toml']).read_text())
   name=cfg.get('pack',{}).get('index_name','ampr_assets.index')
   return (Path(run['stage'])/name).is_file() or (Path(run['output'])/name).is_file()
  except (OSError,KeyError,ValueError):return False
 def publish_build(self):
  from ampr_pack_format import load_manifest
  run=self.d.get('build_run') or {}
  if not run:raise ValueError('No saved build to resume.')
  stage=Path(run['stage']);out=Path(run['output'])
  if stage.parent!=out.parent or not stage.name.startswith('.ampr-building-'):raise ValueError('Invalid build staging record.')
  if out.resolve()!=Path(self.d['paths']['output']).resolve():raise ValueError('Output path changed since the build.')
  cfg=tomllib.loads(Path(self.d['paths']['toml']).read_text());name=cfg.get('pack',{}).get('index_name','ampr_assets.index')
  if Path(name).name!=name:raise ValueError('The app requires an index filename without subfolders.')
  index=stage/name if (stage/name).is_file() else out/name
  manifest=load_manifest(index)
  expected={manifest.pack_name(i):rec.file_size for i,rec in enumerate(manifest.packs)}
  expected.update({name:None,name+'.crc':None})
  if cfg.get('runtime'):expected[name+'.runtime']=None
  published=set(run.get('published',[]));inventory={}
  # Preflight the complete split set before moving anything. The manifest gives
  # PAK sizes, so a truncated file cannot be accepted as a completed build.
  for filename,size in expected.items():
   if Path(filename).name!=filename:raise ValueError('Unexpected nested PAK filename: '+filename)
   source=stage/filename;dest=out/filename
   if source.exists() and dest.exists():raise ValueError('Both output locations contain '+filename+'. Nothing overwritten.')
   if dest.exists() and str(dest) not in published:raise ValueError('Untracked existing output: '+str(dest))
   actual=source if source.exists() else dest
   if actual.is_symlink() or not actual.is_file():raise ValueError('Build output file missing: '+filename)
   stat=actual.stat()
   if size is not None and stat.st_size!=size:raise ValueError('Incomplete PAK file: '+filename)
   inventory[filename]={'size':stat.st_size,'mtime_ns':stat.st_mtime_ns}
  if stage.exists():
   for path in list(stage.iterdir()):
    if path.name.startswith('._') or path.name=='.DS_Store':continue
    if path.name not in expected:raise ValueError('Unexpected build output entry: '+str(path))
  run['publication_inventory']=inventory;run['pack_finished']=True;self.save()
  progress=Progress('Publishing PAK files',len(expected))
  for filename in expected:
   source=stage/filename;dest=out/filename
   if source.is_file():
    if str(dest) not in run['published']:run['published'].append(str(dest))
    self.save();self.track(dest)
    source.rename(dest)
   progress(1)
  # macOS may move AppleDouble sidecars with their main file. Never enumerate
  # and move those sidecars as independent PAK outputs.
  if stage.exists():
   for path in list(stage.iterdir()):
    if (path.name.startswith('._') or path.name=='.DS_Store') and path.is_file() and not path.is_symlink():path.unlink(missing_ok=True)
   stage.rmdir()
  run['finished']=True;self.d['phase']='built';self.save()
  print('PAK output ready. Existing PAKs reused; no repacking was needed for publication.',flush=True)
 def cleanup_build(self):
  run=self.d.get('build_run')
  if not run:return
  # The private staging folder is created only by build_paks for this project.
  stage=Path(run['stage']);out=Path(run['output'])
  if stage.parent!=out.parent or not stage.name.startswith('.ampr-building-'):raise ValueError('Invalid build staging record.')
  if stage.exists():shutil.rmtree(stage)
  for name in run.get('published',[]):
   target=Path(name)
   if target.parent!=out:raise ValueError('Invalid generated file record.')
   if target.is_file():target.unlink()
  self.d.pop('build_run',None);self.d.pop('receipt',None);self.d['running']=None;self.d['phase']='prepared';self.save()
  print('Files created by the cancelled build were removed. The build can be restarted.',flush=True)

def main(args=None):
 p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','index','archive','profile-check','stamp','skip-verify','complete','recover','emulator','build','publish-build','cleanup-build','undo','generate']);p.add_argument('--project',required=True);p.add_argument('--runtime');a=p.parse_args(args)
 project=Project(a.project);project.d['running']=a.action;project.save()
 try:
  if a.action in {'prepare','index'}:project.prepare(a.runtime,a.action=='index')
  elif a.action=='emulator':project.prepare(a.runtime,emulator_only=True)
  elif a.action=='generate':project.generate_profile()
  elif a.action=='build':project.build_paks()
  elif a.action=='publish-build':project.publish_build()
  elif a.action=='cleanup-build':project.cleanup_build()
  elif a.action=='undo':project.undo_step()
  elif a.action=='skip-verify':project.stamp(False)
  elif a.action=='archive':project.archive()
  elif a.action=='profile-check':project.check_profile()
  elif a.action=='stamp':project.stamp()
  elif a.action=='complete':project.complete(a.runtime)
  elif a.action=='recover':project.recover(clean=True)
  project.d['running']=None;project.d.pop('last_error',None);project.save();return 0
 except Exception as e:
  project.d['last_error']=str(e);project.save();print('ERROR: '+str(e),flush=True);return 2
if __name__=='__main__':raise SystemExit(main())
