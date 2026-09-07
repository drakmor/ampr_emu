"""Mac front end: persistent guided workflow and independent manual controls."""
from pathlib import Path
import sys,os,json,threading,queue,subprocess,re,uuid,multiprocessing

def command(tool,*args):
 if getattr(sys,'frozen',False):return [sys.executable,'--internal-'+tool,*map(str,args)]
 script={'pack':'ampr_pack.py','profile':'ampr_pack_profile.py','project':'ampr_project.py'}[tool]
 return [sys.executable,str(Path(__file__).parent/script),*map(str,args)]

def gui():
 import tkinter as tk
 from tkinter import ttk,filedialog,simpledialog
 from tkinter.scrolledtext import ScrolledText
 from ampr_project import Project,create,contained
 from ampr_emulators import candidates,inspect,digest,emu_directory
 from ampr_pack_gui import build_profile_command,load_profile_coverage,apply_manual_coverage

 class App(tk.Tk):
  def __init__(self):
   super().__init__();self.title('AMPR PAK Tools');self.geometry('1350x900');self.minsize(1060,720)
   self.project=None;self.busy=False;self.process=None;self.events=queue.Queue();self.buttons=[];self.fields={};self.mode='manual';self.loaded_base=None;self.cancelled=False;self.progress_window=None;self.run_id=None;self.pending_guide='game';self.extra_emus=[];self.emus={}
   self.status=tk.StringVar(value='Choose Auto Guide, or use the manual controls.');self.step=tk.StringVar(value='No project open');self.follow=tk.BooleanVar(value=True);self.reviewed=tk.BooleanVar(value=False);self.percent=tk.DoubleVar(value=0)
   self.popup_position=None;self.log_dragging=False;self.log_scroll_job=None
   style=ttk.Style(self);style.configure('Toolbar.TButton',font=('Helvetica',13,'bold'),padding=(12,9));style.configure('Guide.Toolbar.TButton',font=('Helvetica',13,'bold'),padding=(12,9),foreground='#278b9a')
   top=ttk.Frame(self,padding=(12,12));top.pack(fill='x')
   for label,fn in [('Auto Guide',self.start_guide),('Continue',self.continue_work),('New Project',self.new_project),('Open Project',self.open_project),('Save Project',lambda:self.save(True)),('Emulator files…',self.manage_emus)]:
    button=self.button(top,label,fn);button.configure(style='Guide.Toolbar.TButton' if label in ('Auto Guide','Continue') else 'Toolbar.TButton');button.pack(side='left',padx=4)
   ttk.Separator(self,orient='horizontal').pack(fill='x',padx=14,pady=(0,5))
   ttk.Label(self,textvariable=self.step,padding=(14,2),wraplength=1260).pack(fill='x')
   panes=ttk.Panedwindow(self,orient='horizontal');panes.pack(fill='both',expand=True,padx=10,pady=8)
   left=ttk.Frame(panes);right=ttk.Frame(panes,padding=8);panes.add(left,weight=3);panes.add(right,weight=2)
   canvas=tk.Canvas(left,highlightthickness=0);scroll=ttk.Scrollbar(left,orient='vertical',command=canvas.yview);canvas.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');canvas.pack(fill='both',expand=True)
   form=ttk.Frame(canvas,padding=8);win=canvas.create_window((0,0),window=form,anchor='nw');form.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')));canvas.bind('<Configure>',lambda e:canvas.itemconfigure(win,width=e.width))
   paths=ttk.LabelFrame(form,text='Manual controls - choose files and folders',padding=8);paths.pack(fill='x',pady=5);paths.columnconfigure(1,weight=1)
   for row,(key,label) in enumerate([('game','Game folder'),('index','ampr_emu.index'),('trace','Trace directory'),('toml','TOML profile'),('output','PAK output directory')]):
    ttk.Label(paths,text=label).grid(row=row,column=0,sticky='w',pady=4);self.fields[key]=tk.StringVar()
    entry=ttk.Entry(paths,textvariable=self.fields[key]);entry.grid(row=row,column=1,sticky='ew',padx=5);self.install_path_selection(entry)
    self.button(paths,'Browse…',lambda k=key:self.browse(k)).grid(row=row,column=2)
   maintenance=ttk.LabelFrame(form,text='Emulator and index - separate actions',padding=8);maintenance.pack(fill='x',pady=5)
   for label,fn in [('Update emulator only…',lambda:self.maintenance('emulator')),('Create / rebuild index…',lambda:self.maintenance('index')),('Set up both…',lambda:self.maintenance('prepare')),('Save recording',self.manual_archive)]:self.button(maintenance,label,fn).pack(fill='x',pady=3)
   profile=ttk.LabelFrame(form,text='PAK profile',padding=8);profile.pack(fill='x',pady=5)
   self.button(profile,'Generate profile from traces',self.manual_generate).pack(fill='x',pady=3)
   self.button(profile,'Load from profile',lambda:self.load_profile(False)).pack(fill='x',pady=3)
   self.patterns=tk.Listbox(profile,height=6,selectmode='extended');self.patterns.pack(fill='x',pady=4)
   row=ttk.Frame(profile);row.pack(fill='x')
   for label,fn in [('Add files…',self.add_files),('Remove selected',self.remove_patterns),('Save selection',self.save_selection)]:self.button(row,label,fn).pack(side='left',padx=3)
   self.button(profile,'Check profile',self.manual_check).pack(fill='x',pady=3)
   ttk.Label(profile,text='Unselected files are copied into the finished game as loose files.',wraplength=530).pack(fill='x',pady=5)
   ttk.Checkbutton(profile,text='I understand. Keep unselected files loose.',variable=self.reviewed).pack(anchor='w')
   actions=ttk.LabelFrame(form,text='Build and finish',padding=8);actions.pack(fill='x',pady=5)
   for label,fn in [('Create PAKs and verify',self.manual_build),('Verify existing PAKs',self.manual_verify),('Finish PAK game…',self.manual_finish),('Recover original game…',self.request_recovery)]:self.button(actions,label,fn).pack(fill='x',pady=3)
   ttk.Label(right,text='Progress / manual log',font=('Helvetica',16,'bold')).pack(anchor='w')
   ttk.Label(right,textvariable=self.status,wraplength=450).pack(fill='x',pady=8)
   progressrow=ttk.Frame(right);progressrow.pack(fill='x');ttk.Progressbar(progressrow,variable=self.percent,maximum=100).pack(side='left',fill='x',expand=True)
   self.stop=ttk.Button(progressrow,text='Stop…',command=lambda:self.guard(self.request_stop),state='disabled');self.stop.pack(side='right',padx=(8,0))
   self.log=ScrolledText(right,wrap='word',font=('Menlo',11),state='disabled',width=49);self.log.pack(fill='both',expand=True,pady=6)
   self.install_log_selection()
   ttk.Checkbutton(right,text='Follow latest messages',variable=self.follow).pack(anchor='w')
   def wheel(e):
    widget=e.widget
    while widget is not None:
     if widget in (form,canvas):canvas.yview_scroll(int(-e.delta),'units');return
     widget=getattr(widget,'master',None)
   self.bind_all('<MouseWheel>',wheel,add='+');self.bind('<Command-o>',lambda e:self.guard(self.open_project));self.bind('<Command-s>',lambda e:self.guard(lambda:self.save(True)))
   self.install_help_menu()
   self.protocol('WM_DELETE_WINDOW',self.close);self.after(100,self.poll)

  def install_help_menu(self):
   bar=tk.Menu(self);help_menu=tk.Menu(bar,name='help',tearoff=False)
   help_menu.add_command(label='AMPR PAK Tools Help',command=lambda:self.guard(self.help_index))
   help_menu.add_separator()
   for label,filename in [('User Guide - Deutsch','USER_GUIDE_DE.pdf'),('User Guide - English','USER_GUIDE_EN.pdf'),('User Guide - Русский (original guide)','UPSTREAM_USER_GUIDE_RU.pdf')]:
    help_menu.add_command(label=label,command=lambda n=filename:self.guard(lambda:self.open_help_file(n)))
   help_menu.add_separator()
   help_menu.add_command(label='About & Credits',command=lambda:self.guard(self.show_credits))
   help_menu.add_command(label='License (GPLv3)',command=lambda:self.guard(lambda:self.open_help_file('LICENSE-GPL-3.0.txt')))
   bar.add_cascade(label='Help',menu=help_menu);self.configure(menu=bar);self.help_bar=bar
   if sys.platform=='darwin':self.createcommand('tk::mac::ShowHelp',lambda:self.guard(self.help_index))
  def open_help_file(self,filename):
   root=Path(sys._MEIPASS)/'help-resources' if getattr(sys,'frozen',False) else Path(__file__).resolve().parent/'macos'/'help-resources'
   path=root/filename
   if not path.is_file():raise ValueError('Help file is missing: '+filename)
   subprocess.run(['/usr/bin/open',str(path)],check=True,capture_output=True)
  def help_index(self):
   choice=self.dialog('AMPR PAK Tools Help','Choose a PDF user guide. The Russian PDF is the original upstream guide; the English and German PDFs describe this Mac version.',('Deutsch','English','Русский','Close'))
   name={'Deutsch':'USER_GUIDE_DE.pdf','English':'USER_GUIDE_EN.pdf','Русский':'UPSTREAM_USER_GUIDE_RU.pdf'}.get(choice)
   if name:self.open_help_file(name)
  def show_credits(self):
   self.notice('About & Credits','AMPR PAK Tools - macOS community port\n\nOriginal AMPR emulator and PAK tools by Drakmor.\nmacOS port, Auto Guide and UI enhancements by Shambhala222.\n\nOriginal project: github.com/drakmor/ampr_emu\n\nModified macOS version. GNU GPLv3; redistribution is permitted under its terms. No warranty. See Help > License. LZ4 retains its separate license.')

  def place_popup(self,window):
   window.update_idletasks()
   width=max(window.winfo_reqwidth(),window.winfo_width());height=max(window.winfo_reqheight(),window.winfo_height())
   position=self.popup_position
   if position is None:position=((self.winfo_screenwidth()-width)//2,(self.winfo_screenheight()-height)//2)
   window.geometry(f'{position[0]:+d}{position[1]:+d}')
   def remember(event):
    if event.widget!=window or not window.winfo_ismapped():return
    # Use WM geometry for both reading and writing. Root/content coordinates
    # include title-bar offsets and cause diagonal drift between windows.
    match=re.search(r'([+-]\d+)([+-]\d+)$',window.geometry())
    if match:self.popup_position=(int(match.group(1)),int(match.group(2)))
   window.bind('<Configure>',remember,add='+')
   window.deiconify();window.lift()
  def install_path_selection(self,entry):
   state={'dragging':False,'job':None,'anchor':0}
   def stop(event=None):
    state['dragging']=False
    if state['job'] is not None:self.after_cancel(state['job']);state['job']=None
   def start(event):
    stop();state['dragging']=True;state['anchor']=entry.index(f'@{event.x}')
   def tick():
    state['job']=None
    if not state['dragging'] or not entry.winfo_exists():return
    x=entry.winfo_pointerx()-entry.winfo_rootx();width=entry.winfo_width()
    if x<0:entry.xview_scroll(-1,'units')
    elif x>=width:entry.xview_scroll(1,'units')
    end=entry.index(f'@{max(0,min(x,width-1))}')
    anchor=min(state['anchor'],len(entry.get()))
    entry.selection_range(min(anchor,end),max(anchor,end))
    entry.icursor(end);state['job']=self.after(45,tick)
   def drag(event):
    if state['job'] is None:tick()
    return 'break'
   entry.bind('<Button-1>',start,add='+');entry.bind('<B1-Motion>',drag)
   entry.bind('<ButtonRelease-1>',stop,add='+');entry.bind('<Destroy>',stop,add='+')

  def install_log_selection(self):
   log=self.log
   def copy(event=None):
    try:text=log.get('sel.first','sel.last')
    except tk.TclError:return 'break'
    self.clipboard_clear();self.clipboard_append(text);return 'break'
   def select_all():
    self.follow.set(False);log.tag_add('sel','1.0','end-1c');return 'break'
   menu=tk.Menu(log,tearoff=False)
   menu.add_command(label='Copy',command=copy,accelerator='⌘C');menu.add_command(label='Select All',command=select_all,accelerator='⌘A')
   def context(event):
    self.stop_log_drag()
    menu.entryconfigure(0,state='normal' if log.tag_ranges('sel') else 'disabled')
    try:menu.tk_popup(event.x_root,event.y_root)
    finally:menu.grab_release()
    return 'break'
   def start(event):
    self.stop_log_drag();self.log_dragging=True;self.log_anchor=log.index(f'@{event.x},{event.y}')
   def drag(event):
    self.follow.set(False)
    if self.log_scroll_job is None:self.scroll_log_selection()
    return 'break'
   log.bind('<Button-1>',start,add='+');log.bind('<B1-Motion>',drag)
   log.bind('<ButtonRelease-1>',lambda event:self.stop_log_drag(),add='+')
   for binding in ['<Button-2>','<Button-3>','<Control-Button-1>']:log.bind(binding,context)
   for binding in ['<Command-c>','<Control-c>']:log.bind(binding,copy)
   log.bind('<Command-a>',lambda event:select_all());log.bind('<Control-a>',lambda event:select_all())
  def stop_log_drag(self):
   self.log_dragging=False
   if self.log_scroll_job is not None:self.after_cancel(self.log_scroll_job);self.log_scroll_job=None
  def scroll_log_selection(self):
   self.log_scroll_job=None
   if not self.log_dragging:return
   log=self.log;x=log.winfo_pointerx()-log.winfo_rootx();y=log.winfo_pointery()-log.winfo_rooty();height=log.winfo_height()
   if y<0:log.yview_scroll(-1,'units')
   elif y>=height:log.yview_scroll(1,'units')
   point=log.index(f'@{max(0,min(x,log.winfo_width()-1))},{max(0,min(y,height-1))}')
   log.tag_remove('sel','1.0','end')
   start,end=(point,self.log_anchor) if log.compare(point,'<',self.log_anchor) else (self.log_anchor,point)
   log.tag_add('sel',start,end)
   self.log_scroll_job=self.after(60,self.scroll_log_selection)

  def button(self,parent,label,fn):
   button=ttk.Button(parent,text=label,command=lambda:self.guard(fn));self.buttons.append(button);return button
  def guard(self,fn):
   try:return fn()
   except Exception as error:self.notice('Cannot continue',str(error))
  def dialog(self,title,text,choices=('OK','Close'),important=None,checkbox=None,countdown=None):
   window=tk.Toplevel(self);window.withdraw();window.title(title);window.transient(self);window.resizable(False,False)
   body=ttk.Frame(window,padding=22);body.pack(fill='both',expand=True)
   ttk.Label(body,text=title,font=('Helvetica',17,'bold'),wraplength=610).pack(anchor='w',pady=(0,12))
   if important:ttk.Label(body,text=important,font=('Helvetica',13,'bold'),wraplength=610,justify='left').pack(anchor='w',pady=(0,12))
   if text:ttk.Label(body,text=text,wraplength=610,justify='left').pack(anchor='w')
   tick=tk.BooleanVar(value=False)
   if checkbox:ttk.Checkbutton(body,text=checkbox,variable=tick).pack(anchor='w',pady=12)
   countdown_text=tk.StringVar();remaining=[countdown or 0]
   if countdown:ttk.Label(body,textvariable=countdown_text,font=('Helvetica',16,'bold')).pack(anchor='w',pady=14)
   row=ttk.Frame(body);row.pack(fill='x',pady=(20,0));answer=[None]
   def choose(value):answer[0]=value;window.destroy()
   for label in choices:
    b=ttk.Button(row,text=label,command=lambda v=label:choose(v));b.pack(side='left',padx=(0,8))
    if checkbox and label.startswith('Accept'):
     b.configure(state='disabled');tick.trace_add('write',lambda *_,button=b:button.configure(state='normal' if tick.get() else 'disabled'))
   def clock():
    if not window.winfo_exists():return
    countdown_text.set(f'Starting in {remaining[0]} seconds…')
    if remaining[0]<=0:choose('elapsed');return
    remaining[0]-=1;window.after(1000,clock)
   window.protocol('WM_DELETE_WINDOW',lambda:choose(None));self.place_popup(window);window.grab_set()
   if countdown:clock()
   self.wait_window(window);return answer[0]
  def notice(self,title,text):return self.dialog(title,text,('OK',))
  def warning_delay(self,title,text):
   if self.dialog(title,text,('Yes','No'))!='Yes':return False
   return self.dialog(title,text+'\n\nYou can still cancel. Nothing will be changed during this countdown.',('Cancel',),countdown=10)=='elapsed'
  def base_location(self):
   parts=Path(self.fields['game'].get()).parts
   return Path('/Volumes')/parts[2] if len(parts)>2 and parts[1]=='Volumes' else Path.home()
  def choose_dir(self,title,initial=None,new=False):return filedialog.askdirectory(parent=self,title=title,initialdir=str(initial or Path.home()),mustexist=not new)
  def save(self,show=False):
   if not self.project:return
   if self.busy:raise ValueError('The current operation saves its own progress. Wait before changing the project.')
   self.project=Project(self.project.path)
   entered=Path(self.fields['game'].get()).expanduser().resolve()
   if entered!=self.project.game:raise ValueError('This game differs from the open project. Use New Project to select another game.')
   for key in ('index','trace','toml','output'):self.project.d['paths'][key]=self.fields[key].get()
   self.project.d['emulators']=self.emus;self.project.d['accepted_loose']=self.reviewed.get();self.project.save()
   if show:self.notice('Project saved','Keep this project and its related files at their current locations for recovery.\n\n'+str(self.project.path))
  def refresh(self):
   if not self.project:return
   self.project=Project(self.project.path);d=self.project.d;self.fields['game'].set(d['game'])
   for key in ('index','trace','toml','output'):self.fields[key].set(d['paths'].get(key,'') or (str(self.project.game/'ampr_emu.index') if key=='index' else ''))
   self.emus=d.get('emulators',{});self.reviewed.set(d.get('accepted_loose',False));g=d.get('guide') or {}
   self.step.set(d['name']+' | '+d['phase']+' | Continue: '+(g.get('step') or d.get('resume_action') or ('finished' if d.get('phase')=='complete' else 'manual controls')))
  def new_project(self):
   if self.busy:return
   if self.project:self.save()
   self.project=None;self.mode='manual';self.emus={};self.loaded_base=None;self.reviewed.set(False)
   for v in self.fields.values():v.set('')
   self.stop_log_drag();self.patterns.delete(0,'end')
   self.log.configure(state='normal');self.log.delete('1.0','end');self.log.configure(state='disabled')
   self.percent.set(0);self.follow.set(True);self.cancelled=False;self.run_id=None;self.process=None;self.extra_emus=[]
   self.active_action=None;self.active_next=None;self.resume_after_cancel=None
   self.stop.configure(state='disabled')
   if self.progress_window is not None:
    if self.progress_window.winfo_exists():self.progress_window.destroy()
    self.progress_window=None
   self.status.set('Choose Auto Guide, or use the manual controls.')
   self.step.set('No project open');self.pending_guide='game'
  def ensure_project(self):
   if self.project:self.save();return True
   if not self.fields['game'].get():
    game=self.choose_dir('Select the game folder')
    if not game:return False
    self.fields['game'].set(game)
   work=self.choose_dir('Choose a working folder outside the game',self.base_location(),True)
   if not work:return False
   values={k:v.get() for k,v in self.fields.items()};self.project=Project(create(values['game'],work));self.project.d['emulators']=self.emus;self.project.d['paths'].update({k:values[k] for k in ('index','trace','toml','output')});self.project.save();self.refresh();return True
  def open_project(self):
   if self.busy:return
   path=filedialog.askopenfilename(parent=self,title='Open Project',filetypes=[('AMPR Project','*.json')])
   if not path:return
   if self.project:self.save()
   self.project=Project(path);self.refresh();self.mode='manual'
   issues=self.project.issues()
   if issues:self.notice('Project needs attention','\n\n'.join(issues))
   else:self.status.set('Project opened. Click Continue to resume the saved step.')
  def browse(self,key):
   if self.busy:return
   self.mode='manual'
   if key=='game':
    path=self.choose_dir('Select the game folder')
    if path and self.project and Path(path).resolve()!=self.project.game:raise ValueError('Use New Project to switch to a different game. Your current project is saved.')
   elif key=='index':path=filedialog.askopenfilename(parent=self,title='Select the matching ampr_emu.index')
   elif key=='toml':
    choice=self.dialog('TOML profile','Open an existing TOML, or choose a filename for a new one.',('Open existing','New file','Close'))
    if choice=='Open existing':path=filedialog.askopenfilename(parent=self,title='Open TOML',filetypes=[('TOML','*.toml')])
    elif choice=='New file':path=filedialog.asksaveasfilename(parent=self,title='New TOML filename',defaultextension='.toml',initialdir=str(self.project.work if self.project else Path.home()))
    else:return
   else:path=self.choose_dir('Choose '+('recording archive' if key=='trace' else 'PAK output folder'),self.project.work if self.project else None,key=='output')
   if path:
    self.fields[key].set(path)
    if key=='game' and not self.fields['index'].get():self.fields['index'].set(str(Path(path)/'ampr_emu.index'))
    if self.project:self.save()
  def checkpoint(self,key,controls=False):
   self.save();self.project=Project(self.project.path);self.project.checkpoint(key,controls)
  def advance(self,next_step):
   self.project=Project(self.project.path);self.project.commit_step(next_step);self.refresh()
  def choose_runtime(self,role,force=False):
   if not force and role in self.emus:
    entry=self.emus[role]
    if Path(entry['path']).is_file() and digest(entry['path'])==entry['sha256']:return entry['path']
   options=candidates(self.extra_emus)
   if not force:
    match=next((x for x in options if x['pack'] is True and x['record']==(role=='recording')),None) if role in ('recording','pak') else None
    if match and match['confirmed']:self.emus[role]=match;self.save();return match['path']
   window=tk.Toplevel(self);window.withdraw();window.title('Choose EMU file - '+role);window.transient(self);window.geometry('850x430')
   frame=ttk.Frame(window,padding=16);frame.pack(fill='both',expand=True)
   ttk.Label(frame,text='Choose a file. Names are hints; unknown capabilities must be confirmed.',wraplength=800).pack(anchor='w',pady=8)
   listing=tk.Listbox(frame);listing.pack(fill='both',expand=True)
   for item in options:listing.insert('end',item['name']+' | PAK: '+str(item['pack'])+' | Recording: '+str(item['record']))
   picked=[None]
   def take():
    selection=listing.curselection()
    if selection:picked[0]=options[selection[0]];window.destroy()
   def browse():
    path=filedialog.askopenfilename(parent=window,title='Select libSceAmpr.sprx version')
    if path:self.extra_emus.append(path);picked[0]=inspect(path);window.destroy()
   row=ttk.Frame(frame);row.pack(fill='x',pady=8)
   for label,fn in [('Use selected',take),('Browse…',browse),('Close',window.destroy)]:ttk.Button(row,text=label,command=fn).pack(side='left',padx=4)
   self.place_popup(window);window.grab_set();self.wait_window(window);entry=picked[0]
   if not entry:return None
   if not entry.get('confirmed'):
    note='File: '+entry['name']+'\n\nConfirm its capabilities from the release information. A version number alone cannot identify them.'
    pack=self.dialog('PAK support',note+'\n\nDoes it support PAK files?',('Yes','No','Close'))
    if pack not in ('Yes','No'):return None
    rec=self.dialog('Recording enabled?',note+'\n\nDoes this version record commands / debug traces?',('Yes','No','Close'))
    if rec not in ('Yes','No'):return None
    entry.update(pack=pack=='Yes',record=rec=='Yes',confirmed=True)
    if entry['pack']:
     pool=simpledialog.askinteger('Runtime pool','Memory pool size in MiB, as documented for this version (the bundled version uses 384):',parent=self,minvalue=1,initialvalue=384)
     if pool is None:return None
     entry['pool_mib']=pool
   if role=='recording' and not entry['record']:raise ValueError('Recording requires a version with command recording enabled.')
   if role=='pak' and (not entry['pack'] or entry['record']):raise ValueError('Choose a PAK-capable runtime with recording disabled.')
   self.emus[role]=entry;self.save();return entry['path']
  def manage_emus(self):
   choice=self.dialog('Emulator files','Choose which libSceAmpr.sprx version the app should use. For the normal Auto Guide, the included versions are already selected automatically.\n\nRecording: records file accesses while you play on PS5.\n\nPAK game: reads the PAK files in your finished game, without recording. This is what PAK runtime means.\n\nManual update: a version you choose for a separate emulator update.\n\nYou can browse to a downloaded SPRX or place it in:\n'+str(emu_directory())+'\n\nSelecting a version here does not change your game yet.',('Recording','PAK game','Manual update','Close'))
   role={'Recording':'recording','PAK game':'pak','Manual update':'manual'}.get(choice)
   if role:self.choose_runtime(role,True)
  def pcmd(self,action,runtime=None):
   args=[action,'--project',str(self.project.path)]
   if runtime:args+=['--runtime',runtime]
   return command('project',*args)
  def maintenance(self,action):
   self.mode='manual'
   if not self.ensure_project():return
   selected=self.choose_runtime('manual') if action!='index' else None
   if action!='index' and not selected:return
   if (self.project.game/'ampr_assets.index').exists() and action=='emulator' and (not self.emus['manual']['pack'] or self.emus['manual']['record']):raise ValueError('An existing PAK game needs a PAK-capable runtime without recording.')
   self.project.d['maintenance_action']=action;self.project.save()
   self.checkpoint('maintenance',True)
   self.run([(action.title(),self.pcmd(action,selected))],action='maintenance',message='Update completed. Previous files were backed up for Recovery.')
  def manual_archive(self):
   self.mode='manual'
   if not self.ensure_project():return
   if not self.fields['trace'].get():self.fields['trace'].set(str(self.project.work/'Recordings'))
   self.checkpoint('archive');self.run([('Saving recording',self.pcmd('archive'))],action='archive',message='Recording saved successfully.')
  def paths(self,trace=False):
   if not self.ensure_project():return False
   for key in ('index','toml','output')+(('trace',) if trace else ()):
    if not self.fields[key].get():raise ValueError('Select '+key+' first.')
   if not Path(self.fields['index'].get()).is_file():raise ValueError('Select a matching ampr_emu.index or create it first.')
   self.save();return True
  def manual_generate(self):
   self.mode='manual'
   if not self.paths(True):return
   self.generate_job(False)
  def generate_job(self,guided):
   toml=Path(self.fields['toml'].get())
   if not guided and toml.exists() and toml.stat().st_size and self.dialog('Replace TOML?','This profile exists. Its previous contents will be saved for Step Back. Replace it?',('Yes','No'))!='Yes':return
   args=build_profile_command(Path(self.fields['trace'].get()),toml)[2:];self.checkpoint('generate')
   self.run([('Generating profile from recordings',self.pcmd('generate'))],action='generate',next_step='load' if guided else None,message='Profile created successfully.')
  def load_profile(self,guided=False):
   if not guided:self.mode='manual'
   if not self.ensure_project():return
   coverage=load_profile_coverage(Path(self.fields['toml'].get()));self.loaded_base=set(coverage.base_patterns);self.patterns.delete(0,'end')
   for item in coverage.effective_patterns:self.patterns.insert('end',item)
   if guided:self.checkpoint('load')
   self.run([('Checking profile',self.pcmd('profile-check'))],action='load',next_step='consent' if guided else None,message='Profile loaded successfully.')
  def add_files(self):
   if not self.ensure_project():return
   for name in filedialog.askopenfilenames(parent=self,title='Add original game files',initialdir=str(self.project.game)):
    rel=Path(name).resolve().relative_to(self.project.game).as_posix()
    if rel not in self.patterns.get(0,'end'):self.patterns.insert('end',rel)
  def remove_patterns(self):
   for i in reversed(self.patterns.curselection()):self.patterns.delete(i)
  def save_selection(self):
   if self.loaded_base is None:raise ValueError('Load from profile first.')
   current=set(self.patterns.get(0,'end'));apply_manual_coverage(Path(self.fields['toml'].get()),current-self.loaded_base,excluded_patterns=self.loaded_base-current,action='compress',layout='mixed',block_size='64KiB');self.save();self.status.set('Selection saved.')
  def manual_check(self):
   self.mode='manual'
   if self.ensure_project():self.run([('Checking profile',self.pcmd('profile-check'))],action='check',message='Profile checked.')
  def acceptance(self,guided=False):
   choice=self.dialog('Confirm loose files','Files that are not packed will remain as loose files in the finished game. They will be copied from the original. The recording does not cover every part of the game.',(('Accept and start','Decline','Step Back','Close') if guided else ('Accept','Decline','Close')),checkbox='I understand. Keep unselected files loose.')
   if choice=='Step Back':return 'back'
   if choice and choice.startswith('Accept'):
    self.reviewed.set(True);self.save();return True
   self.status.set('Nothing started. Confirm loose files to continue.');return False
  def manual_build(self):
   self.mode='manual'
   if not self.paths():return
   if not self.reviewed.get():
    self.acceptance(False);self.status.set('Click Create PAKs and verify to start after accepting.');return
   self.build_job(False)
  def build_job(self,guided):
   if not self.paths():return
   self.checkpoint('build')
   jobs=[('Checking profile',self.pcmd('profile-check')),('Creating PAK files',self.pcmd('build'))]
   if not guided:jobs += self.verify_jobs()
   self.run(jobs,action='build',next_step='verify' if guided else None,message='PAK files created successfully.' if guided else 'PAK files created and verified successfully. Use Finish PAK game to assemble the game.')
  def verify_jobs(self):
   index=Path(self.fields['output'].get())/'ampr_assets.index'
   return [('Verifying PAK files',command('pack','verify','--index',index,'--root',self.project.game)),('Recording verification result',self.pcmd('stamp'))]
  def manual_verify(self):
   self.mode='manual'
   if self.paths():self.run(self.verify_jobs(),action='verify',message='PAK verification completed successfully.')
  def finish_job(self,guided):
   selected=self.choose_runtime('pak')
   if not selected:return
   self.save();receipt=self.project.d.get('receipt')
   if not receipt:raise ValueError('Verify the PAK files first, or use Auto Guide to explicitly skip byte verification.')
   self.checkpoint('finish',True)
   self.run([('Finishing complete PAK game',self.pcmd('complete',selected))],action='finish',next_step='done' if guided else None,message=self.finish_message())
  def finish_message(self):
   return 'The complete PAK game is ready at:\n'+str(self.project.game)+'\n\nTest it on your PS5. Keep the original backup and project in:\n'+str(self.project.work)+'\n\nIf the game works and you no longer want Recovery or to continue this project, you may remove the dedicated working folder. First make sure it contains no unrelated files and is not a parent of the game folder. Deleting the backup permanently removes this project’s recovery option.'
  def manual_finish(self):
   self.mode='manual'
   if not self.ensure_project():return
   if self.dialog('Finish PAK game','Create a complete PAK game at the current game location? The full original will be saved inside your working folder. Only loose files are copied into PAK Output. Existing PAKs and the original game are moved. Different volumes require a transfer and take longer. The final runtime supports PAKs without recording; ampr_commands.bin and ampr_emu.log are excluded.',('Yes','No'))=='Yes':self.finish_job(False)
  def request_recovery(self):
   self.mode='manual'
   if not self.ensure_project():return
   if self.warning_delay('Recover original game?','This will undo this project’s changes and restore the state captured when the project was created. After the original is restored successfully, this will permanently delete this project’s PAK game, generated recordings, outputs and temporary files, and reset its progress. Imported and pre-existing files are kept. You will start again from scratch. Are you sure?'):
    self.run([('Recovering original game',self.pcmd('recover'))],action='recover',message='Original game restored. Project-generated files and progress removed. Click New Project to start again; you can reuse the same working folder.',commit=False)

  def sequence(self):
   common=['game','work','route','prepare']
   template=self.project and self.project.d.get('guide',{}).get('template',False)
   return common+([] if template else ['play','archive'])+['paths']+([] if template else ['generate'])+['load','consent','build','verify','finish','done']
  def heading(self,key,title):return 'Step '+str(self.sequence().index(key)+1)+' - '+title
  def guide_choice(self,key,title,text,choices=('OK','Close'),important=None):
   choices=list(choices)
   if key!='game' and 'Step Back' not in choices:choices.insert(-1,'Step Back')
   result=self.dialog(self.heading(key,title),text,tuple(choices),important)
   if result=='Step Back':self.step_back();return None
   return result
  def start_guide(self):
   if self.busy:return
   if self.project and self.project.d['phase']=='recovered':raise ValueError('Recovery is complete. Choose New Project to start again.')
   self.mode='guide'
   if self.project:
    self.save();self.project.d.setdefault('guide',{'step':self.infer_step(),'template':False});self.project.d['guide']['mode']='guide';self.project.save()
   self.guide_step()
  def infer_step(self):
   d=self.project.d
   if d['phase']=='complete':return 'done'
   if d.get('receipt'):return 'finish'
   if d.get('build_run',{}).get('finished'):return 'verify'
   if 'profile' in d.get('completed',[]) or (d['paths'].get('toml') and Path(d['paths']['toml']).is_file()):return 'load'
   if d.get('recordings'):return 'paths'
   if d['phase']=='prepared':return 'play'
   return 'route'
  def continue_work(self):
   if self.busy:return
   if self.project and self.project.d['phase']=='recovered':raise ValueError('Recovery is complete. Choose New Project to start again.')
   if not self.project:self.start_guide();return
   self.refresh()
   if self.project.d.get('transaction') in {'original-moved','original-restored','published'} or (self.project.d.get('transaction') in {'assembling','assembled'} and self.project.game.is_dir()):
    self.mode='manual';self.manual_finish();return
   if self.project.can_resume_publication():
    guided=self.project.d.get('guide',{}).get('mode')=='guide'
    self.mode='guide' if guided else 'manual'
    if self.dialog('Continue existing PAK build','The PAK files already exist. Continue moving them into Pack Output without repacking?',('Continue','Close'))!='Continue':return
    jobs=[('Publishing existing PAK files',self.pcmd('publish-build'))]
    if not guided:jobs+=self.verify_jobs()
    self.run(jobs,action='build',next_step='verify' if guided else None,message='PAK output is ready. Existing files were reused.');return
   if self.project.d.get('running') or self.project.d.get('pending_checkpoint'):
    if self.dialog('Interrupted operation','Resume requires undoing the incomplete step first. This removes only this operation’s generated files and restores its saved changes.',('Undo interrupted step','Close'))=='Undo interrupted step':self.undo_pending()
    return
   if self.project.d.get('guide',{}).get('mode')=='guide':self.mode='guide';self.guide_step()
   else:
    action=self.project.d.get('resume_action')
    self.mode='manual'
    actions={'build':self.manual_build,'verify':self.manual_verify,'generate':self.manual_generate,'archive':self.manual_archive,'load':lambda:self.load_profile(False),'check':self.manual_check,'finish':self.manual_finish,'maintenance':lambda:self.maintenance(self.project.d.get('maintenance_action','index')),'recover':self.request_recovery}
    if action in actions:actions[action]()
    else:self.status.set('Project loaded. Continue with the manual controls, or choose Auto Guide.')
  def guide_step(self):
   if self.busy:return
   key=self.project.d.get('guide',{}).get('step','route') if self.project else self.pending_guide
   if key=='game':
    if self.guide_choice(key,'Select your game','Select the complete game folder you want to prepare. It can be on an internal or external drive.')!='OK':return
    game=self.fields['game'].get() or self.choose_dir('Select the game folder')
    if not game:return
    if (Path(game)/'ampr_assets.index').exists():raise ValueError('Auto Guide needs a complete original game, not an already reduced PAK game.')
    self.fields['game'].set(game);self.pending_guide='work';self.after(0,lambda:self.guard(self.guide_step));return
   if key=='work':
    if self.guide_choice(key,'Choose your working folder','Now choose a folder outside the game that your PS5 loader does not scan. Navigate to the desired location first, then use New Folder. Your project, recordings and original-game backup will be stored here.')!='OK':return
    work=self.choose_dir('Choose a working folder',self.base_location(),True)
    if not work:return
    values={k:v.get() for k,v in self.fields.items()}
    existing=Path(work)/(Path(values['game']).name+'.json')
    if existing.is_file():
     candidate=Project(existing)
     if candidate.game!=Path(values['game']).resolve() or candidate.d['phase']!='created' or candidate.d.get('history'):raise ValueError('This working folder has an existing project. Use Open Project or choose another working folder.')
     self.project=candidate
    else:self.project=Project(create(values['game'],work))
    self.project.d['emulators']=self.emus;self.project.d['paths'].update({k:values[k] for k in ('index','trace','toml','output')});self.project.d['guide']={'step':'route','mode':'guide','template':False};self.project.save();self.refresh();self.after(0,lambda:self.guard(self.guide_step));return
   if key=='route':
    answer=self.guide_choice(key,'Do you have a TOML profile?','',('Yes','No','Close'),important='IF THIS IS YOUR FIRST TIME HEARING ABOUT A TOML FILE, CLICK NO!')
    if answer not in ('Yes','No'):return
    chosen=None
    if answer=='Yes':
     chosen=self.fields['toml'].get() if Path(self.fields['toml'].get()).is_file() else filedialog.askopenfilename(parent=self,title='Choose existing TOML',filetypes=[('TOML','*.toml')])
     if not chosen:return
    self.checkpoint('route');self.project.d.setdefault('guide',{})['template']=answer=='Yes'
    if chosen:self.project.d['paths']['toml']=chosen
    self.project.save();self.advance('prepare');self.after(0,lambda:self.guard(self.guide_step));return
   if key=='prepare':
    g=self.project.game;template=self.project.d['guide'].get('template',False)
    if template:
     text=('fakelib folder found.' if (g/'fakelib').is_dir() else 'fakelib folder not found. It will be created.')+'\n\n'+('Your current fakelib/libSceAmpr.sprx will be backed up and replaced.' if (g/'fakelib/libSceAmpr.sprx').is_file() else 'fakelib/libSceAmpr.sprx not found. It will be installed.')+'\n\nThe selected PAK-capable emulator without recording will be installed now. Your TOML replaces the gameplay recording step.'+'\n\n'+('Your current ampr_emu.index will be backed up and rebuilt from the complete game.' if (g/'ampr_emu.index').is_file() else 'ampr_emu.index will be created from the complete game.')+'\n\nThese changes are saved for Step Back and Recovery.'
    else:
     text=('fakelib folder found.' if (g/'fakelib').is_dir() else 'fakelib folder not found. It will be created.')+'\n\n'+('Your current libSceAmpr.sprx will be backed up.' if (g/'fakelib/libSceAmpr.sprx').is_file() else 'libSceAmpr.sprx not found. The recording version will be installed.')+'\n\n'+('Your current ampr_emu.index will be backed up and rebuilt.' if (g/'ampr_emu.index').is_file() else 'ampr_emu.index not found. It will be created.')+'\n\nThe index is created from the game files. Recovery records these changes automatically.'
    if self.guide_choice(key,'Prepare game files',text)!='OK':return
    selected=self.choose_runtime('pak' if template else 'recording')
    if not selected:return
    self.checkpoint('prepare',True)
    self.run([('Preparing game files',self.pcmd('prepare',selected))],action='prepare',next_step='paths' if template else 'play',message='Game files prepared successfully.');return
   if key=='play':
    text='Safely eject the game drive if it is external, then connect it to the PS5. The app has not ejected it.\n\nPlay for about 5-10 minutes for a first recording. Try different locations and actions. Close the game normally, then reconnect the drive to the Mac at the same location.\n\nOnly then click OK. Close pauses the guide; Continue brings you back here.'
    if self.guide_choice(key,'Record on your PS5',text,important='IMPORTANT: CLICK OK ONLY AFTER PLAYING AND RECONNECTING THE GAME DRIVE.')!='OK':return
    if not (self.project.game/'ampr_commands.bin').is_file():raise ValueError('No ampr_commands.bin found. Close the game and reconnect the correct drive first.')
    self.checkpoint('play');self.advance('archive');self.after(0,lambda:self.guard(self.guide_step));return
   if key=='archive':
    dest=self.project.work/'Recordings'
    self.checkpoint('archive');self.project.d['paths']['trace']=str(dest);self.project.save();self.refresh()
    self.run([('Saving recording automatically to '+str(dest),self.pcmd('archive'))],action='archive',next_step='paths',message='Recording saved successfully.');return
   if key=='paths':
    template=self.project.d['guide'].get('template',False)
    text=('The app will keep your existing TOML profile and create a Pack Output folder in your working folder.' if template else 'The app will create a TOML profile named after your game and a Pack Output folder in your working folder.')+'\n\nClick OK to continue. Existing files and non-empty output folders will not be overwritten.'
    if self.guide_choice(key,'Create profile and output locations',text)!='OK':return
    self.checkpoint('paths');self.auto_paths(template);self.advance('load' if template else 'generate')
    if self.dialog('Created successfully','TOML profile and Pack Output folder are ready.',('OK','Close'))=='OK':self.after(0,lambda:self.guard(self.guide_step))
    return
   if key=='generate':
    if self.guide_choice(key,'Generate profile from recordings','The app will use your saved recordings to generate the TOML profile. These recordings are also called traces. Files not selected for PAK storage will remain loose.')=='OK':self.generate_job(True)
    return
   if key=='load':
    if self.guide_choice(key,'Load and check profile','The app will now load your TOML profile and check its configuration. No manual Load from profile click is needed.')=='OK':self.load_profile(True)
    return
   if key=='consent':
    self.checkpoint('consent')
    accepted=self.acceptance(True)
    if accepted is True:self.advance('build');self.build_job(True)
    else:
     self.project=Project(self.project.path);self.project.d.pop('pending_checkpoint',None);self.project.save()
     if accepted=='back':self.step_back()
    return
   if key=='build':
    if self.guide_choice(key,'Create PAK files','Click OK to start the PAK build. Progress stays visible in this window. Stop asks for confirmation and gives you ten seconds to cancel that request.')=='OK':self.build_job(True)
    return
   if key=='verify':
    choice=self.guide_choice(key,'Verify PAK files?','Verification reads the PAK data and compares it with the original files. This takes additional time.\n\nYou may skip the byte comparison. File structure and memory checks still run, but the PAK contents will be marked UNVERIFIED.',('Verify','Skip verification','Close'))
    if choice not in ('Verify','Skip verification'):return
    self.checkpoint('verify');jobs=self.verify_jobs() if choice=='Verify' else [('Checking structure (byte verification skipped)',self.pcmd('skip-verify'))]
    self.run(jobs,action='verify',next_step='finish',message='Verification completed successfully.' if choice=='Verify' else 'Byte verification skipped. This PAK set is marked UNVERIFIED.');return
   if key=='finish':
    unverified=not self.project.d.get('receipt',{}).get('verified',True)
    text='The app will keep the complete original game inside your working folder and build a complete PAK game at the original game location. Only unpacked files are copied into PAK Output. PAKs and the original game are moved. Different volumes require a transfer and take longer. A PAK-capable runtime without recording will be installed. ampr_emu.index is retained. ampr_commands.bin and ampr_emu.log are excluded.\n\nWorking folder:\n'+str(self.project.work)
    if self.guide_choice(key,'Finish PAK game',text,important='THIS SET HAS NOT BEEN BYTE-VERIFIED.' if unverified else None)=='OK':self.finish_job(True)
    return
   if key=='done':
    self.guide_choice(key,'Success',self.finish_message(),('Close',));return
  def auto_paths(self,template):
   def unique(path):
    original=path;i=2
    while path.exists():path=original.with_name(original.stem+f' ({i})'+original.suffix);i+=1
    return path
   if not template:
    toml=unique(self.project.work/(self.project.game.name+'.toml'));self.project.track(toml);toml.write_text('# Profile will be generated from recordings in the next step.\n');self.project.d['paths']['toml']=str(toml)
   out=unique(self.project.work/'Pack Output');self.project.track(out);out.mkdir();self.project.d['paths']['output']=str(out);self.project.save();self.refresh()
  def step_back(self):
   if not self.project:
    self.pending_guide='game';self.fields['game'].set('');self.fields['index'].set('');self.after(0,lambda:self.guard(self.guide_step));return
   if not self.project.d.get('history'):
    if self.project.d['phase']!='created':raise ValueError('This project has no earlier step checkpoints. Use Recover original game for its earlier changes.')
    self.project=None;self.pending_guide='work';self.after(0,lambda:self.guard(self.guide_step));return
   if self.dialog('Step Back','Undo the previous step and return to it? Generated files from that step are removed. Files that existed beforehand are restored.',('Step Back','Close'))!='Step Back':return
   jobs=[]
   record=self.project.d.get('pending_checkpoint') or (self.project.d.get('history') or [{}])[-1]
   if record.get('step')=='build':jobs.append(('Removing files from this build',self.pcmd('cleanup-build')))
   jobs.append(('Undoing previous step',self.pcmd('undo')))
   self.run(jobs,action='undo',message='Previous step restored.',commit=False)
  def undo_pending(self):
   jobs=[]
   if self.project.d.get('build_run') and self.project.d.get('pending_checkpoint',{}).get('step')=='build':jobs.append(('Cleaning interrupted build',self.pcmd('cleanup-build')))
   if self.project.d.get('pending_checkpoint'):jobs.append(('Undoing interrupted step',self.pcmd('undo')))
   if jobs:self.run(jobs,action='undo',message='Interrupted step undone. Click Continue to restart it.',commit=False)
   else:self.notice('Recovery required','This older operation has no step checkpoint. Use Recover original game before starting a new project.')

  def show_progress(self,label):
   window=tk.Toplevel(self);window.withdraw();window.title(label);window.transient(self);window.geometry('700x340');window.resizable(True,False)
   body=ttk.Frame(window,padding=22);body.pack(fill='both',expand=True)
   ttk.Label(body,text=label,font=('Helvetica',17,'bold')).pack(anchor='w',pady=(0,12))
   ttk.Label(body,textvariable=self.status,wraplength=650).pack(fill='x',pady=10)
   ttk.Progressbar(body,variable=self.percent,maximum=100).pack(fill='x',pady=10)
   row=ttk.Frame(body);row.pack(fill='x',pady=12)
   cancel=ttk.Button(row,text='Stop…',command=lambda:self.guard(self.request_stop),state='disabled' if self.active_action in ('undo','cleanup') else 'normal');cancel.pack(side='left')
   close=ttk.Button(row,text='Close',command=window.withdraw);close.pack(side='left',padx=10)
   ttk.Label(body,text='Close hides this window. The operation continues; use Stop to cancel.',wraplength=650).pack(anchor='w')
   window.protocol('WM_DELETE_WINDOW',window.withdraw);self.place_popup(window);self.progress_window=window
  def run(self,jobs,action,message,next_step=None,commit=True):
   if self.busy:return
   pending=self.project.d.get('pending_checkpoint',{}).get('step')
   if pending and pending!=action and action not in ('cleanup','undo','recover'):
    raise ValueError('Another step is incomplete. Use Continue to undo it before starting a different operation.')
   self.save();self.busy=True;self.cancelled=False;self.run_id=uuid.uuid4().hex;self.active_action=action;self.active_next=next_step;self.percent.set(0)
   for b in self.buttons:b.configure(state='disabled')
   self.stop.configure(state='normal' if action not in ('undo','cleanup') else 'disabled')
   project_path=self.project.path;guided=self.mode=='guide'
   self.project.d.setdefault('guide',{})['mode']='guide' if guided else 'manual';self.project.d['running']=action;self.project.d['resume_action']='build' if action=='build' else action;self.project.save()
   if guided:self.show_progress(jobs[0][0])
   def worker():
    try:
     logdir=Project(project_path).store/'logs';logdir.mkdir(exist_ok=True)
     with (logdir/(self.run_id+'.log')).open('w') as log:
      for label,cmd in jobs:
       if self.cancelled:raise RuntimeError('Stopped by user.')
       state=Project(project_path);state.d['running']=action;state.save();self.events.put(('phase',label))
       env=os.environ.copy();env['PYTHONUTF8']='1';env['PYTHONUNBUFFERED']='1'
       self.process=subprocess.Popen(cmd,cwd=str(state.work),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,env=env,start_new_session=True)
       for line in self.process.stdout:log.write(line);log.flush();self.events.put(('log',line))
       result=self.process.wait();self.process=None
       if result!=0:raise RuntimeError('The operation did not finish. Read the error in Progress.')
     self.events.put(('done',True,message,next_step,commit,guided,action))
    except Exception as e:self.events.put(('done',False,str(e),None,False,guided,action))
   threading.Thread(target=worker,daemon=True).start()
  def poll(self):
   try:
    while True:
     event=self.events.get_nowait()
     if event[0]=='phase':self.status.set(event[1]);self.percent.set(0);self.append('\n'+event[1]+'\n')
     elif event[0]=='log':
      self.append(event[1]);match=re.search(r'\[[^\]]*?(\d+)%\]',event[1])
      if match:self.percent.set(int(match.group(1)));self.status.set(event[1].strip())
     else:
      ok,msg,next_step,commit,guided,action=event[1:];cancelled=self.cancelled;self.busy=False;self.process=None
      for b in self.buttons:b.configure(state='normal')
      self.stop.configure(state='disabled')
      if self.progress_window:
       self.progress_window.destroy();self.progress_window=None
      self.project=Project(self.project.path)
      if cancelled:
       self.resume_after_cancel=action
       jobs=[]
       if action=='build':jobs.append(('Removing this build’s generated files',self.pcmd('cleanup-build')))
       if self.project.d.get('pending_checkpoint'):jobs.append(('Restoring this step',self.pcmd('undo')))
       if jobs:self.run(jobs,action='cleanup',message='Stopped. Changes from this step were undone. Click Continue to restart.',commit=False);continue
       self.project.d['running']=None;self.project.save();self.refresh();self.status.set('Stopped. Click Continue to restart.');continue
      if ok:
       if commit:self.project.commit_step(next_step)
       else:self.project.d['running']=None;self.project.save()
       if not guided and action not in ('cleanup','undo'):
        self.project.d['resume_action']={'build':'finish','verify':'finish','generate':'load','archive':'generate','load':'build','check':'build'}.get(action);self.project.save()
       if action=='cleanup':
        self.project.d['resume_action']=getattr(self,'resume_after_cancel','build');self.project.save()
       self.refresh();self.percent.set(100);self.status.set(msg)
       if action=='finish':msg=self.finish_message()
       if guided:
        answer=self.dialog('Success',msg,('OK','Step Back','Close') if action not in ('cleanup','recover') else ('OK','Close'))
        if answer=='Step Back':self.after(0,lambda:self.guard(self.step_back))
        if answer=='OK' and action not in ('cleanup','recover'):self.after(0,lambda:self.guard(self.guide_step))
       elif action in ('finish','recover'):self.notice('Completed successfully',msg)
      else:
       self.project.d['last_error']=msg;self.project.d['running']=None;self.project.save();self.refresh();self.status.set('Not completed. Read Progress, then use Continue.');self.notice('Operation not completed',msg)
   except queue.Empty:pass
   self.after(100,self.poll)
  def append(self,text):
   self.log.configure(state='normal');self.log.insert('end',text);self.log.configure(state='disabled')
   if self.follow.get():self.log.see('end')
  def request_stop(self):
   if not self.busy:return
   run_id=self.run_id
   if not self.warning_delay('Stop current operation?','Stop this operation and undo its changes? For a PAK build, only files created by this build are removed. Continue can restart this step.'):return
   if not self.busy or run_id!=self.run_id:return
   self.cancelled=True
   if self.process:
    import signal
    try:os.killpg(self.process.pid,signal.SIGTERM)
    except ProcessLookupError:pass
   self.status.set('Stopping… waiting for the operation, then restoring this step.')
  def close(self):
   if self.busy:self.notice('Operation running','Use Stop and wait for cleanup before closing the app.');return
   if self.project:self.save()
   self.destroy()
 App().mainloop();return 0

def main():
 multiprocessing.freeze_support();args=sys.argv[1:]
 if args and args[0].startswith('--internal-'):
  tool=args.pop(0).removeprefix('--internal-')
  if tool=='pack':from ampr_pack import main as run
  elif tool=='profile':from ampr_pack_profile import main as run
  elif tool=='project':from ampr_project import main as run
  else:raise ValueError('Unknown tool')
  return run(args)
 return gui()
if __name__=='__main__':raise SystemExit(main())
