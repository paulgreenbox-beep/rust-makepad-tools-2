"""Storage policy inside the existing WSLC owner, not a container manager.

Versioned hard-quota and operator-approved monitored-soft admission. Missing
observations refuse; neither monitoring nor cleanup grants ownership.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
EVIDENCE=ROOT/'reports/evidence'
MAX_BYTES=120_000_000_000
RESERVE=10_000_000_000
WSLC=Path(r'C:\Program Files\WSL\wslc.exe')

class StorageRefusal(RuntimeError):
    def __init__(self,code):self.code=code;super().__init__(code)

def require(condition,code):
    if not condition:raise StorageRefusal(code)

def integer(value):return type(value) is int and value>=0

def read(path,cap=1_048_576):
    with Path(path).open('rb') as stream:
        raw=stream.read(cap+1)
    require(len(raw)<=cap,'STORAGE_RECEIPT_TOO_LARGE')
    return json.loads(raw.decode('utf-8-sig'))

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1_048_576),b''):h.update(block)
    return h.hexdigest().upper()

def safe_path(path,root,*,must_exist=True):
    # lstat each component BEFORE resolve: junctions/reparse points are not
    # accepted merely because the resolved target happens to stay under root.
    p=Path(os.path.abspath(path));boundary=Path(os.path.abspath(root))
    require(p.is_relative_to(boundary),'STORAGE_PATH_ESCAPE')
    for component in [p,*p.parents]:
        try:info=component.lstat()
        except FileNotFoundError:info=None
        if info is not None:
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&1024,'STORAGE_REPARSE_REFUSED')
        if component==boundary:break
    require(not must_exist or p.exists(),'STORAGE_PATH_MISSING')
    return p

def policy():
    try:value=read(HERE/'storage-policy.json',16384)
    except OSError:raise StorageRefusal('STORAGE_POLICY_UNAVAILABLE') from None
    except (ValueError,UnicodeError):raise StorageRefusal('STORAGE_POLICY_INVALID') from None
    expected={'schema':'toolkit-wslc-storage-policy-v1','policy_id':'TOOLKIT_WSLC_STORAGE_POLICY_V1','version':1,
      'container_storage_max_bytes':MAX_BYTES,'host_ssd_reserve_bytes':RESERVE,'warning_bytes':96_000_000_000,
      'cleanup_bytes':108_000_000_000,'stop_growth_bytes':114_000_000_000,
      'require_hard_quota_before_create':True,'eager_allocation':False,'delete_foreign_resources':False,'preserve_core_references':True}
    if value.get('schema')=='toolkit-wslc-storage-policy-v1.1':
        expected.update(schema='toolkit-wslc-storage-policy-v1.1',policy_id='TOOLKIT_WSLC_STORAGE_POLICY_V1_1',version='1.1',
            storage_enforcement='monitored_soft_limit',hard_quota_enforced=False,require_hard_quota_before_create=False,
            approved_soft_profile='focus_trace71',max_scenario_growth_bytes=1073741824,max_single_growth_bytes=536870912,
            max_host_evidence_bytes=268435456,max_capture_count=4)
    require(all(type(value.get(k)) is type(v) and value[k]==v for k,v in expected.items()),'STORAGE_POLICY_INVALID')
    require(set(value)==set(expected)|{'allowed_staging_files','scope'},'STORAGE_POLICY_INVALID')
    require(value.get('allowed_staging_files')==['ai-workspace-fixture'],'STORAGE_POLICY_INVALID')
    return value

def soft_mode(p):return p.get('storage_enforcement')=='monitored_soft_limit'

def decide(usage_bytes,free_bytes,operation,*,incoming_bytes=0,quota=None):
    p=policy()
    precreate=usage_bytes is None and operation=='create' and soft_mode(p)
    require(integer(usage_bytes) or precreate,'USAGE_NOT_VERIFIED')
    require(all(integer(v) for v in (free_bytes,incoming_bytes)),'STORAGE_MEASUREMENT_INVALID')
    require(operation in ('create','stage','upload','build','grow','observe','cleanup'),'STORAGE_OPERATION_UNSUPPORTED')
    level='NEW_CONTAINER_NOT_YET_CREATED' if precreate else 'NORMAL' if usage_bytes<p['warning_bytes'] else 'WARNING' if usage_bytes<p['cleanup_bytes'] else 'CLEANUP_REFUSE_HEAVY' if usage_bytes<p['stop_growth_bytes'] else 'STOP_GROWTH'
    result={'schema':'toolkit-wslc-storage-decision-v1','level':level,'operation':operation,
      'usage_bytes':usage_bytes,'host_free_bytes':free_bytes,'incoming_bytes':incoming_bytes,
      'max_bytes':MAX_BYTES,'reserve_bytes':RESERVE,'automatic_retry_allowed':False,
      'storage_enforcement':p.get('storage_enforcement','hard_quota'),'hard_quota_enforced':False,
      'cleanup_requires_independent_ownership':True,'mutation_interruption_authorized':False}
    code=None
    if operation not in ('observe','cleanup'):
        if free_bytes-incoming_bytes<RESERVE:code='HOST_STORAGE_RESERVE_REFUSED' if soft_mode(p) else 'HOST_SSD_RESERVE_VIOLATED'
        elif usage_bytes is not None and (usage_bytes+incoming_bytes>MAX_BYTES or usage_bytes>=p['stop_growth_bytes']):code='STORAGE_GROWTH_REFUSED'
        elif usage_bytes is not None and usage_bytes>=p['cleanup_bytes'] and operation in ('create','stage','upload','build'):code='STORAGE_HEAVY_OPERATION_REFUSED'
        elif soft_mode(p) and incoming_bytes>p['max_single_growth_bytes']:code='UNBOUNDED_GUEST_WRITE_REQUEST'
        elif operation=='create' and soft_mode(p):
            q=quota or {}
            if not (precreate and q.get('storage_enforcement')=='monitored_soft_limit' and q.get('hard_limit_enforced') is False
                and 'limit_readback_bytes' in q and q['limit_readback_bytes'] is None
                and q.get('profile')=='focus_trace71' and q.get('usage_status')=='NEW_OWNED_CONTAINER_NOT_YET_CREATED'
                and q.get('inventory_verified') is True and q.get('guest_process_inventory_verified') is True
                and q.get('size_observation_available') is True and q.get('unexpected_writable_mounts') is False
                and type(q.get('scenario_growth_budget_bytes')) is int and q['scenario_growth_budget_bytes']==p['max_scenario_growth_bytes']
                and q.get('eager_allocation') is False):code='BLOCKED_EXISTING_RUNTIME'
            elif free_bytes-p['max_scenario_growth_bytes']<RESERVE:code='HOST_STORAGE_RESERVE_REFUSED'
        elif operation=='create':
            # A software counter or CLI option alone cannot establish quota.
            q=quota or {}
            if not (q.get('hard_limit_enforced') is True and type(q.get('limit_readback_bytes')) is int
                and q['limit_readback_bytes']==MAX_BYTES and q.get('covers_all_writable_mounts') is True
                and q.get('kernel_write_refusal_observed') is True and q.get('eager_allocation') is False):
                code='STORAGE_QUOTA_UNSUPPORTED'
            else:result['hard_quota_enforced']=True
    result.update(status='REFUSED' if code else 'ADMITTED',code=code)
    return result

_PORT=None
def fixed_query(args):
    """Reuse the existing bounded pipe reader, no second driver or shell."""
    global _PORT
    if _PORT is None:
        p=ROOT/'crates/toolkit-windows-automation/src/makepad_remote/wslc_host.py'
        spec=importlib.util.spec_from_file_location('toolkit_storage_existing_port',p)
        _PORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(_PORT)
    started=time.monotonic_ns()
    try:
        # Native WSLC session-run rejects a NUL stdin handle on this runtime.
        # Supply an actual empty pipe; no input command or shell is introduced.
        code,out,err=_PORT.run_bounded([str(WSLC),*args],data=b'',timeout=10,out_cap=262144,err_cap=65536)
        return {'args':args,'exit_code':code,'stdout':out.decode('utf-8','replace'),'stderr':err.decode('utf-8','replace'),
            'elapsed_monotonic_ns':time.monotonic_ns()-started,'output_bounded':True}
    except _PORT.Fault as error:
        return {'args':args,'error_code':error.code,'output_bounded':True,'elapsed_monotonic_ns':time.monotonic_ns()-started}

def successful(row):return row.get('exit_code')==0 and not row.get('stderr') and 'error_code' not in row

def probe(profile=None):
    """Fixed read-only commands only; never create a container or session."""
    if soft_mode(policy()):
        value={'schema':'toolkit-wslc-storage-capability-v1.1','observed_utc':datetime.now(timezone.utc).isoformat(),
            'storage_enforcement':'monitored_soft_limit','hard_limit_enforced':False,'limit_readback_bytes':None,
            'eager_allocation':False,'profile':profile,'usage_status':'NEW_OWNED_CONTAINER_NOT_YET_CREATED',
            'observed_usage_bytes':None,'inventory_verified':False,'guest_process_inventory_verified':False,
            'size_observation_available':False,'unexpected_writable_mounts':False,'scenario_growth_budget_bytes':1073741824,
            'container_created':False,'shared_settings_changed':False,'observations':[]}
        if profile!='focus_trace71':value['code']='STORAGE_SOFT_PROFILE_REFUSED';return value
        info=fixed_query(['info','--format','json']);value['observations'].append(info)
        if not successful(info):value['code']='BLOCKED_EXISTING_RUNTIME';return value
        try:sessions=json.loads(info['stdout'])['Server']['Sessions']
        except (ValueError,KeyError,TypeError):sessions=[]
        if not (type(sessions) is list and len(sessions)==1 and type(sessions[0].get('Name')) is str
                and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',sessions[0]['Name'])):
            value['code']='BLOCKED_EXISTING_RUNTIME';return value
        session=sessions[0]['Name'];value['shared_session']=sessions[0]
        help_row=fixed_query(['inspect','--help']);value['observations'].append(help_row)
        value['size_observation_available']=successful(help_row) and '--size' in help_row['stdout']
        inventory=fixed_query(['--session',session,'list','--all','--no-trunc','--quiet']);value['observations'].append(inventory)
        # Conservative first qualification: no adoption or competing container.
        value['inventory_verified']=successful(inventory) and not inventory['stdout'].strip()
        if not value['inventory_verified']:value['code']='BLOCKED_EXISTING_RUNTIME';return value
        processes=fixed_query(['--session',session,'system','session','run','ps','-eo','pid,ppid,comm'])
        value['observations'].append(processes)
        lines=processes.get('stdout','').splitlines()[1:]
        names=[line.split()[-1] for line in lines if len(line.split())==3]
        value['guest_process_inventory_verified']=successful(processes) and bool(lines) and bool(names) and names.count('ps')==1 and not any(n in ('docker','ctr') for n in names)
        value['code']=None if value['guest_process_inventory_verified'] and value['size_observation_available'] else 'BLOCKED_EXISTING_RUNTIME'
        return value
    commands=[['--version'],['create','--help'],['info','--format','json']]
    observations=[]
    for args in commands:
        started=time.monotonic_ns()
        observations.append(fixed_query(args))
    help_text=observations[1].get('stdout','')
    return {'schema':'toolkit-wslc-storage-capability-v1','observed_utc':datetime.now(timezone.utc).isoformat(),
      'wslc_executable_sha256':digest(WSLC),'observations':observations,
      'storage_opt_advertised':bool(re.search(r'--storage-opt\b',help_text)),
      'hard_limit_enforced':False,'eager_allocation':False,'code':'STORAGE_QUOTA_UNSUPPORTED',
      'reason':'No verified installed WSLC per-container quota enforcer/readback/write-refusal provider; session VHDX size is a different scope.',
      'container_created':False,'shared_settings_changed':False}

def admit_create(output,profile=None):
    ensure_host_reserve(262144)
    out=safe_path(output,EVIDENCE,must_exist=False);out.mkdir(parents=True,exist_ok=False)
    p=policy();capability=probe(profile);free=shutil.disk_usage(ROOT).free
    decision=decide(None if soft_mode(p) else 0,free,'create',quota=capability)
    value={'schema':'toolkit-wslc-storage-admission-v1.1' if soft_mode(p) else 'toolkit-wslc-storage-admission-v1',
      'policy_id':p['policy_id'],'storage_enforcement':p.get('storage_enforcement','hard_quota'),
      'hard_quota_enforced':decision['hard_quota_enforced'],'observed_utc':datetime.now(timezone.utc).isoformat(),
      'policy_sha256':digest(HERE/'storage-policy.json'),'capability':capability,'decision':decision,
      'container_created':False,'staging_started':False,'host_free_bytes':free}
    with (out/'storage-admission.json').open('x',encoding='utf-8') as f:json.dump(value,f,indent=2)
    return value

def measure_owned(actual,ctx):
    """An inspect --size observation, independently fenced to the own context."""
    require(re.fullmatch(r'[a-f0-9]{64}',str(ctx.get('container_id',''))) is not None,'CLEANUP_IDENTITY_NOT_VERIFIED')
    require(actual.get('Id')==ctx['container_id'] and actual.get('Image')==ctx.get('image')
        and bool(ctx.get('container_created')) and actual.get('Created')==ctx['container_created']
        and bool(ctx.get('container_started_at')) and actual.get('State',{}).get('StartedAt')==ctx['container_started_at'],
        'CLEANUP_IDENTITY_NOT_VERIFIED')
    labels=actual.get('Config',{}).get('Labels',{})
    require(bool(ctx.get('exclusive_owner')) and bool(ctx.get('exclusive_nonce'))
        and labels.get('aiui.toolkit.owner')==ctx['exclusive_owner'] and labels.get('aiui.toolkit.nonce')==ctx['exclusive_nonce'],
        'CLEANUP_IDENTITY_NOT_VERIFIED')
    require(actual.get('Mounts')==[] and not actual.get('HostConfig',{}).get('Tmpfs'),'UNEXPECTED_WRITABLE_MOUNT')
    require(integer(actual.get('SizeRw')),'USAGE_NOT_VERIFIED')
    return {'writable_layer_bytes':actual['SizeRw'],'guest_temporary_artifacts':'INCLUDED_IN_WRITABLE_LAYER; no tmpfs or external mounts',
        'shared_rootfs_bytes':actual.get('SizeRootFs'),'shared_rootfs_attributed_to_container':False,
        'container_id':ctx['container_id'],'image':ctx['image'],'nonce':ctx['exclusive_nonce'],
        'owner':ctx['exclusive_owner'],'created':ctx['container_created'],'started_at':ctx['container_started_at']}

def growth_decision(actual,ctx,*,incoming_bytes,operation='grow'):
    p=policy();usage=measure_owned(actual,ctx)
    require(ctx.get('fixture_sha256')=='9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB',
        'STORAGE_ARTIFACT_IDENTITY_CHANGED')
    require(integer(incoming_bytes) and incoming_bytes<=p.get('max_single_growth_bytes',536870912),'UNBOUNDED_GUEST_WRITE_REQUEST')
    if soft_mode(p):
        require(usage['writable_layer_bytes']+incoming_bytes<=p['max_scenario_growth_bytes'],'STORAGE_SCENARIO_BUDGET_REFUSED')
    result=decide(usage['writable_layer_bytes'],shutil.disk_usage(ROOT).free,operation,incoming_bytes=incoming_bytes)
    require(result['status']=='ADMITTED',result['code'])
    return {'schema':'toolkit-wslc-storage-usage-v1.1','policy_sha256':digest(HERE/'storage-policy.json'),
        'observation':usage,'decision':result,'hard_quota_enforced':False,'observed_monotonic_ns':time.monotonic_ns()}

def admit_growth(runtime,incoming_bytes,operation='upload'):
    out=safe_path(runtime,EVIDENCE);ctx=read(out/'context.json')
    require(re.fullmatch(r'[a-f0-9]{64}',str(ctx.get('container_id',''))) is not None,'CLEANUP_IDENTITY_NOT_VERIFIED')
    row=fixed_query(['inspect','--size','--format','json',ctx.get('container_id','')])
    require(successful(row),'USAGE_NOT_VERIFIED')
    try:items=json.loads(row['stdout'])
    except ValueError:raise StorageRefusal('USAGE_NOT_VERIFIED') from None
    require(type(items) is list and len(items)==1 and type(items[0]) is dict,'USAGE_NOT_VERIFIED')
    result=growth_decision(items[0],ctx,incoming_bytes=incoming_bytes,operation=operation)
    result['native_observation']=row
    path=out/'storage'/('growth-'+str(time.monotonic_ns())+'.json')
    with path.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
    return result

def ensure_host_reserve(incoming_bytes):
    require(integer(incoming_bytes),'STORAGE_MEASUREMENT_INVALID')
    free=shutil.disk_usage(ROOT).free
    require(free-incoming_bytes>=RESERVE,'HOST_STORAGE_RESERVE_REFUSED' if soft_mode(policy()) else 'HOST_SSD_RESERVE_VIOLATED')
    return {'host_free_bytes':free,'reserved_bytes':RESERVE,'incoming_bytes':incoming_bytes}

# Match the native Arbiter's 16 MiB persistence bound, not the 1 MiB
# evidence-receipt limit. All reads happen under its existing named mutex.
ARBITER_REGISTRY_CAP=16*1024*1024
ARBITER_TERMINAL={'COMPLETED','CANCELLED','TIMED_OUT'}
ARBITER_STATES={'QUEUED','WAITING_RESOURCES','LEASED','GUI_ACTIVE','QUIESCING',
    'BACKGROUND_RUNNING','RESUME_QUEUED','VERIFYING','COMPLETED','CANCELLED',
    'TIMED_OUT','OWNER_LOST','RECOVERING','RESOURCE_QUARANTINED','FAIL_TEST_INFRA'}

def _registry_identity(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)

def _registry_unique_pairs(pairs):
    value={}
    for key,item in pairs:
        require(key not in value,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
        value[key]=item
    return value

def _read_registry_snapshot(path):
    """Bounded full FD read, second-pass hash and path/FD identity join."""
    path=Path(path)
    try:
        with path.open('rb') as stream:
            before=os.fstat(stream.fileno())
            require(before.st_nlink==1,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
            require(before.st_size<=ARBITER_REGISTRY_CAP,'STORAGE_RECEIPT_TOO_LARGE')
            require(_registry_identity(before)==_registry_identity(path.stat()),
                    'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
            raw=bytearray()
            while len(raw)<=ARBITER_REGISTRY_CAP:
                chunk=stream.read(min(65536,ARBITER_REGISTRY_CAP+1-len(raw)))
                if not chunk:break
                raw.extend(chunk)
            require(len(raw)<=ARBITER_REGISTRY_CAP,'STORAGE_RECEIPT_TOO_LARGE')
            require(len(raw)==before.st_size,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
            expected=hashlib.sha256(raw).digest()
            stream.seek(0);check=hashlib.sha256()
            for chunk in iter(lambda:stream.read(65536),b''):check.update(chunk)
            after=os.fstat(stream.fileno())
            safe_path(path,path.parent)
            require(_registry_identity(before)==_registry_identity(after)
                    and _registry_identity(after)==_registry_identity(path.stat())
                    and check.digest()==expected,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
    except OSError:
        raise StorageRefusal('STORAGE_LEASE_OBSERVATION_UNAVAILABLE') from None
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=_registry_unique_pairs,
                          parse_constant=lambda _:require(False,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE'))
    except (ValueError,UnicodeError,TypeError):
        raise StorageRefusal('STORAGE_LEASE_OBSERVATION_UNAVAILABLE') from None

def _registry_lease_count(value,session_id):
    """Conservative filter, not a second Arbiter persistence validator."""
    bad='STORAGE_LEASE_OBSERVATION_UNAVAILABLE'
    require(type(value) is dict and type(session_id) is str and bool(session_id),bad)
    require(type(value.get('schema_version')) is int and value['schema_version']==1,bad)
    next_id=value.get('next_id');entries=value.get('entries');events=value.get('events')
    require(type(next_id) is int and next_id>0 and type(entries) is list
            and len(entries)<=4096 and type(events) is list and len(events)<=10000,bad)
    seen=set();active=0
    for entry in entries:
        require(type(entry) is dict,bad)
        rid=entry.get('request_id');generation=entry.get('generation')
        owner=entry.get('owner');state=entry.get('state')
        require(type(rid) is int and 0<rid<next_id and rid not in seen
                and type(generation) is int and generation>0
                and type(state) is str and state in ARBITER_STATES
                and type(owner) is dict,bad)
        seen.add(rid)
        require(all(type(owner.get(k)) is str and bool(owner[k].strip())
                    for k in ('worker_id','job_id','attempt_id','session_id')),bad)
        require(type(owner.get('pid')) is int and owner['pid']>0
                and type(owner.get('process_birth')) is str
                and owner['process_birth'].isdigit() and int(owner['process_birth'])>0,bad)
        require(type(entry.get('resources')) is list and bool(entry['resources']),bad)
        for resource in entry['resources']:
            if type(resource) is str:
                require(resource in ('DesktopInput','SystemClipboard','BackgroundCompute'),bad)
            else:
                require(type(resource) is dict and len(resource)==1,bad)
                kind,details=next(iter(resource.items()))
                require(kind in ('WindowMutation','SessionSemantic') and type(details) is dict,bad)
                if kind=='SessionSemantic':
                    require(type(details.get('session_id')) is str and bool(details['session_id']),bad)
                else:
                    require(type(details.get('hwnd')) is int and details['hwnd']>0
                            and type(details.get('pid')) is int and details['pid']>0
                            and type(details.get('process_birth')) is str
                            and details['process_birth'].isdigit()
                            and int(details['process_birth'])>0,bad)
        acquired=entry.get('acquired_at');reservations=entry.get('active_reservations',0)
        clipboard=entry.get('clipboard_pending',False)
        queued=entry.get('queued_at');deadline=entry.get('deadline');heartbeat=entry.get('heartbeat')
        require(all(type(v) is int and v>=0 for v in (queued,deadline,heartbeat))
                and deadline>queued and heartbeat>=queued
                and type(reservations) is int and 0<=reservations<=256
                and type(clipboard) is bool and type(entry.get('logical_background',False)) is bool
                and (acquired is None or (type(acquired) is int and queued<=acquired<deadline
                                          and acquired<=heartbeat))
                and (acquired is not None or (reservations==0 and not clipboard)),bad)
        require(not (state in ('LEASED','GUI_ACTIVE','QUIESCING','VERIFYING',
                               'RECOVERING','RESOURCE_QUARANTINED') and acquired is None)
                and not (state in ('QUEUED','WAITING_RESOURCES','RESUME_QUEUED',
                                   'BACKGROUND_RUNNING','COMPLETED','CANCELLED',
                                   'TIMED_OUT','OWNER_LOST') and acquired is not None),bad)
        if owner['session_id']==session_id and (
            state not in ARBITER_TERMINAL or acquired is not None or reservations or clipboard
        ):active+=1
    last=-1
    for event in events:
        require(type(event) is dict and type(event.get('timestamp')) is int
                and event['timestamp']>=last and type(event.get('request')) is int
                and 0<event['request']<next_id and type(event.get('state')) is str
                and event['state'] in ARBITER_STATES
                and type(event.get('reason')) is str and bool(event['reason'].strip()),bad)
        last=event['timestamp']
    return active

from contextlib import contextmanager
@contextmanager
def _arbiter_registry_lock(session):
    """Same named mutex and bounded wait as native DesktopArbiter::transaction."""
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.LPCWSTR]
    kernel.CreateMutexW.restype=wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    kernel.WaitForSingleObject.restype=wintypes.DWORD
    kernel.ReleaseMutex.argtypes=[wintypes.HANDLE]
    kernel.ReleaseMutex.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.restype=wintypes.BOOL
    handle=kernel.CreateMutexW(None,False,f'Local\\MakepadToolkitDesktopArbiterV1-{session}')
    require(bool(handle),'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
    acquired=False
    try:
        status=kernel.WaitForSingleObject(handle,2000)
        # WAIT_ABANDONED requires native owner recovery; never infer leases=0.
        require(status==0,'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
        acquired=True
        yield
    finally:
        if acquired:kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)

def active_session_leases(session_id):
    """Read the existing Arbiter registry; no recovery, mutation or second owner."""
    require(os.name=='nt','STORAGE_HOST_PLATFORM_UNSUPPORTED')
    import ctypes,uuid
    from ctypes import wintypes
    shell=ctypes.WinDLL('shell32');ole=ctypes.WinDLL('ole32');kernel=ctypes.WinDLL('kernel32')
    guid=(ctypes.c_ubyte*16).from_buffer_copy(uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091').bytes_le)
    path=ctypes.c_wchar_p();sid=wintypes.DWORD()
    shell.SHGetKnownFolderPath.argtypes=[ctypes.c_void_p,wintypes.DWORD,wintypes.HANDLE,ctypes.POINTER(ctypes.c_wchar_p)]
    shell.SHGetKnownFolderPath.restype=ctypes.c_long;ole.CoTaskMemFree.argtypes=[ctypes.c_void_p]
    require(shell.SHGetKnownFolderPath(ctypes.byref(guid),0,None,ctypes.byref(path))>=0,
            'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
    try:local=Path(path.value)
    finally:ole.CoTaskMemFree(ctypes.cast(path,ctypes.c_void_p))
    kernel.ProcessIdToSessionId.argtypes=[wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype=wintypes.BOOL
    require(bool(kernel.ProcessIdToSessionId(os.getpid(),ctypes.byref(sid))),
            'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
    registry=safe_path(local/'MakepadToolkit/desktop-arbiter-v1'/f'session-{sid.value}'/'resource-registry.json',local)
    with _arbiter_registry_lock(sid.value):
        require(not (registry.parent/'abandoned-recovery-required.json').exists(),
                'STORAGE_LEASE_OBSERVATION_UNAVAILABLE')
        return _registry_lease_count(_read_registry_snapshot(registry),session_id)

def remove_exact_file(path,expected,expected_sha):
    """Windows delete-by-handle, denying concurrent write/rename/delete."""
    require(os.name=='nt','STORAGE_HOST_PLATFORM_UNSUPPORTED')
    import ctypes,msvcrt
    from ctypes import wintypes
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    k.CreateFileW.restype=wintypes.HANDLE
    k.SetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    k.SetFileInformationByHandle.restype=wintypes.BOOL;k.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=k.CreateFileW(str(path),0x80010000,1,None,3,0x00200000,None)
    require(handle not in (None,ctypes.c_void_p(-1).value),'CLEANUP_IDENTITY_NOT_VERIFIED')
    fd=None
    try:
        fd=msvcrt.open_osfhandle(int(handle),os.O_RDONLY);handle=None
        with os.fdopen(fd,'rb') as stream:
            fd=None;info=os.fstat(stream.fileno())
            require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)==expected and info.st_nlink==1,'CLEANUP_IDENTITY_NOT_VERIFIED')
            h=hashlib.sha256()
            for block in iter(lambda:stream.read(1_048_576),b''):h.update(block)
            require(h.hexdigest().upper()==expected_sha,'CLEANUP_IDENTITY_NOT_VERIFIED')
            class Disposition(ctypes.Structure):_fields_=[('DeleteFile',wintypes.BOOL)]
            disposition=Disposition(True)
            require(bool(k.SetFileInformationByHandle(wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno())),4,ctypes.byref(disposition),ctypes.sizeof(disposition))),'STORAGE_DELETE_UNCONFIRMED')
    finally:
        if fd is not None:os.close(fd)
        if handle is not None:k.CloseHandle(handle)
    require(not path.exists(),'STORAGE_DELETE_UNCONFIRMED')

def cleanup_staging(runtime,*,identity_verified,terminal,active_leases,container_absent):
    """Called only after existing owner verified CID/incarnation/nonce/processes.

    A complete transfer's source bytes are retained for Core re-verification.
    Incomplete staging is removable only if the approved original still matches.
    No recursive deletion, globs, images, volumes, caches or VM operations.
    """
    out=safe_path(runtime,EVIDENCE)
    require(identity_verified is True and terminal is True and active_leases==0 and type(active_leases) is int
            and container_absent is True,'CLEANUP_IDENTITY_NOT_VERIFIED')
    decisions=[]
    staged=safe_path(out/'ai-workspace-fixture',out,must_exist=False)
    if not staged.exists():return {'status':'NO_DISPOSABLE_STAGING','decisions':[],'deleted_bytes':0}
    safe_path(staged,out)
    info=staged.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'CLEANUP_IDENTITY_NOT_VERIFIED')
    if (out/'fixture-upload.json').exists() and read(out/'fixture-upload.json').get('exit_code')==0:
        return {'status':'PRESERVED_CORE_REFERENCE','decisions':[{'path':str(staged),'decision':'PRESERVE_COMPLETE_TRANSFER_SOURCE'}],'deleted_bytes':0}
    receipt=read(out/'stage-linux-fixture.json',16384)
    require(receipt.get('target')==str(staged),'CLEANUP_IDENTITY_NOT_VERIFIED')
    original=safe_path(receipt['source'],EVIDENCE)
    require(original!=staged and original.is_file() and info.st_size==receipt['bytes']
            and digest(staged)==digest(original)==receipt['sha256'],'CLEANUP_IDENTITY_NOT_VERIFIED')
    before=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
    remove_exact_file(staged,before,receipt['sha256'])
    decisions.append({'path':str(staged),'decision':'DELETE_DISPOSABLE_COPY','bytes':info.st_size,'approved_original_preserved':str(original)})
    return {'status':'DISPOSABLE_STAGING_CLEANED','decisions':decisions,'deleted_bytes':info.st_size}

def main():
    parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--admit-create',type=Path);group.add_argument('--admit-growth',type=Path)
    parser.add_argument('--profile',choices=['focus_trace71']);parser.add_argument('--incoming-bytes',type=int)
    args=parser.parse_args()
    try:
        result=admit_create(args.admit_create,args.profile) if args.admit_create else admit_growth(args.admit_growth,args.incoming_bytes)
        print(json.dumps(result));return 0 if result['decision']['status']=='ADMITTED' else 2
    except StorageRefusal as error:
        print(json.dumps({'status':'REFUSED','code':error.code,'automatic_retry_allowed':False}));return 2
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({'status':'REFUSED','code':'STORAGE_OBSERVATION_UNAVAILABLE','automatic_retry_allowed':False}));return 2
if __name__=='__main__':sys.exit(main())
