"""Read-only Windows injection evidence collection and bounded correlation.

API-entry sequences describe attempts, not successful execution or malicious intent.
No target code is executed and no process memory is modified by this module.
"""
from collections import deque
from functools import lru_cache
import struct
import time

INJECTION_APIS = set('VirtualAllocEx VirtualProtectEx WriteProcessMemory CreateRemoteThread '
                     'CreateRemoteThreadEx QueueUserAPC SetThreadContext Wow64SetThreadContext '
                     'ResumeThread NtAllocateVirtualMemory NtProtectVirtualMemory NtWriteVirtualMemory '
                     'NtCreateThreadEx NtQueueApcThread NtSetContextThread NtResumeThread '
                     'NtUnmapViewOfSection NtMapViewOfSection'.split())


@lru_cache(maxsize=1)
def _apis():
    import ctypes as c
    from ctypes import wintypes as w
    k = c.WinDLL('kernel32', use_last_error=True)
    n = c.WinDLL('ntdll', use_last_error=True)
    for name, result, args in (
        ('OpenProcess', c.c_void_p, [w.DWORD,w.BOOL,w.DWORD]),
        ('CloseHandle', w.BOOL, [c.c_void_p]),
        ('GetCurrentProcess', c.c_void_p, []),
        ('DuplicateHandle', w.BOOL, [c.c_void_p,c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p),w.DWORD,w.BOOL,w.DWORD]),
        ('GetProcessId', w.DWORD, [c.c_void_p]),
        ('GetProcessIdOfThread', w.DWORD, [c.c_void_p]),
        ('GetThreadId', w.DWORD, [c.c_void_p]),
        ('GetProcessTimes', w.BOOL, [c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p]),
    ):
        function = getattr(k, name)
        function.restype, function.argtypes = result, args
    n.NtQueryInformationProcess.restype = w.LONG
    n.NtQueryInformationProcess.argtypes = [c.c_void_p,w.ULONG,c.c_void_p,w.ULONG,c.c_void_p]
    return k,n


def capture_api_event(hooker, api, ctx, thread_id):
    """Resolve handles in the caller's handle table, including WOW64 callers."""
    if api not in INJECTION_APIS:
        return None
    import ctypes as c
    from windows_process_reader import filetime_to_unix
    k,_ = _apis()
    arg = lambda n: hooker._argument(ctx,n)
    thread_api = api in {'QueueUserAPC','NtQueueApcThread','SetThreadContext',
                        'Wow64SetThreadContext','NtSetContextThread','ResumeThread','NtResumeThread'}
    handle = arg(2 if api in ('QueueUserAPC','NtMapViewOfSection') else 4 if api=='NtCreateThreadEx' else 1)
    mask = 0xffffffff if hooker._wow64 else 0xffffffffffffffff
    if handle & mask in (mask,mask-1):
        return None  # current process/thread pseudo-handle: no remote operation
    event = {'source_pid':hooker.pid,'source_thread_id':thread_id,'api':api,
             'time':time.time(),'evidence':'api_entry','outcome':'unknown',
             'target_pid':None,'target_created_at':None,'target_thread_id':None}
    if not hooker._dup_ph:
        hooker._dup_ph = k.OpenProcess(0x40,False,hooker.pid)
    duplicate = c.c_void_p()
    if hooker._dup_ph and k.DuplicateHandle(hooker._dup_ph,handle,k.GetCurrentProcess(),c.byref(duplicate),0,False,2):
        try:
            pid = (k.GetProcessIdOfThread if thread_api else k.GetProcessId)(duplicate)
            event['target_pid'] = int(pid) or None
            if pid == hooker.pid:
                return None
            if api=='NtUnmapViewOfSection' and pid:
                from windows_process_reader import WindowsProcessReader
                reader = WindowsProcessReader(pid)
                try:
                    event['target_image_base'],_ = _peb_image_base(duplicate,
                        lambda at,size: reader.read_memory(duplicate,at,size))
                except OSError:
                    event['target_image_base'] = None
                # NtUnmapViewOfSection accepts any address inside the view.
                # Attribute the actual allocation, not proximity to the PEB base.
                region = reader.query_memory(duplicate, arg(2))
                event['unmap_allocation_base'] = int(region.AllocationBase or 0) if region else None
                event['unmap_memory_type'] = int(region.Type) if region else None
                event['unmaps_main_image'] = bool(region and region.State == 0x1000
                    and region.Type == 0x1000000 and event.get('target_image_base')
                    and event['unmap_allocation_base'] == event['target_image_base'])
            if thread_api:
                event['target_thread_id'] = int(k.GetThreadId(duplicate)) or None
            process = k.OpenProcess(0x1000,False,pid) if thread_api and pid else None
            try:
                times = [c.c_uint64() for _ in range(4)]
                if pid and k.GetProcessTimes(process if thread_api else duplicate, *(c.byref(v) for v in times)):
                    event['target_created_at'] = filetime_to_unix(times[0].value)
            finally:
                if process:
                    k.CloseHandle(process)
        finally:
            k.CloseHandle(duplicate)
    def pointer(at):
        size = 4 if hooker._wow64 else 8
        raw = hooker._read_mem(at,size)
        return int.from_bytes(raw,'little') if raw and len(raw)==size else 0
    if api in ('WriteProcessMemory','NtWriteVirtualMemory'):
        event.update(kind='write_memory',address=arg(2),size=arg(4))
    elif api in ('VirtualAllocEx','NtAllocateVirtualMemory'):
        event.update(kind='allocate_memory',address=arg(2) if api=='VirtualAllocEx' else pointer(arg(2)),
                     size=arg(3) if api=='VirtualAllocEx' else pointer(arg(4)))
    elif api in ('VirtualProtectEx','NtProtectVirtualMemory'):
        event.update(kind='protect_memory',address=arg(2) if api=='VirtualProtectEx' else pointer(arg(2)),
                     size=arg(3) if api=='VirtualProtectEx' else pointer(arg(3)),protection=arg(4))
    elif api in ('CreateRemoteThread','CreateRemoteThreadEx','NtCreateThreadEx'):
        event.update(kind='remote_thread',address=arg(5) if api=='NtCreateThreadEx' else arg(4),
                     parameter=arg(6) if api=='NtCreateThreadEx' else arg(5))
    elif api in ('QueueUserAPC','NtQueueApcThread'):
        event.update(kind='queue_apc',address=arg(1) if api=='QueueUserAPC' else arg(2))
    elif api in ('SetThreadContext','Wow64SetThreadContext','NtSetContextThread'):
        from windows_api_hooker import CONTEXT, WOW64_CONTEXT
        context_type = WOW64_CONTEXT if hooker._wow64 or api=='Wow64SetThreadContext' else CONTEXT
        raw = hooker._read_mem(arg(2),c.sizeof(context_type))
        event.update(kind='set_context',addresses=[])
        if raw and len(raw)==c.sizeof(context_type):
            value = context_type.from_buffer_copy(raw)
            if value.ContextFlags & 1:
                event['addresses'].append(value.Eip if context_type is WOW64_CONTEXT else value.Rip)
            if value.ContextFlags & 2:
                event['addresses'].append(value.Eax if context_type is WOW64_CONTEXT else value.Rcx)
    elif api in ('ResumeThread','NtResumeThread'):
        event.update(kind='resume_thread')
    elif api=='NtUnmapViewOfSection':
        event.update(kind='unmap_image',address=arg(2))
    else:
        event.update(kind='map_section',address=pointer(arg(3)))
    return event


def pe_identity(data):
    """Stable PE header fields; excludes relocations, imports and patched code."""
    try:
        if data[:2] != b'MZ':
            return None
        offset = struct.unpack_from('<I',data,60)[0]
        if offset > 16384-88 or data[offset:offset+4] != b'PE\0\0':
            return None
        machine = struct.unpack_from('<H',data,offset+4)[0]
        magic = struct.unpack_from('<H',data,offset+24)[0]
        if (machine,magic) not in ((0x14c,0x10b),(0x8664,0x20b)):
            return None
        return {'machine':machine,'timestamp':struct.unpack_from('<I',data,offset+8)[0],
                'entry_rva':struct.unpack_from('<I',data,offset+40)[0],
                'image_size':struct.unpack_from('<I',data,offset+80)[0]}
    except struct.error:
        return None


def _peb_image_base(handle, read):
    import ctypes as c
    _,n = _apis()
    wow_peb = c.c_void_p()
    status = n.NtQueryInformationProcess(handle,26,c.byref(wow_peb),c.sizeof(wow_peb),None)
    if status < 0:
        raise OSError(f'ProcessWow64Information: {status:#x}')
    if wow_peb.value:
        base_slot,size,architecture = wow_peb.value+8,4,'x86'
    else:
        basic = (c.c_void_p * 6)()
        status = n.NtQueryInformationProcess(handle,0,c.byref(basic),c.sizeof(basic),None)
        if status < 0 or not basic[1]:
            raise OSError(f'ProcessBasicInformation: {status:#x}')
        base_slot,size,architecture = basic[1]+16,8,'x64'
    raw = read(base_slot,size)
    if not raw or len(raw)!=size:
        raise OSError('PEB image base is unreadable')
    return int.from_bytes(raw,'little'),architecture


def inspect_process_image(pid, expected_birth):
    """Inspect the PEB image base without trusting the process's loader module list."""
    import psutil
    from windows_process_reader import WindowsProcessReader
    result = {'pid':pid,'created_at':expected_birth,'time':time.time(),'status':'unavailable','indicators':[]}
    reader = WindowsProcessReader(pid, expected_birth=expected_birth)
    handle = None
    try:
        process = psutil.Process(pid)
        if process.create_time() != expected_birth:
            result['reason'] = 'pid_reused'
            return result
        path = process.exe()
        # A target-controlled UNC path must not make the analyzer contact a server.
        if not path or path.startswith(('\\\\','//')):
            result['reason'] = 'non_local_image_path'
            return result
        handle = reader.get_process_handle()
        if not handle:
            raise OSError('Image memory is inaccessible')
        base,result['architecture'] = _peb_image_base(handle,lambda at,size: reader.read_memory(handle,at,size))
        result.update(image_base=base,path=path)
        mbi = reader.query_memory(handle,base)
        if not base or not mbi or mbi.State != 0x1000:
            result.update(status='observed',indicators=['image_base_not_committed'])
            return result
        result['memory_type'] = {0x1000000:'image',0x20000:'private',0x40000:'mapped'}.get(mbi.Type,'unknown')
        result['protection'] = mbi.Protect
        identity = pe_identity(reader.read_memory(handle,base,16384) or b'')
        with open(path,'rb') as image_file:
            disk_identity = pe_identity(image_file.read(16384))
        result.update(status='observed',memory_header=identity,disk_header=disk_identity)
        if mbi.Type != 0x1000000:
            result['indicators'].append('image_base_not_mem_image')
        if identity is None:
            result['indicators'].append('memory_pe_header_missing')
        if identity is not None and disk_identity is not None and identity != disk_identity:
            result['indicators'].append('pe_header_differs_from_disk')
        if not disk_identity:
            result['disk_comparison'] = 'unavailable'
    except (OSError,psutil.Error) as exc:
        result['reason'] = str(exc)
    finally:
        if handle:
            _apis()[0].CloseHandle(handle)
    return result


class InjectionMonitor:
    WINDOW_SECONDS = 30
    MAX_EVENTS = 2048
    MAX_FINDINGS = 256

    def __init__(self):
        self.history = deque(maxlen=self.MAX_EVENTS)
        self.finding_keys = set()
        self.report = {'status':'running','events':[],'findings':[],'images':{},
                       'events_dropped':0,'findings_dropped':0,'unresolved_targets':0,
                       'limits':{'events':self.MAX_EVENTS,'findings':self.MAX_FINDINGS,'correlation_seconds':self.WINDOW_SECONDS},
                       'limitations':['API entry is an attempted operation; return values are not collected.',
                                      'Direct syscalls and events before attachment can be missed.',
                                      'Image anomalies can also occur in legitimate packers and self-modifying applications.']}

    def _finding(self, kind, source, target, birth, address, evidence):
        source_birth = evidence[0].get('source_created_at') if source is not None else None
        key = (kind,source,source_birth,target,birth,address)
        if key in self.finding_keys:
            return
        if len(self.finding_keys)>=self.MAX_FINDINGS:
            self.report['findings_dropped'] += 1
            return
        self.finding_keys.add(key)
        self.report['findings'].append({'kind':kind,'classification':'candidate','source_pid':source,
            'source_created_at':source_birth,'target_pid':target,'target_created_at':birth,'address':address,'time':time.time(),
            'evidence':evidence,'execution_confirmed':False})

    def observe(self, event):
        now = event['time']
        while self.history and now-self.history[0]['time']>self.WINDOW_SECONDS:
            self.history.popleft()
        self.report['events'].append(event)
        if len(self.report['events'])>self.MAX_EVENTS:
            del self.report['events'][0]
            self.report['events_dropped'] += 1
        target,source,birth = event.get('target_pid'),event['source_pid'],event.get('target_created_at')
        if not target or birth is None or event.get('source_created_at') is None:
            self.report['unresolved_targets'] += 1
            return
        if target==source:
            return
        related = [e for e in self.history if e['source_pid']==source and e.get('source_created_at')==event.get('source_created_at')
                   and e.get('target_pid')==target and e.get('target_created_at')==birth and 0<=now-e['time']<=self.WINDOW_SECONDS]
        kind = event['kind']
        addresses = [event.get('address',0)]
        context = None
        if kind=='resume_thread' and event.get('target_thread_id'):
            context = next((e for e in reversed(related) if e['kind']=='set_context'
                            and e.get('target_thread_id')==event['target_thread_id']),None)
            addresses = context.get('addresses',[]) if context else []
        if kind in ('remote_thread','queue_apc') or context:
            write = next((e for e in reversed(related) if e['kind']=='write_memory' and e.get('size',0)>0
                          and (not context or e['time']<=context['time'])
                          and any(e['address']<=a<e['address']+e['size'] for a in addresses if a)),None)
            if write:
                unmap = next((e for e in reversed(related) if e['kind']=='unmap_image' and e['time']<=write['time']
                              and e.get('unmaps_main_image') is True),None) if context else None
                evidence = ([unmap] if unmap else [])+[write]+([context] if context else [])+[event]
                self._finding('hollowing_api_sequence' if unmap else 'remote_write_execution_sequence',
                              source,target,birth,write['address'],evidence)
        self.history.append(event)

    def observe_image(self, result):
        self.report['images'][str(result['pid'])] = result
        indicators = result.get('indicators',[])
        # RWX, a missing header, or a header difference alone is not sufficient.
        if result['status']=='observed' and 'image_base_not_mem_image' in indicators and (
                'memory_pe_header_missing' in indicators or 'pe_header_differs_from_disk' in indicators):
            self._finding('hollowing_image_anomaly',None,result['pid'],result['created_at'],
                          result['image_base'],[result])
