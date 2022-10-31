# use debugging API and triton to triage the crashes

r"""
build triton with

mkdir build
cd build
cmake -G "Visual Studio 16 2019" -A x64 -DPYTHON_INCLUDE_DIRS="C:\Program Files\Python38\include" -DPYTHON_LIBRARIES="C:\Program Files\Python38\libs\python38.lib" -DZ3_INCLUDE_DIRS="C:\Users\jorda\source\z3-4.11.0-x64-win\include" -DZ3_LIBRARIES="C:\Users\jorda\source\z3-4.11.0-x64-win\bin\libz3.lib" -DCAPSTONE_INCLUDE_DIRS="C:\Users\jorda\source\capstone\include" -DCAPSTONE_LIBRARIES="C:\Users\jorda\source\capstone\msvc\x64\Release\capstone.lib" ..

Also had to drag the z3 python dll into the same folder as the triton dll, so it could find the dep
"""

from multiprocessing import Process
from ctypes import *
try:
    import termcolor
except:
    termcolor = None
import struct
import time
import sys
import os

# update the path
# be sure to import same z3 used to build triton

sys.path.append(r"C:\Users\jorda\source\z3-4.11.0-x64-win\bin\python")
sys.path.append(r"C:\Users\jorda\source\Triton\build\src\libtriton\Release")

from triton import *

from win_types import *

# verbosity settings
# 0-5 with 1 being only print the most important, 5 being print everything
VERB = {
    "process": 3,
    "dbgevents": 2,
    "inst": 2,
    "hook": 5,
    "crash": 4,
    "profile": 3,
}

def log(key, priority, message):
    if priority > VERB[key]:
        return

    if termcolor is not None:
        # get all colorful here
        color = {
            0: "white",
            1: "red",
            2: "cyan",
            3: "green",
            4: "blue",
            5: "magenta",
        }[priority]

        message = termcolor.colored(message, color)

    #TODO process ID as well, if using multiprocessing

    print(f"[{key}] : ", message, flush=True)

class TriagerException(Exception):
    def __init__(self, message):
        super().__init__(message)

        # to be filled out by the stepper if we have an associated symbolic instruction
        self.symbinst = None # can be a Instruction or a string, so check
        self.extracond = None

class UnexpectedEvent(TriagerException):
    def __init__(self, message, event):
        super().__init__(message)
        self.event = event

class UnexpectedException(UnexpectedEvent):
    def __init__(self, message, event):
        super().__init__(message, event)
        er = event.u.Exception.ExceptionRecord
        self.er = er

class UnexpectedVuln(TriagerException):
    pass

def gle():
    return windll.kernel32.GetLastError()

def connect_debugger(proccmd):
    # CreateProcessA
    flags = 0
    flags |= 0x1 # DEBUG_PROCESS
    flags |= 0x2 # DEBUG_ONLY_THIS_PROCESS

    strtinfo = STARTUPINFOA()
    strtinfo.cb = sizeof(strtinfo)
    strtinfo.dwFlags = 1 # STARTF_USE_SHOWWINDOW
    strtinfo.wShowWindow = 1 # SW_NORMAL

    procinfo = PROCESS_INFORMATION()

    res = windll.kernel32.CreateProcessW(
        None,
        proccmd,
        None,
        None,
        0,
        flags,
        None,
        None,
        byref(strtinfo),
        byref(procinfo) # output
    )

    if res == 0:
        raise Exception(f"Failure to create process, got result {res}: GLE 0x{gle():x}")

    handle = procinfo.hProcess
    log("process", 2, f"started process {procinfo.dwProcessId}:{procinfo.dwThreadId}")

    windll.kernel32.CloseHandle(procinfo.hThread)

    # WaitForDebugEvent wait for inital attach
    event = dbg_wait(handle, None, ignore=())
    dbg_cont(event)

    return handle, procinfo.dwThreadId

def dbg_until(handle, addr, event):
    # place breakpoint, execute until we hit it
    dbg_bp(handle, addr)
    
    # wait for debug breakpoint to be hit, ignore other debug events except second chance exceptions or process exit
    event = dbg_wait(handle, event, ignore=(2, 3, 4, 6, 7, 8), catchfirst=(EXCEPTION_BREAKPOINT,))

    # if it is not a breakpoint, freak out?
    if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT:
        raise UnexpectedEvent(f"Expected to continue until breakpoint, but got event {event.dwDebugEventCode}", event)
    er = event.u.Exception.ExceptionRecord
    if er.ExceptionCode != EXCEPTION_BREAKPOINT:
        raise UnexpectedException(f"Expected to continue until breakpoint, but got exception: {exceptionstr(handle, er, event.dwThreadId)}", event)

    dbg_bp_restore(handle, addr)

    # now move RIP back
    tid = event.dwThreadId
    regs = dbg_get_regs(tid)

    if regs.Rip != addr + 1:
        raise Exception(f"Got a breakpoint in until, but not the one we expected! @{regs.RIP:x}, not {addr:x}")

    regs.Rip = addr
    dbg_set_regs(tid, regs)

    return event

def dbg_step(handle, tid, event, regs=None, ins=None):
    # Setting trap flag doesn't work when we hit a syscall
    # so we need to do a normal breakpoint there

    # get instruction
    if ins is None:
        if regs is None:
            regs = dbg_get_regs(tid)
        addr = regs.Rip
        data = dbg_read(handle, addr, 15)
        ins = Instruction(addr, data)
    
    # handle special cases
    #TODO
    # stop the stepping if we are about to do a until
    # dbg_stop_step(tid, regs, checkstep=False)
    
    # otherwise just set the single step flag
    if regs is None:
        regs = dbg_get_regs(tid)

    regs.EFlags |= 0x100 # turn on the trap flag
    dbg_set_regs(tid, regs)

    # expect EXCEPTION_SINGLE_STEP
    event = dbg_wait(handle, event, ignore=(2,3,4,6,7,8), catchfirst=(EXCEPTION_SINGLE_STEP,))
    etid = event.dwThreadId
    # if it is not a breakpoint, freak out?
    if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT:
        raise UnexpectedEvent(f"Expected to singlestep {tid}, but got event for {etid} {event.dwDebugEventCode}", event)

    er = event.u.Exception.ExceptionRecord
    
    if er.ExceptionCode != EXCEPTION_SINGLE_STEP:
        raise UnexpectedException(f"Expected to singlestep {tid}, but got exception: {exceptionstr(handle, er, etid)}", event)

    return event

def dbg_kill(handle):
    # stop debugging and kill the proc
    #TODO must still have an open handle somewhere? window isn't closing
    windll.kernel32.TerminateProcess(handle, 0)
    windll.kernel32.CloseHandle(handle)

# Global dictionary of open thread handles, so we can quickly look them up by tid
thandles = {}

def dbg_wait(handle, event, ignore=(6, 7, 4, 2), catchfirst=()):
    # this function will wait for the next debug event, ignoring certain events as needed

    if event is None:
        event = DEBUG_EVENT()
    else:
        # continue from this last event
        dbg_cont(event, DBG_CONTINUE)

    # loop while hitting events we want to ignore
    while True:
        status = DBG_CONTINUE

        res = windll.kernel32.WaitForDebugEvent(byref(event), 0xffffffff)
        if res == 0:
            raise Exception(f"Failure to debug wait, got result {res}: GLE 0x{gle():x}")

        code = event.dwDebugEventCode
        log("dbgevents", 3, f"Event: {event.dwProcessId}:{event.dwThreadId} {code}")

        # save/remove thread handles as threads/processes are created/destroyed
        # so we can do get/set context with just thread ids and not have to open new ones
        if code == CREATE_PROCESS_DEBUG_EVENT:
            # create process, save main thread handle
            thandles[event.dwThreadId] = event.u.CreateProcessInfo.hThread
        elif code == CREATE_THREAD_DEBUG_EVENT:
            # create thread, save thread hande
            thandles[event.dwThreadId] = event.u.CreateThread.hThread
        elif code == EXIT_THREAD_DEBUG_EVENT:
            # thread exit, remove thread handle
            del thandles[event.dwThreadId]

        if code not in ignore:
            skip = False
            if code == EXCEPTION_DEBUG_EVENT:
                status = DBG_EXCEPTION_NOT_HANDLED
                fc = event.u.Exception.dwFirstChance
                er = event.u.Exception.ExceptionRecord
                log("dbgevents", 3 if fc != 1 else 5, f"Got Exception{' (1st chance)' if fc else ''} {exceptionstr(handle, er, event.dwThreadId)}")
                ecode = er.ExceptionCode
                if fc != 0 and ecode not in catchfirst:
                    skip = True

                if ecode == EXCEPTION_BREAKPOINT:
                    # check if we have a cooresponding breakpoint we placed
                    # we want to skip LdrpDoDebuggerBreak
                    if er.ExceptionAddress not in bp_orig_bytes:
                        skip = True
                        log("dbgevents", 4, f"Skipping Unknown bp @ 0x{er.ExceptionAddress:x}")

            if not skip:
                break

        dbg_cont(event, status)

    return event

def dbg_clean_event(event):
    # Docs are not super clear about what handles need to be closed by us
    # but this will close the ones I think we need to close
    if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT: # EXCEPTION
        pass
    elif event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT: # CREATE_THREAD
        #hnd = event.u.CreateThread.hThread
        #if hnd != 0:
        #    windll.kernel32.CloseHandle(hnd)
        pass
    elif event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT: # CREATE_PROCESS
        hnd = event.u.CreateProcessInfo.hFile
        if hnd != 0:
            windll.kernel32.CloseHandle(hnd)
        #hnd = event.u.CreateProcessInfo.hProcess
        #if hnd != 0:
        #    windll.kernel32.CloseHandle(hnd)
        #hnd = event.u.CreateProcessInfo.hThread
        #if hnd != 0:
        #    windll.kernel32.CloseHandle(hnd)
    elif event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT: # EXIT_THREAD
        pass
    elif event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT: # EXIT_PROCESS
        pass
    elif event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT: # LOAD_DLL
        hnd = event.u.LoadDll.hFile
        if hnd != 0:
            windll.kernel32.CloseHandle(hnd)
    elif event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT: # UNLOAD_DLL
        pass
    elif event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT: # DBG_STRING
        pass
    elif event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT: # UNLOAD_DLL
        pass
    else:
        raise Exception(f"Unknown debug event! {event.dwDebugeEventCode}")

def dbg_cont(event, status=DBG_CONTINUE):
    # shouldn't be called directly, use dbg_wait or dbg_until or whatever
    dbg_clean_event(event)
    dbg_cont_id(event.dwProcessId, event.dwThreadId, status)

def dbg_cont_id(proc, thread, status=DBG_CONTINUE):
    res = windll.kernel32.ContinueDebugEvent(proc, thread, status)
    if res == 0:
        raise Exception(f"Failure to debug cont, got result {res}: GLE 0x{gle():x}")

def dbg_read(handle, addr, sz):
    buf = (c_byte * sz)()
    outsz = c_size_t()

    res = windll.kernel32.ReadProcessMemory(handle, c_void_p(addr), byref(buf), sz, byref(outsz))
    
    if res == 0:
        raise Exception(f"Failure to read proc mem at 0x{addr:x}, got result {res}: GLE 0x{gle():x}")
    
    if outsz.value != sz:
        raise Exception(f"Failure to read proc mem sufficiently , read {outsz.value} instead of {sz}")

    return bytes(buf)

def dbg_readA(handle, addr):
    i = 0
    data = b""
    while True:
        c = dbg_readb(handle, addr + i)
        if c == 0:
            break

        i += 1

        data = data + bytes([c])
    return data

def dbg_readq(handle, addr):
    b = dbg_read(handle, addr, 8)
    return struct.unpack("<Q", b)[0]

def dbg_readd(handle, addr):
    b = dbg_read(handle, addr, 4)
    return struct.unpack("<I", b)[0]

def dbg_readw(handle, addr):
    b = dbg_read(handle, addr, 2)
    return struct.unpack("<H", b)[0]

def dbg_readb(handle, addr):
    b = dbg_read(handle, addr, 1)
    return b[0]

def dbg_write(handle, addr, data):
    sz = len(data)
    t = c_byte * sz
    buf = t.from_buffer_copy(data)
    outsz = c_size_t()
    res = windll.kernel32.WriteProcessMemory(handle, c_void_p(addr), buf, sz, byref(outsz))

    if res == 0:
        raise Exception(f"Failure to write proc mem, got result {res}: GLE 0x{gle():x}")
    
    if outsz.value != sz:
        raise Exception(f"Failure to write proc mem sufficiently , wrote {outsz.value} instead of {sz}")

def dbg_maps(handle):
    # get the PEB, find the LDR stuff, find the base address
    bi = PROCESS_BASIC_INFORMATION()

    stat = windll.ntdll.NtQueryInformationProcess(
        handle,
        0, # ProcessBasicInformation
        byref(bi),
        sizeof(bi),
        0
    )
    
    if stat != 0:
        raise Exception(f"Failure to find target PEB, got status 0x{stat:x}")

    # get PEB+0x18 (PEB_LDR_DATA*)
    ldrptr = dbg_readq(handle, bi.PebBaseAddress + 0x18)

    if ldrptr == 0:
        # nothing yet
        return []

    listhead = ldrptr + 0x10
    entry = dbg_readq(handle, ldrptr + 0x10)

    loaded = {}
    while entry != listhead:
        # at each entry, grab the DllBase and FullDllName
        base = dbg_readq(handle, entry+0x30)
        nameus = UNICODE_STRING.from_buffer_copy(dbg_read(handle, entry+0x48, 0x10))
        namedata = dbg_read(handle, nameus.Buffer, nameus.Length)
        name = str(namedata, "utf-16-le")

        loaded[name] = base

        # follow ldrdata.InLoadOrderModuleList.Flink to the LDR_DATA_TABLE_ENTRY structures until we circle back
        entry = dbg_readq(handle, entry)

    return loaded

def dbg_get_imports_from(handle, pebase, dllnames):
    dllnames = [x.lower() for x in dllnames]
    out = {}
    # we could add hooks to every export of those dlls by going through the LDR_DATA_TABLE_ENTRYs (like in dbg_maps) and their EATs
    # but that seems wasteful? Let's just use the IAT of the pe we care about?

    # cast base to IMAGE_DOS_HEADER
    # follow e_lfanew to the IMAGE_NT_HEADERS64
    ntheaders_rva = dbg_readd(handle, pebase + 0x3c)
    # Follow the optional header's data_directory[1(IAT_ENTRY)]
    imptab_rva = dbg_readd(handle, pebase + ntheaders_rva + 0x18 + 0x70 + (1 * 0x8))

    # for each entry in the table of IMAGE_IMPORT_DESCRIPTOR (until a NULL entry)
    imgdesc = imptab_rva + pebase
    while True:
        origft_rva = dbg_readd(handle, imgdesc + 0x0)

        if origft_rva == 0:
            break

        # use the Name RVA to check it is a DLL worth following
        name_rva = dbg_readd(handle, imgdesc + 0xc)
        namedata = dbg_readA(handle, pebase + name_rva)
        name = str(namedata, "ascii")
        log("process", 5, f"PE imports from {name}")
        
        if name.lower() in dllnames:
            ft_rva = dbg_readd(handle, imgdesc + 0x10)

            # if it is, go over all the firstthunks, adding a hook there
            # we check that the import has been resolved too


            i = 0
            while True:
                orig_val = dbg_readq(handle, pebase + origft_rva + (i*8))
                val = dbg_readq(handle, pebase + ft_rva + (i*8))

                i += 1
                if val == 0:
                    break
                elif orig_val == val:
                    raise Exception("Tried to get imports from a dll that has not been resolved")

                # know the name by going through the originalfirstthunk if we wanted
                fname = ""
                if orig_val & 0x80000000:
                    # ordinal
                    fname = f"#0x{orig_val & 0xffff}"
                else:
                    fname_rva = orig_val & 0x7fffffff
                    fnamedata = dbg_readA(handle, pebase + fname_rva + 2)
                    fname = str(fnamedata, "ascii")


                fname = name +"!"+ fname

                # okay! add the address so it can get hooked
                out[fname] = val

        imgdesc += 0x14

    return out

bp_orig_bytes = {}
def dbg_bp(handle, addr):
    ob = dbg_read(handle, addr, 1)
    bp_orig_bytes[addr] = ob

    dbg_write(handle, addr, b'\xcc')

def dbg_bp_restore(handle, addr):
    ob = bp_orig_bytes[addr]

    dbg_write(handle, addr, ob)

    # make sure RIP gets reset too! It will be pointer after the 0xCC if we don't do something about it

def dbg_get_regs(tid, regcontext=CONTEXT_FULL):
    # Note: thread must be suspended

    thandle = thandles[tid]
    regs = CONTEXT()

    # set regs.ContextFlags to specify portion of context to get
    regs.ContextFlags = regcontext

    res = windll.kernel32.GetThreadContext(thandle, byref(regs))

    if res == 0:
        raise Exception(f"Failure to get thread context, got result {res}: GLE 0x{gle():x}")

    return regs

def dbg_set_regs(tid, regs, regcontext=CONTEXT_FULL):
    thandle = thandles[tid]

    # set regs.ContextFlags to specify portion of context to set
    regs.ContextFlags = regcontext

    res = windll.kernel32.SetThreadContext(thandle, byref(regs))

    if res == 0:
        raise Exception(f"Failure to set thread context, got result {res}: GLE 0x{gle():x}")

def exceptionstr_single(er, tid):
    ecode = er.ExceptionCode
    addr = er.ExceptionAddress
    estr = f"({tid}){ecode2str.get(ecode, '???')}(0x{ecode:x}) @ 0x{addr:x}"
    if ecode == EXCEPTION_ACCESS_VIOLATION or ecode == EXCEPTION_IN_PAGE_ERROR:
        estr += " "
        if er.ExceptionInformation[0] == 0:
            estr += "read"
        elif er.ExceptionInformation[0] == 1:
            estr += "write"
        elif er.ExceptionInformation[0] == 8:
            estr += "exec"
        else:
            raise Exception("Unknown param for access violation record")
        estr += f" at 0x{er.ExceptionInformation[1]:x}"

    if ecode == EXCEPTION_IN_PAGE_ERROR:
        estr += f" code 0x{er.ExceptionInformation[2]:x}"

    return estr

def exceptionstr(handle, er, tid):
    out = []
    while er != None:
        out.append(exceptionstr_single(er, tid))
        ner = er.ExceptionRecord
        if ner != None:
            sz = sizeof(er)
            data = dbg_read(handle, ner, sz)
            er = EXCEPTION_RECORD()
            memmove(pointer(er), data, sz)
        else:
            er = None
    
    return ' -- '.join(out)

# a global set of loaded memory pages so we know what needs to be lazy loaded
loaded_pgs = set()

def tri_load_dbg_mem(ctx, handle, addr, sz, skip_write=False):
    # do lazy loading of memory into triton from the debugger
    global loaded_pgs

    endaddr = addr + sz
    pgaddr = addr >> 12
    endpgaddr = endaddr >> 12

    for p in range(pgaddr, endpgaddr+1):
        if p in loaded_pgs:
            continue

        a = p << 12

        log("process", 5, f"Loading page 0x{a:x} from debugger ({addr:x}, {sz:x})")

        try:
            data = dbg_read(handle, a, 0x1000)
        except Exception as e:
            log("process", 1, f"WARN: When loading mem: {e}")
            continue

        loaded_pgs.add(p)

        if not skip_write:
            # if it is just a read, we do not need to skip any piece of this
            ctx.setConcreteMemoryAreaValue(a, data, callbacks=False)
        else:
            # do not overwrite the area being written to
            # that will desync the symbolic and concrete data there
            if a < addr:
                # write up until the address
                d = data[:addr - a]
                ctx.setConcreteMemoryAreaValue(a, d, callbacks=False)
            if (a + 0x1000) > (addr + sz):
                # write after the area
                s = (addr + sz) - a
                d = data[s:]
                ctx.setConcreteMemoryAreaValue((addr+sz), d, callbacks=False)

# registers for checking each step
# to ensure we are in sync
checkregs = {x:x.lower() for x in 
    ["Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip", "Xmm0", "Xmm1", "Xmm2", "Xmm3", "Xmm4", "Xmm5", "Xmm6", "Xmm7", "Xmm8", "Xmm9", "Xmm10", "Xmm11", "Xmm12", "Xmm13", "Xmm14", "Xmm15", "EFlags"]
}

# registers to sync at the beginning, but not necissarily checked each step
syncregs = checkregs.copy()

def tri_copy_regs(ctx, tid):
    # sync triton's register state with the debugger's ground truth
    # should only be done once at the beginning, this will lose symbolic information

    regs = dbg_get_regs(tid, CONTEXT_FULL)
    # set GS_base based on getting the TEB of the thread
    tbi = THREAD_BASIC_INFORMATION()
    res = windll.ntdll.NtQueryInformationThread(
        thandles[tid],
        0, # ThreadBasicInformation
        byref(tbi),
        sizeof(tbi),
        0
    )
    
    if res != 0:
        raise Exception(f"Failed calling NtQueryInformationThread with status 0x{res:x}")

    # set GS (used on x64 to point to TIB)
    # triton's GS is not a selector, but the actual gs_base
    ctx.setConcreteRegisterValue(ctx.registers.gs, tbi.TebBaseAddress)

    for r in syncregs:
        tr = syncregs[r]
        rv = getattr(regs, r)
        if isinstance(rv, M128A):
            rv = rv.Low | (rv.High << 64)
        elif r.startswith("Seg"):
            # could use values from GetThreadSelectorEntry to get base for segments on 32 bit
            # but just ignore them here on x64
            pass

        tri_reg = getattr(ctx.registers, tr)
        ctx.setConcreteRegisterValue(tri_reg, rv)

def tri_check_regs(ctx, regs, inst=None, warn=False):
    # called each step, to make sure we are in sync
    # because we don't emulate everything (syscalls, some hooked funcs) desync is unavoidable sometimes

    for r in checkregs:
        tr = checkregs[r]
        rv = getattr(regs, r)
        if isinstance(rv, M128A):
            rv = rv.Low | (rv.High << 64)
        tri_reg = getattr(ctx.registers, tr)
        tv = ctx.getConcreteRegisterValue(tri_reg)
        if tv != rv:
            if r == "EFlags" and ((tv ^ rv) & 0xC0) == 0:
                # only adjust certain vital flags
                # triton seems to get certain flags wrong often with certain avx instructions
                # could be they are undefined
                continue

            if warn:
                log("inst", 3, f"WARN: {r} desync after {inst}: ({rv:x}, {tv:x})")

            ctx.setConcreteRegisterValue(tri_reg, rv)

def tri_init(handle, onlyonsym=False, memarray=False):
    # do the base initialization of a TritonContext

    ctx = TritonContext(ARCH.X86_64)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, onlyonsym)
    if memarray:
        ctx.setMode(MODE.MEMORY_ARRAY, True)
    else:
        ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

    # set lazy memory loading
    def getmemcb(ctx, ma):
        addr = ma.getAddress()
        sz = ma.getSize()
        # will only load pages that have not been previously loaded
        tri_load_dbg_mem(ctx, handle, addr, sz, False)

    def setmemcb(ctx, ma, val):
        addr = ma.getAddress()
        sz = ma.getSize()
        # will only load pages that have not been previously loaded
        tri_load_dbg_mem(ctx, handle, addr, sz, True)

    ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, getmemcb)
    ctx.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, setmemcb)

    return ctx

def tri_q(ctx, addr):
    # read a q word
    return struct.unpack("<Q", ctx.getConcreteMemoryAreaValue(addr, 0x8))[0]

def hook_return(ctx, handle, tid, event):
    # return the triton instance to the return value without evaluating the function
    # and also will continue the debugger until the return value

    # assumes this is called at the start of a hooked function, with rsp pointing to the return
    # also assumes a calling convention that is caller cleanup

    # pop the return address off the stack
    rsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
    ret = tri_q(ctx, rsp)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, rsp+8)

    # place Triton there
    ctx.setConcreteRegisterValue(ctx.registers.rip, ret)

    # go until the return in the debugger
    event = dbg_until(handle, ret, event)
    if event.dwThreadId != tid:
        raise Exception("dbg_until stopped a different thread at our target return address!")

    # clear up return values
    regs = dbg_get_regs(tid)

    #TODO here we should concretize volatile registers and shadow space
    tri_check_regs(ctx, regs, inst=None, warn=False)

    # after this, hooks can symbolize returned values/buffers as needed
    return event, regs

HOOK_STAT_NONE = 0
HOOK_STAT_STEPPED = 1
HOOK_STAT_DIDRET = 2

def skipfunc_hook(ctx, handle, tid, event, hooks, arg):
    name = arg
    rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
    log("hook", 5, f"skipping emulation at {rip:x}({name})")

    try:
        event, regs = hook_return(ctx, handle, tid, event)
    except TriagerException as e:
        # extend the exception with info that we are in a hook
        e.symbinst = f"skipfunc hook @ {rip:x} ({name})"
        raise e

    return event, regs, HOOK_STAT_DIDRET

def memset_hook(ctx, handle, tid, event, hooks, arg):
    # a hook for memset
    # hooks return event, regs, and a bool indicating if they handled the inst or not

    # rcx is the buffer
    # rdx is the value for filling
    # r8 is the size

    dst = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    val = ctx.getConcreteRegisterValue(ctx.registers.rdx) & 0xff
    size = ctx.getConcreteRegisterValue(ctx.registers.r8)

    log("hook", 3, f"memset(0x{dst:x}, 0x{val:x}, 0x{size:x})")

    if ctx.isRegisterSymbolized(ctx.registers.rcx) or ctx.isRegisterSymbolized(ctx.registers.r8):
        astctx = ctx.getAstContext()
        rcxast = ctx.getRegisterAst(ctx.registers.rcx)
        r8ast = ctx.getRegisterAst(ctx.registers.r8)
        bufendast = astctx.bvadd(rcxast, r8ast)
        bufendcon = dst + size

        log("hook", 3, "Symbolic memset argument!")
        log("hook", 4, f"base: {ctx.simplify(rcxast, True)}")
        log("hook", 4, f"size: {ctx.simplify(r8ast, True)}")

        #TODO use solver to check if bufend can be controlled to invalid locations
        # for now let's see if we can get away with a leaky check of, could the size be greater than x bigger
        # ((bufendcon + x) <= bufendast)
        testpast = 0xf1414141
        cond = ((bufendcon + testpast) <= bufendast)
        cond = astctx.land([cond, ctx.getPathPredicate()])
        log("hook", 5, "Trying to solve for a big memset")
        model, status, _ = ctx.getModel(cond, True)
        if status == SOLVER_STATE.SAT:
            # can go that far
            # this may not be the cause of our crash though, so let's just report it, not raise it
            # investigating these, they are on a dynamic buffer, so it just allocates a ton
            log("crash", 2, "Symbolic memset could go really far!")

            # uncomment this raise to output a testcase file for it

            #e = UnexpectedVuln("Symbolic memset can go really far!")
            # add the conditions for building to here
            #e.extracond = ((bufendcon + testpast) <= bufendast)
            #raise e

    try:
        event, regs = hook_return(ctx, handle, tid, event)
    except TriagerException as e:
        # extend the exception with info that we are in a memcpy hook
        e.symbinst = "memset hook"
        raise e

    # here we should actually do the memset on the triton side as well
    # but we wont for huge cases, because it is killing our perf
    if size <= 0x10000:
        ctx.setConcreteMemoryAreaValue(dst, bytes([val]) * size)
    else:
        log("hook", 2, f"memset hook skipping emulating memset with size 0x{size:x}")

    # if size and such are controlled, we could also symbolize record the before and apply a symbolic condition to the values that got set with an ITE, and past it as possible
    
    return event, regs, HOOK_STAT_DIDRET

def memcpy_hook(ctx, handle, tid, event, hooks, arg):
    # rcx is the buffer
    # rdx is the value for filling
    # r8 is the size

    dst = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    src = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    size = ctx.getConcreteRegisterValue(ctx.registers.r8)

    log("hook", 3, f"memcpy(0x{dst:x}, 0x{src:x}, 0x{size:x})")

    docheck = False
    if ctx.isRegisterSymbolized(ctx.registers.rcx):
        ast = ctx.getRegisterAst(ctx.registers.rcx)
        ast = ctx.simplify(ast, True)
        log("hook", 4, f"Symbolic memcpy dst: {ast}")
        docheck = True

    if ctx.isRegisterSymbolized(ctx.registers.rdx):
        ast = ctx.getRegisterAst(ctx.registers.rdx)
        ast = ctx.simplify(ast, True)
        log("hook", 4, f"Symbolic memcpy src: {ast}")

    if ctx.isRegisterSymbolized(ctx.registers.r8):
        ast = ctx.getRegisterAst(ctx.registers.r8)
        ast = ctx.simplify(ast, True)
        log("hook", 4, f"Symbolic memcpy size: {ast}")
        docheck = True

    # check for bad memcpy symbolically here
    # these checks are not super needed during triage though, we already have a crash
    # just want more information when we hit the crash
    if docheck and False:
        astctx = ctx.getAstContext()
        cond = ctx.getPathPredicate()
        # dst + size
        dstendast = ctx.getRegisterAst(ctx.registers.rcx) + ctx.getRegisterAst(ctx.registers.r8)
        # concrete value of the dst + size
        dstendcon = dst + size
        testpast = 0x414141
        cond = astctx.land([cond, (dstendcon + testpast) <= dstendast])

        log("hook", 5, "Trying to solve for a big memcpy")
        model, status, _ = ctx.getModel(cond, True)
        if status == SOLVER_STATE.SAT:
            # can go that far
            # this may not be the cause of our crash though, so let's just report it, not raise it
            log("crash", 2, "Symbolic memcpy could go really far!")



    # do the actual memcpy in dbg
    try:
        event, regs = hook_return(ctx, handle, tid, event)
    except TriagerException as e:
        # extend the exception with info that we are in a memcpy hook
        e.symbinst = "memcpy hook"
        raise e

    # do the memcpy in triton
    data = ctx.getConcreteMemoryAreaValue(src, size)
    ctx.setConcreteMemoryAreaValue(dst, data)

    # keep the symbolic information too
    # we don't handle overlapping memmove correctly here, because we pull in already overwritten stuff
    for i in range(size):
        sa = MemoryAccess(src + i, 1)
        da = MemoryAccess(dst + i, 1)
        cell = ctx.getMemoryAst(sa)
        expr = ctx.newSymbolicExpression(cell, "memcpy byte")
        ctx.assignSymbolicExpressionToMemory(expr, da)

    return event, regs, HOOK_STAT_DIDRET

def domapview_hook(ctx, handle, tid, event, hooks, arg):
    # a hook for a call to MapViewOfFile that happens

    # hooks return event, regs, and a bool indicating if they handled the inst or not

    # record the arguments we care about
    offset = (ctx.getConcreteRegisterValue(ctx.registers.r8) & 0xffffffff) << 32
    offset |= (ctx.getConcreteRegisterValue(ctx.registers.r9) & 0xffffffff)

    rsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
    size = tri_q(ctx, rsp + 0x20)

    rip = ctx.getConcreteRegisterValue(ctx.registers.rip)

    log("hook", 3, f"@{rip:x}: MapViewOfFile(offset=0x{offset:x}, size=0x{size:x})")

    # register a hook for the next instruction, with that data    
    
    hooks[rip + 6] = (aftermapview_hook, (offset, size))

    # or we could walk the debugger until then, not trace those inst if we wanted to

    return event, None, HOOK_STAT_NONE

def aftermapview_hook(ctx, handle, tid, event, hooks, arg):
    offset, size = arg
    addr = ctx.getConcreteRegisterValue(ctx.registers.rax)
    log("hook", 3, f"MapViewOfFile returned 0x{addr:x}, remapping symbols")

    # if it fails, let it fail, no remapping to do
    if addr == 0:
        return event, None, HOOK_STAT_NONE

    # we need to symbolize now!
    # We are going to assume the file hasn't changed since mapped last
    # Which might be a bad assumption? But our fuzzer didn't try to find toctou
    # so shouldn't matter for us

    astctx = ctx.getAstContext()

    # should probably hold on to these in a different way
    # here we assume that the whole file was mapped earlier, and the mapping here won't extend
    # this is fine for our target this time, but should be checked for other stuff
    vars = ctx.getSymbolicVariables()

    for i in range(size):
        a = addr + i
        off = offset + i

        # saw some strange mappings happening in some, just bypass those?
        if off not in vars:
            continue

        name = f"INPUT_{off:x}"
        var = vars[off]

        # test to be sure
        if var.getAlias() != name:
            raise Exception(f"Vars not laid out as expected @0x{off:x} {var.getAlias()} != {name}")

        # be careful not to double define the variables
        varast = astctx.variable(var)
        expr = ctx.newSymbolicExpression(varast, "remapped")
        ctx.assignSymbolicExpressionToMemory(expr, MemoryAccess(a, 1))

    return event, None, HOOK_STAT_NONE

def reg_deref_inspect_hook(ctx, handle, tid, event, hooks, arg):
    # for easy debugging, see what a value pointed to is at given points

    rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for reg, offset in arg:
        rv = ctx.getConcreteRegisterValue(reg)
        addr = rv + offset
        v = tri_q(ctx, addr)
        log("hook", 1, f"@{rip:x} DEBUG inspect 0x{addr:x}: 0x{v:x}")

    return event, None, HOOK_STAT_NONE

def failearly_hook(ctx, handle, tid, event, hooks, arg):
    log("crash", 2, "Process detected bad input")
    raise Exception("Errored out with bad input")

def dual_step(ctx, handle, tid, event, hooks, regs=None):
    # step both the debugger and triton
    # step triton first
    # in case memory changes and we pull in the updated instructions
    # this has the bad side effect of we execute the faulting instruction, so we might have to stop earlier on later runs
    # for example if mov edx, [rdx] is executed by triton, but crashes in the dbg, we just lost the symbolic info in rdx

    ip = ctx.getConcreteRegisterValue(ctx.registers.rip)

    if ip in hooks:
        hookfun, privarg = hooks[ip]
        event, regs, hook_stat = hookfun(ctx, handle, tid, event, hooks, privarg)
        if hook_stat == HOOK_STAT_DIDRET:
            return (event, regs, None, -1)
        elif hook_stat == HOOK_STAT_STEPPED:
            return (event, regs, None, None)
        elif hook_stat == HOOK_STAT_NONE:
            # need to do the instruction still
            pass
        else:
            raise Exception(f"Unknown hook status {hook_stat}")

    data = ctx.getConcreteMemoryAreaValue(ip, 15)
    inst = Instruction(ip, data)

    fixup = False
    exc = ctx.processing(inst)
    if EXCEPTION.FAULT_UD == exc:
        # skip this instruction
        log("inst", 2, f"WARN: unknown instruction: {inst}")
        fixup = True
    elif EXCEPTION.NO_FAULT != exc:
        #TODO handle these
        raise Exception(f"Triton Exception ({exc}) processing instruction at 0x{ip:x}: {inst}")

    log("inst", 4, f"{inst}")

    # step debugger
    try:
        event = dbg_step(handle, tid, event, regs, ins=inst)
    except TriagerException as e:
        # extend e with the instruction information
        e.symbinst = inst
        raise e

    regs = dbg_get_regs(tid)

    funcaddr = None

    insttype = inst.getType()
    if insttype == OPCODE.X86.SYSCALL:
        fixup = True
        #TODO here we should concretize syscall volatile registers and shadow space
        # otherwise we may oversymbolized
    
        # should we keep the memory the same after a syscall, is there a good way to do this without huge cost?
        # I think just fixing desync in the registers is enough, and cheaper
    elif insttype in [OPCODE.X86.CALL, OPCODE.X86.LCALL]:
        # get new RIP to return as function addr
        funcaddr = regs.Rip
    elif insttype == OPCODE.X86.RET:
        funcaddr = -1

    # check for desync
    tri_check_regs(ctx, regs, inst, warn=(not fixup))

    return (event, regs, inst, funcaddr)

def in_exception_chain(handle, er, el):
    while er != None:
        if er.ExceptionCode in el:
            return True

        ner = er.ExceptionRecord
        if ner != None:
            sz = sizeof(er)
            data = dbg_read(handle, ner, sz)
            er = EXCEPTION_RECORD()
            memmove(pointer(er), data, sz)
        else:
            er = None

    return False

def handle_case(f, verbupdate=None, timeout=1):
    # this one doesn't use Triton except for telling what kind of crash it was
    # This can run fast and a lot, to try and pin down unstable crashes

    if verbupdate is not None:
        # needed for updating verb when multiprocessing
        global VERB
        VERB = verbupdate


    cmd = f"\"D:\\Projects\\procmoncrashes\\Procmon64.exe\" /NoConnect /NoFilter /OpenLog {f}"
    if timeout > 0:
        cmd += f" /Runtime {int(timeout)}"

    log("process", 3, f"running: {cmd}")
    
    handle, main_tid = connect_debugger(cmd)

    log("process", 3, f":{main_tid} -- {f}")

    event = dbg_wait(handle, None)
    code = event.dwDebugEventCode

    if code == EXIT_PROCESS_DEBUG_EVENT:
        log("crash", 1, f"{f} Closed with no crash")
    elif code == EXCEPTION_DEBUG_EVENT:
        # exception to investigate
        log("crash", 1, f"{f} crashed:")
        er = event.u.Exception.ExceptionRecord
        log("crash", 1, exceptionstr(handle, er, event.dwThreadId))

    else:
        log("process", 1, f"{f} hit unexpected Debug Event {code}")

    dbg_kill(handle)

def build_input_from_model(model, sz, f=None, fillchar=0x40, truncate=True):
    # builds a new input, given a solved model

    data = bytearray()
    if f is not None:
        with open(f, "rb") as fp:
            data = bytearray(fp.read())

    minsize = 0x3a8 # this is the procmon header size, min to get most parsing done

    # extend data to sz
    if len(data) < sz:
        data += bytes([fillchar] * (sz - len(data)))

    for k in model:
        sm = model[k]
        i, n = sm.getVariable().getAlias().split('_')
        if i != "INPUT":
            raise Exception("Unexpected symvar alias in model?")
        num = int(n,16)

        if num > minsize:
            minsize = num+1

        data[num] = sm.getValue()

    # truncate to minsize?
    if truncate:
        # will cause issues, if file size is part of the path logic
        # or if other values are needed
        data = data[:minsize]

    return bytes(data)

def getDllOffset(maps, addr):
    closest = "Unk"
    closest_off = -1

    for libname in maps:
        base = maps[libname]

        if base > addr:
            continue

        off = addr - base
        if closest_off == -1 or closest_off > off:
            closest_off = off
            closest = libname

    if closest_off == -1:
        return "??? {addr:x}"
    return f"{closest}+0x{closest_off:x}"

def annotatedTrace(ctx, maps, itrace_portion):
    # gets path constraints and labels them in the trace
    # this isn't exact, because we don't know for sure these constraints match up to this time we hit this address
    # but is still informative?
    # if we end up needing something more accurate,
    # we could set comments with instruction count on the path constraints as they come up

    pcd = {x.getBranchConstraints()[0]['srcAddr']: x for x in ctx.getPathConstraints()}

    out = []
    for addr in itrace_portion:
        off = getDllOffset(maps, addr)
        symb = pcd.get(addr)

        out.append((addr, off, symb))
    return out

def parse_aststr(aststr):
    # used by expand_ast to get the tree
    i = 0
    aststr = aststr.lstrip()
    c = aststr[i]
    if c != '(':
        # just parse a token
        ei = i
        while aststr[ei] not in [' ', '(', ')']:
            ei += 1

        return (aststr[:ei], ei)

    # go past the '('
    i += 1

    # get node type
    nodetype, ni = parse_aststr(aststr[i:])
    i += ni

    # get any arguments
    args = []
    while True:
        if aststr[i] == ' ':
            i += 1
            continue
        if aststr[i] == ')':
            # done
            i += 1
            break

        arg, ni = parse_aststr(aststr[i:])
        i += ni
        args.append(arg)

    return ((nodetype, args), i)

def expand_ast(aststr, tab=0, root=None, multiline=True):
    # call expand_ast(ctx.getRegisterAst(...)) to print it nicely tabbed out

    tb = '  ' * tab
    out = ''
    nl = '\n'
    if not multiline:
        tb = ''
        nl = ' '

    if root is None:
        root, _ = parse_aststr(str(aststr))
    if isinstance(root[0], str):
        if root[0] == '_':
            # no multiline on these
            nl = ' '
            # may still need inital tab though
            out += tb
            tb = ''
        out += f"{tb}({root[0]}{nl}"
    else:
        out += f"{tb}({expand_ast(None, tab+1, root[0], False).strip()}{nl}"
    for a in root[1]:
        if isinstance(a, str):
            etb = tb
            if etb != '' or tab==0:
                etb += '  '
            out += f"{etb}{a}{nl}"
        else:
            out += f"{expand_ast(None, tab+1, a)}{nl}"
    out += f"{tb})"

    return out

def backslice_expr(ctx, symbexp, print_expr=True):
    # sort by refId to put things temporal
    # to get a symbolic expression from a load access, do something like:
    # symbexp = inst.getLoadAccess()[0][0].getLeaAst().getSymbolicExpression()
    items = sorted(ctx.sliceExpressions(symbexp).items(), key=lambda x: x[0])
    for _, expr in items:
        if print_expr:
            print(expr)
        da = expr.getDisassembly()
        if len(da) > 0:
            print("\t" if print_expr else "", da)

def memast(ctx, ma):
    print(expand_ast(ctx.simplify(ctx.getMemoryAst(ma), True)))

def regast(ctx, reg):
    print(expand_ast(ctx.simplify(ctx.getRegisterAst(reg), True)))

def sym_crash(ctx, handle, f, sz, extraext="simplified", extraconstraints=None, inst=None, event=None, callstack=None, doaddconstraint=True, minimize=True):
    # prints out known symbolic information about the crash
    # and tries to generate a simplified input

    # try to use instruction and predicate to expose what is causing the exception

    # if it is a access violation, let's use the inst to get the access to get the leaAst
    # requires not having ONLY_ON_SYMBOLIZED to get, sometimes

    maps = dbg_maps(handle)
    for libname in maps:
        log("process", 4, f"{libname} @ 0x{maps[libname]:x}")

    astctx = ctx.getAstContext()
    cond = ctx.getPathPredicate()
    if extraconstraints is not None:
        cond = astctx.land([extraconstraints, cond])

    er = None
    if event is not None:
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
            er = event.u.Exception.ExceptionRecord

    if inst is not None:
        if isinstance(inst, str):
            log("crash", 1, f"Crash happend during {inst}")
        else:
            # working with an actual inst
            if er is not None and in_exception_chain(handle, er, [EXCEPTION_ACCESS_VIOLATION]):
                log("crash", 3, "Got an access violation, checking for symbolic access")
                for ma, _ in inst.getLoadAccess():
                    ast = ma.getLeaAst()
                    if not ast.isSymbolized():
                        continue
                    ast = ctx.simplify(ast, True)
                    log("crash", 1, f"Loaded from symbolic address: {ast}")

                    # could backslice these

                    # add to constraints
                    if doaddconstraint:
                        cond = astctx.land([cond, ma.getLeaAst() == ma.getAddress()])

                for ma, val in inst.getStoreAccess():
                    ast = ma.getLeaAst()
                    if ast.isSymbolized():
                        ast = ctx.simplify(ast, True)

                        log("crash", 1, f"Wrote to symbolic address: {ast}")

                        # add to constraints
                        if doaddconstraint:
                            cond = astctx.land([cond, ma.getLeaAst() == ma.getAddress()])
                    if val.isSymbolized():
                        val = ctx.simplify(val, True)
                        log("crash", 1, f"Wrote symbolic value: {val}")

    pathcs = ctx.getPathConstraints()

    if callstack is not None:
        log("crash", 4, '\n'.join([hex(x) + " " + getDllOffset(maps, x) for x in callstack]))

    if VERB["crash"] >= 5:
        log("crash", 5, "Symbolic Path to reach crash")
        for c in pathcs:
            ast = ctx.simplify(c.getTakenPredicate(), True)
            addr  = c.getTakenAddress()
            log("crash", 5, f"To 0x{addr:x} ({getDllOffset(maps, addr)}): {ast}")

    if minimize:
        # solve for simple testcase

        model, state, _ = ctx.getModel(cond, True)
        if state != SOLVER_STATE.SAT:
            log("crash", 2, f"Added constraints did not give a SAT model ({state})")
            return False
        
        # without adding extra constraints, this isn't super useful
        # it isolates the parts that were important in our path
        # but just filling the rest with filler leads to other issues
        # and won't usually end up taking the same path
        inp = build_input_from_model(model, sz, f=None)

        fout = f + "." + extraext + ".PML"
        with open(fout, "wb") as fp:
            fp.write(inp)

        log("crash", 2, f"Wrote {fout}")

        cmd = f"\"D:\\Projects\\procmoncrashes\\Procmon64.exe\" /NoConnect /NoFilter /OpenLog {fout}"
        log("crash", 3, f"Verify with: {cmd}")

    # TODO, verify that the simplified crash does crash the same place?
    # may be hard with some of these, if there is still non-determanism when stepping like this
    return True

# offsets in procmon64.exe
OFF_LOADED_BREAK = 0xa92d8
OFF_INLINE_MEMCPY = 0xb5340
OFF_INLINE_MEMSET = 0xb4f80
OFF_OTHER_MAPVIEW = 0xa907b
OFF_FAIL_MSG = 0x96e19

def trace_access_case(f, timeout=60, verbupdate=None, skip_imports=True, minimize=True, profile=False, interact=False, trace=False, maxcount=0, breakpoints=None):
    # runs the process with the given input, trying to give info about why it crashes, symbolically

    if verbupdate is not None:
        # needed for updating verb when multiprocessing
        global VERB
        VERB = verbupdate

    cmd = f"\"D:\\Projects\\procmoncrashes\\Procmon64.exe\" /NoConnect /NoFilter /OpenLog {f}"
    if timeout > 0:
        cmd += f" /Runtime {int(timeout) + 6}"
    log("process", 3, f"running: {cmd}")
    handle, main_tid = connect_debugger(cmd)

    # to get the base addr we can use dbg_maps
    # first we have to wait until the exe is loaded
    event = None

    event = dbg_wait(handle, event, ignore=())
    if event.dwDebugEventCode != LOAD_DLL_DEBUG_EVENT:
        raise Exception("Initial event was not a dll load")

    event = dbg_wait(handle, event, ignore=())
    if event.dwDebugEventCode != LOAD_DLL_DEBUG_EVENT:
        raise Exception("Second event was not a dll load")

    maps = dbg_maps(handle)
    base = [maps[x] for x in maps if x.lower().endswith("procmon64.exe")][0]
    ntdllbase = [maps[x] for x in maps if x.lower().endswith("ntdll.dll")][0]
    log("process", 4, f"procmon @ 0x{base:x}, ntdll @ 0x{ntdllbase:x}")

    # break at where our input is loaded and mapped
    bp = base + OFF_LOADED_BREAK

    event = dbg_until(handle, bp, event)

    # set up the Triton context to pull in memory lazy
    ctx = tri_init(handle)
    tri_copy_regs(ctx, main_tid)

    # symbolize input file
    # CreateFileMappingW @ 0x689ee maps the log in
    # at offset 0xa92d8 we have mapped it into memory at [rdi+8]
    # with size at [r13+0x20]

    mptrptr = ctx.getConcreteRegisterValue(ctx.registers.rdi) + 8
    mptr = tri_q(ctx, mptrptr)
    szptr = ctx.getConcreteRegisterValue(ctx.registers.r13)+0x20
    sz = tri_q(ctx, szptr)

    log("process", 3, f"{f} size detected = 0x{sz:x}")

    # symbolize input
    for i in range(sz):
        a = mptr + i
        ctx.symbolizeMemory(MemoryAccess(a, 1), f"INPUT_{i:x}")

    # step together until a crash

    # set up hooks
    hooks = {
        base + OFF_INLINE_MEMSET: (memset_hook, None),
        base + OFF_INLINE_MEMCPY: (memcpy_hook, None),
        base + OFF_OTHER_MAPVIEW: (domapview_hook, None),
        base + OFF_FAIL_MSG: (failearly_hook, None), # this hook is because we freeze up in this error box
    }

    # set up debug breaks
    # we can do this on the command line, or here if we want a condition
    # if interactive is on, these will give us a chance to inspect with ipython
    breakpts = {
        #0x7FF76BEAB557: lambda ctx: ctx.getConcreteRegisterValue(ctx.registers.rbx) == 0,
    }
    if breakpoints is not None:
        breakpts.update({x:None for x in breakpoints})

    # skip drawing code
    if skip_imports:
        impfuncs = dbg_get_imports_from(handle, base, ["user32.dll", "gdi32.dll", "comdlg32.dll", "comctl32.dll"])
        for name in impfuncs:
            addr = impfuncs[name]

            # don't skip a few user32 ones
            skip = True
            for ds in ["PostMessage", "DefWindowProc", "PostQuitMessage", "GetMessagePos", "PeekMessage", "DispatchMessage", "GetMessage", "TranslateMessage", "SendMessage", "CallWindowProc", "CallNextHook"]:
                if ds.lower() in name.lower():
                    skip = False
                    break

            if skip:
                hooks[addr] = (skipfunc_hook, name)

    # impose some kind of time limit without relying on /Runtime
    timestart = time.time()

    # for debugging in interactive mode
    saved_exception = None

    regs = None
    callstack = None
    timings = None
    if profile:
        callstack = []
        timings = {}
    itrace = None
    if trace:
        itrace = []
    count = 0

    try:
        while True:
            if timeout > 0 and (time.time() - timestart) > timeout:
                log("process", 1, "Timed out")
                return False

            event, regs, inst, funcaddr = dual_step(ctx, handle, main_tid, event, hooks, regs=regs)

            count += 1
            if maxcount > 0 and count > maxcount:
                log("process", 1, f"Hit maximum instruction count! 0x{count:x}")
                break

            if inst is not None:
                # check for controllable pointers
                # so we can add extra conditions around them so our gen is nice?
                # also so we can report if they could be bad pointers
                # could be expensive solving that often though...
                #TODO
                pass

            if trace and inst is not None:
                itrace.append(inst.getAddress())

            # profile
            if profile and funcaddr is not None:
                #DEBUG
                log("profile", 5, f"{funcaddr:x}")
                now = time.time()
                if funcaddr == -1:
                    # we could have started in the middle of our stack
                    if len(callstack) > 0:
                        # RET
                        outfunc, inst_starttime, in_starttime = callstack[-1]
                        callstack = callstack[:-1]
                        
                        # add to the insttimer of the func we returned from
                        inst_time, in_time = timings.get(outfunc, (0.0, 0.0))
                        inst_time += now - inst_starttime
                        # add to the intimer of the func we returned from
                        in_time += now - in_starttime

                        timings[outfunc] = (inst_time, in_time)

                    if len(callstack) > 0:
                        # start up the insttimer of the func we returned to
                        retfunc, inst_starttime, in_starttime = callstack[-1]
                        callstack[-1] = (retfunc, now, in_starttime)

                else:
                    # did a call
                    # start recording time in this function

                    callstack.append((funcaddr, now, now))

                    # we want to know time in the function's instructions separate from time in the function itself
                    # so count the instruction time of the last function and add it to it's total
                    if len(callstack) > 1:
                        prevfunc, prev_inst_starttime, prev_in_starttime = callstack[-2]
                        inst_delta = now - prev_inst_starttime

                        inst_time, in_time = timings.get(prevfunc, (0.0, 0.0))
                        inst_time += inst_delta
                        timings[prevfunc] = (inst_time, in_time)

            # breakpoints
            if interact:
                if regs is None:
                    regs = dbg_get_regs(main_tid)
                if regs.Rip in breakpts:
                    # take a break here if condition passes
                    fn = breakpts[regs.Rip]

                    if fn is None or fn(ctx):
                        log("inst", 1, f"BREAKING FOR DEBUGGING before {regs.Rip:x}")
                        import IPython; IPython.embed(colors="neutral")
                        # exiting out of the prompt will continue


                
    except UnexpectedException as e:
        event = e.event
        er = e.er
        inst = e.symbinst

        log("crash", 1, f"Stepped to an exception: {e}")
        
        if callstack is not None:
            callstack = [x[0] for x in callstack]
        sym_crash(ctx, handle, f, sz, inst=inst, event=event, extraconstraints=e.extracond, callstack=callstack, minimize=minimize)

        saved_exception = e

    except UnexpectedVuln as e:
        log("crash", 1, f"Detected a vulnerable condition! {e}")

        if callstack is not None:
            callstack = [x[0] for x in callstack]
        sym_crash(ctx, handle, f, sz, inst=None, event=None, extraconstraints=e.extracond, callstack=callstack, minimize=minimize)

        saved_excecption = e

    except Exception as e:
        print("Unknown Exception", e)
        raise e

    maps = dbg_maps(handle)

    log("profile", 2, f"Total time: {time.time() - timestart}")

    if timings is not None:
        log("profile", 3, "Function, instruction time, total time")
        stimings = sorted(timings.items(), key=lambda x: x[1][1], reverse=True)
        for addr, times in stimings:
            inst_time, tot_time = times
            log("profile", 3, f"@{addr:x} ({getDllOffset(maps, addr)}) : {inst_time} {tot_time}")

    if interact:
        # investigate here!
        # generate new inputs with your own constraints ("Can I make this read X address?")
        # backslice to find relevant instructions
        # check the instruction trace to check where you traveled (addr in itrace)
        # use annotatedTrace to mix constraints and a piece of the itrace
        # etc!
        import IPython; IPython.embed(colors="neutral")

    return True

def sall(path = ".\\crsh", times=6):
    for _ in range(times):
        for r, ds, fs in os.walk(path):
            for f in fs:
                p = r + '\\' + f
                # separate to another process so we don't have to worry about cleaning up handles, etc
                p = Process(target = handle_case, args=(p,VERB))
                p.start()
                p.join()
    # retry this a bunch and sort results
    # see sall_parser.py

def findmins(path = ".\\crsh", timeout=60, skipimp=True, minimize=True):
    for r, ds, fs in os.walk(path):
        for f in fs:
            p = r + '\\' + f
            if minimize:
                if '.simplified.' in f:
                    continue
                # don't simplify if we already have one for the input?
                if os.path.exists(p + ".simplified.PML"):
                    continue

            # separate to another process so we don't have to worry about cleaning up handles, etc
            p = Process(target=trace_access_case, args=(p, timeout, VERB, skipimp, minimize))
            p.start()
            p.join()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('command', type=str, choices=['crash', 'sym', 'crashall', 'symall'])
    parser.add_argument('path', type=str, default='.\\crsh')
    parser.add_argument('-t', '--timeout', type=float, default=0.0)
    parser.add_argument('-i', '--interactive', action='store_true')
    parser.add_argument('--nocolor', action='store_true')
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--skipimp', action='store_true')
    parser.add_argument('--minimize', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--maxinst', type=int, default=0)
    parser.add_argument("--breakp", type=lambda x: int(x, 0), nargs='*')

    for vkey in VERB:
        parser.add_argument(f'--v_{vkey}', default=VERB[vkey], type=int)

    args = parser.parse_args()

    # update verbosity first
    for vkey in VERB:
        name = f'v_{vkey}'
        VERB[vkey] = getattr(args, name)

    if args.nocolor:
        termcolor = None

    if args.command in ['crash', 'sym']:
        if not args.path.endswith('.PML'):
            print("path argument ending in '.PML' required")
            parser.print_help()
            exit(-1)

    if args.command == "crash":
        handle_case(args.path)
    elif args.command == "sym":
        trace_access_case(args.path, args.timeout, skip_imports=args.skipimp, profile=args.profile, minimize=args.minimize, interact=args.interactive, trace=args.trace, maxcount=args.maxinst, breakpoints=args.breakp)
    elif args.command == "crashall":
        sall(args.path)
    elif args.command == "symall":
        # .\triage.py symall .\crsh\ --v_inst=0 --v_hook=0 --skipimp -t 270
        # ^ to get a small symbolic summary of each file's crash
        findmins(args.path, args.timeout, skipimp=args.skipimp, minimize=args.minimize)
    else:
        print("Unknown command!")
        parser.print_help()
        exit(-1)
