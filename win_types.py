from ctypes import *

class UNICODE_STRING(Structure):
    _pack_ = 1
    _fields_ = [
        ("Length", c_ushort),
        ("MaximumLength", c_ushort),
        ("_pad_04", c_uint32),
        ("Buffer", c_void_p),
    ]

class STARTUPINFOA(Structure):
    _pack_ = 1
    _fields_ = [
        ("cb", c_uint),    # 0
        ("_pad_4", c_byte),
        ("_pad_5", c_byte),
        ("_pad_6", c_byte),
        ("_pad_7", c_byte),
        ("lpReserved", c_void_p),    # 8
        ("lpDesktop", c_void_p),    # 10
        ("lpTitle", c_void_p),    # 18
        ("dwX", c_uint),    # 20
        ("dwY", c_uint),    # 24
        ("dwXSize", c_uint),    # 28
        ("dwYSize", c_uint),    # 2c
        ("dwXCountChars", c_uint),    # 30
        ("dwYCountChars", c_uint),    # 34
        ("dwFillAttribute", c_uint),    # 38
        ("dwFlags", c_uint),    # 3c
        ("wShowWindow", c_short),    # 40
        ("cbReserved2", c_short),    # 42
        ("_pad_44", c_byte),
        ("_pad_45", c_byte),
        ("_pad_46", c_byte),
        ("_pad_47", c_byte),
        ("lpReserved2", c_void_p),    # 48
        ("hStdInput", c_void_p),    # 50
        ("hStdOutput", c_void_p),    # 58
        ("hStdError", c_void_p),    # 60
    ]

class PROCESS_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ("hProcess", c_void_p),    # 0
        ("hThread", c_void_p),    # 8
        ("dwProcessId", c_uint),    # 10
        ("dwThreadId", c_uint),    # 14
    ]

class EXCEPTION_RECORD(Structure):
    _pack_ = 1
    _fields_ = [
        ("ExceptionCode", c_uint),    # 0
        ("ExceptionFlags", c_uint),    # 4
        ("ExceptionRecord", c_void_p),    # 8
        ("ExceptionAddress", c_void_p),    # 10
        ("NumberParameters", c_uint),    # 18
        ("_pad_1c", c_byte),
        ("_pad_1d", c_byte),
        ("_pad_1e", c_byte),
        ("_pad_1f", c_byte),
        ("ExceptionInformation", c_ulonglong * 15),    # 20
    ]

class EXCEPTION_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),    # 0
        ("dwFirstChance", c_uint),    # 98
        ("_pad_9c", c_uint),
    ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hThread", c_void_p),    # 0
        ("lpThreadLocalBase", c_void_p),    # 8
        ("lpStartAddress", c_void_p),    # 10
    ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", c_void_p),    # 0
        ("hProcess", c_void_p),    # 8
        ("hThread", c_void_p),    # 10
        ("lpBaseOfImage", c_void_p),    # 18
        ("dwDebugInfoFileOffset", c_uint),    # 20
        ("nDebugInfoSize", c_uint),    # 24
        ("lpThreadLocalBase", c_void_p),    # 28
        ("lpStartAddress", c_void_p),    # 30
        ("lpImageName", c_void_p),    # 38
        ("fUnicode", c_short),    # 40
    ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwExitCode", c_uint),    # 0
    ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwExitCode", c_uint),    # 0
    ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", c_void_p),    # 0
        ("lpBaseOfDll", c_void_p),    # 8
        ("dwDebugInfoFileOffset", c_uint),    # 10
        ("nDebugInfoSize", c_uint),    # 14
        ("lpImageName", c_void_p),    # 18
        ("fUnicode", c_short),    # 20
    ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("lpBaseOfDll", c_void_p),    # 0
    ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("lpDebugStringData", c_void_p),    # 0
        ("fUnicode", c_short),    # 8
        ("nDebugStringLength", c_short),    # a
    ]

class RIP_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwError", c_uint),    # 0
        ("dwType", c_uint),    # 4
    ]

class DEBUG_EVENT_u(Union):
    _pack_ = 1
    _fields_ = [
      ("Exception", EXCEPTION_DEBUG_INFO),
      ("CreateThread", CREATE_THREAD_DEBUG_INFO),
      ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
      ("ExitThread", EXIT_THREAD_DEBUG_INFO),
      ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
      ("LoadDll", LOAD_DLL_DEBUG_INFO),
      ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
      ("DebugString", OUTPUT_DEBUG_STRING_INFO),
      ("RipInfo", RIP_INFO),
    ]

class DEBUG_EVENT(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwDebugEventCode", c_uint32),
        ("dwProcessId", c_uint32),
        ("dwThreadId", c_uint32),
        ("_pad_0c", c_uint32),
        ("u", DEBUG_EVENT_u),
    ]

assert sizeof(DEBUG_EVENT) == 0xb0

class LDT_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("LimitLow", c_uint16),
        ("BaseLow", c_uint16),
        ("BaseMid", c_uint8),
        ("Flags1", c_uint8),
        ("Flags2", c_uint8),
        ("BaseHi", c_uint8),
    ]

class M128A(Structure):
    _pack_ = 1
    _fields_ = [
        ("Low", c_ulonglong),
        ("High", c_ulonglong),
    ]

class CONTEXT(Structure):
    _pack_ = 1
    _fields_ = [
        ("P1Home", c_ulonglong),    # 0
        ("P2Home", c_ulonglong),    # 8
        ("P3Home", c_ulonglong),    # 10
        ("P4Home", c_ulonglong),    # 18
        ("P5Home", c_ulonglong),    # 20
        ("P6Home", c_ulonglong),    # 28
        ("ContextFlags", c_uint),    # 30
        ("MxCsr", c_uint),    # 34
        ("SegCs", c_short),    # 38
        ("SegDs", c_short),    # 3a
        ("SegEs", c_short),    # 3c
        ("SegFs", c_short),    # 3e
        ("SegGs", c_short),    # 40
        ("SegSs", c_short),    # 42
        ("EFlags", c_uint),    # 44
        ("Dr0", c_ulonglong),    # 48
        ("Dr1", c_ulonglong),    # 50
        ("Dr2", c_ulonglong),    # 58
        ("Dr3", c_ulonglong),    # 60
        ("Dr6", c_ulonglong),    # 68
        ("Dr7", c_ulonglong),    # 70
        ("Rax", c_ulonglong),    # 78
        ("Rcx", c_ulonglong),    # 80
        ("Rdx", c_ulonglong),    # 88
        ("Rbx", c_ulonglong),    # 90
        ("Rsp", c_ulonglong),    # 98
        ("Rbp", c_ulonglong),    # a0
        ("Rsi", c_ulonglong),    # a8
        ("Rdi", c_ulonglong),    # b0
        ("R8", c_ulonglong),    # b8
        ("R9", c_ulonglong),    # c0
        ("R10", c_ulonglong),    # c8
        ("R11", c_ulonglong),    # d0
        ("R12", c_ulonglong),    # d8
        ("R13", c_ulonglong),    # e0
        ("R14", c_ulonglong),    # e8
        ("R15", c_ulonglong),    # f0
        ("Rip", c_ulonglong),    # f8
        #("XMM_STUFF", (c_byte * 0x3a0)), #100
        ("Xmm_Header", M128A * 2),
        ("Xmm_Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
        ("Xmm_Other", M128A * 6),
        ("VectorRegister", M128A * 26),
        ("VectorControl", c_ulonglong),    # 4a0
        ("DebugControl", c_ulonglong),    # 4a8
        ("LastBranchToRip", c_ulonglong),    # 4b0
        ("LastBranchFromRip", c_ulonglong),    # 4b8
        ("LastExceptionToRip", c_ulonglong),    # 4c0
        ("LastExceptionFromRip", c_ulonglong),    # 4c8
    ]

assert sizeof(CONTEXT) == 0x4d0

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = (CONTEXT_AMD64 | 0x00000001) # Rsp, Rip, EFlags, ...
CONTEXT_INTEGER = (CONTEXT_AMD64 | 0x00000002) # General
CONTEXT_SEGMENTS = (CONTEXT_AMD64 | 0x00000004) # Some other Segs
CONTEXT_FLOATING_POINT = (CONTEXT_AMD64 | 0x00000008)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x00000010)
CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)
CONTEXT_XSTATE = (CONTEXT_AMD64 | 0x00000040)
CONTEXT_KERNEL_DEBUGGER = 0x04000000
CONTEXT_EXCEPTION_ACTIVE = 0x08000000
CONTEXT_SERVICE_ACTIVE = 0x10000000
CONTEXT_EXCEPTION_REQUEST = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000

class PROCESS_BASIC_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ("ExitStatus", c_int32),
        ("_pad_04", c_int32),
        ("PebBaseAddress", c_void_p),
        ("AffinityMask", c_uint64),
        ("BasePriority", c_uint32),
        ("_pad_1c", c_int32),
        ("UniqueProcessId", c_uint64),
        ("InheritedFromUniqueProcessId", c_uint64),
    ]

assert sizeof(PROCESS_BASIC_INFORMATION) == 0x30

class THREAD_BASIC_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ("ExitStatus", c_int32),
        ("_pad_04", c_int32),
        ("TebBaseAddress", c_void_p),
        ("ClientId_UniqueProcess", c_void_p),
        ("ClientId_UniqueThread", c_void_p),
        ("AffinityMask", c_uint64),
        ("Priority", c_uint32),
        ("BasePriority", c_uint32),
    ]

assert sizeof(THREAD_BASIC_INFORMATION) == 0x30

ecode2str = {}

EXCEPTION_ABANDONED_WAIT_0 = 0x00000080
ecode2str[0x00000080] = "EXCEPTION_ABANDONED_WAIT_0"
EXCEPTION_USER_APC = 0x000000C0
ecode2str[0x000000C0] = "EXCEPTION_USER_APC"
EXCEPTION_TIMEOUT = 0x00000102
ecode2str[0x00000102] = "EXCEPTION_TIMEOUT"
EXCEPTION_PENDING = 0x00000103
ecode2str[0x00000103] = "EXCEPTION_PENDING"
DBG_EXCEPTION_HANDLED = 0x00010001
ecode2str[0x00010001] = "DBG_EXCEPTION_HANDLED"
DBG_CONTINUE = 0x00010002
ecode2str[0x00010002] = "DBG_CONTINUE"
EXCEPTION_SEGMENT_NOTIFICATION = 0x40000005
ecode2str[0x40000005] = "EXCEPTION_SEGMENT_NOTIFICATION"
EXCEPTION_FATAL_APP_EXIT = 0x40000015
ecode2str[0x40000015] = "EXCEPTION_FATAL_APP_EXIT"
DBG_REPLY_LATER = 0x40010001
ecode2str[0x40010001] = "DBG_REPLY_LATER"
DBG_TERMINATE_THREAD = 0x40010003
ecode2str[0x40010003] = "DBG_TERMINATE_THREAD"
DBG_TERMINATE_PROCESS = 0x40010004
ecode2str[0x40010004] = "DBG_TERMINATE_PROCESS"
DBG_CONTROL_C = 0x40010005
ecode2str[0x40010005] = "DBG_CONTROL_C"
DBG_PRINTEXCEPTION_C = 0x40010006
ecode2str[0x40010006] = "DBG_PRINTEXCEPTION_C"
DBG_RIPEXCEPTION = 0x40010007
ecode2str[0x40010007] = "DBG_RIPEXCEPTION"
DBG_CONTROL_BREAK = 0x40010008
ecode2str[0x40010008] = "DBG_CONTROL_BREAK"
DBG_COMMAND_EXCEPTION = 0x40010009
ecode2str[0x40010009] = "DBG_COMMAND_EXCEPTION"
DBG_PRINTEXCEPTION_WIDE_C = 0x4001000A
ecode2str[0x4001000A] = "DBG_PRINTEXCEPTION_WIDE_C"
EXCEPTION_GUARD_PAGE_VIOLATION = 0x80000001
ecode2str[0x80000001] = "EXCEPTION_GUARD_PAGE_VIOLATION"
EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002
ecode2str[0x80000002] = "EXCEPTION_DATATYPE_MISALIGNMENT"
EXCEPTION_BREAKPOINT = 0x80000003
ecode2str[0x80000003] = "EXCEPTION_BREAKPOINT"
EXCEPTION_SINGLE_STEP = 0x80000004
ecode2str[0x80000004] = "EXCEPTION_SINGLE_STEP"
EXCEPTION_LONGJUMP = 0x80000026
ecode2str[0x80000026] = "EXCEPTION_LONGJUMP"
EXCEPTION_UNWIND_CONSOLIDATE = 0x80000029
ecode2str[0x80000029] = "EXCEPTION_UNWIND_CONSOLIDATE"
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
ecode2str[0x80010001] = "DBG_EXCEPTION_NOT_HANDLED"
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
ecode2str[0xC0000005] = "EXCEPTION_ACCESS_VIOLATION"
EXCEPTION_IN_PAGE_ERROR = 0xC0000006
ecode2str[0xC0000006] = "EXCEPTION_IN_PAGE_ERROR"
EXCEPTION_INVALID_HANDLE = 0xC0000008
ecode2str[0xC0000008] = "EXCEPTION_INVALID_HANDLE"
EXCEPTION_INVALID_PARAMETER = 0xC000000D
ecode2str[0xC000000D] = "EXCEPTION_INVALID_PARAMETER"
EXCEPTION_NO_MEMORY = 0xC0000017
ecode2str[0xC0000017] = "EXCEPTION_NO_MEMORY"
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
ecode2str[0xC000001D] = "EXCEPTION_ILLEGAL_INSTRUCTION"
EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025
ecode2str[0xC0000025] = "EXCEPTION_NONCONTINUABLE_EXCEPTION"
EXCEPTION_INVALID_DISPOSITION = 0xC0000026
ecode2str[0xC0000026] = "EXCEPTION_INVALID_DISPOSITION"
EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
ecode2str[0xC000008C] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"
EXCEPTION_FLOAT_DENORMAL_OPERAND = 0xC000008D
ecode2str[0xC000008D] = "EXCEPTION_FLOAT_DENORMAL_OPERAND"
EXCEPTION_FLOAT_DIVIDE_BY_ZERO = 0xC000008E
ecode2str[0xC000008E] = "EXCEPTION_FLOAT_DIVIDE_BY_ZERO"
EXCEPTION_FLOAT_INEXACT_RESULT = 0xC000008F
ecode2str[0xC000008F] = "EXCEPTION_FLOAT_INEXACT_RESULT"
EXCEPTION_FLOAT_INVALID_OPERATION = 0xC0000090
ecode2str[0xC0000090] = "EXCEPTION_FLOAT_INVALID_OPERATION"
EXCEPTION_FLOAT_OVERFLOW = 0xC0000091
ecode2str[0xC0000091] = "EXCEPTION_FLOAT_OVERFLOW"
EXCEPTION_FLOAT_STACK_CHECK = 0xC0000092
ecode2str[0xC0000092] = "EXCEPTION_FLOAT_STACK_CHECK"
EXCEPTION_FLOAT_UNDERFLOW = 0xC0000093
ecode2str[0xC0000093] = "EXCEPTION_FLOAT_UNDERFLOW"
EXCEPTION_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
ecode2str[0xC0000094] = "EXCEPTION_INTEGER_DIVIDE_BY_ZERO"
EXCEPTION_INTEGER_OVERFLOW = 0xC0000095
ecode2str[0xC0000095] = "EXCEPTION_INTEGER_OVERFLOW"
EXCEPTION_PRIVILEGED_INSTRUCTION = 0xC0000096
ecode2str[0xC0000096] = "EXCEPTION_PRIVILEGED_INSTRUCTION"
EXCEPTION_STACK_OVERFLOW = 0xC00000FD
ecode2str[0xC00000FD] = "EXCEPTION_STACK_OVERFLOW"
EXCEPTION_DLL_NOT_FOUND = 0xC0000135
ecode2str[0xC0000135] = "EXCEPTION_DLL_NOT_FOUND"
EXCEPTION_ORDINAL_NOT_FOUND = 0xC0000138
ecode2str[0xC0000138] = "EXCEPTION_ORDINAL_NOT_FOUND"
EXCEPTION_ENTRYPOINT_NOT_FOUND = 0xC0000139
ecode2str[0xC0000139] = "EXCEPTION_ENTRYPOINT_NOT_FOUND"
EXCEPTION_CONTROL_C_EXIT = 0xC000013A
ecode2str[0xC000013A] = "EXCEPTION_CONTROL_C_EXIT"
EXCEPTION_DLL_INIT_FAILED = 0xC0000142
ecode2str[0xC0000142] = "EXCEPTION_DLL_INIT_FAILED"
EXCEPTION_CONTROL_STACK_VIOLATION = 0xC00001B2
ecode2str[0xC00001B2] = "EXCEPTION_CONTROL_STACK_VIOLATION"
EXCEPTION_FLOAT_MULTIPLE_FAULTS = 0xC00002B4
ecode2str[0xC00002B4] = "EXCEPTION_FLOAT_MULTIPLE_FAULTS"
EXCEPTION_FLOAT_MULTIPLE_TRAPS = 0xC00002B5
ecode2str[0xC00002B5] = "EXCEPTION_FLOAT_MULTIPLE_TRAPS"
EXCEPTION_REG_NAT_CONSUMPTION = 0xC00002C9
ecode2str[0xC00002C9] = "EXCEPTION_REG_NAT_CONSUMPTION"
EXCEPTION_HEAP_CORRUPTION = 0xC0000374
ecode2str[0xC0000374] = "EXCEPTION_HEAP_CORRUPTION"
EXCEPTION_STACK_BUFFER_OVERRUN = 0xC0000409
ecode2str[0xC0000409] = "EXCEPTION_STACK_BUFFER_OVERRUN"
EXCEPTION_INVALID_CRUNTIME_PARAMETER = 0xC0000417
ecode2str[0xC0000417] = "EXCEPTION_INVALID_CRUNTIME_PARAMETER"
EXCEPTION_FATAL_USER_CALLBACK_EXCEPTION_INVALID_CRUNTIME_PARAMETER = 0xC000041d
ecode2str[0xC000041d] = "EXCEPTION_FATAL_USER_CALLBACK_EXCEPTION_INVALID_CRUNTIME_PARAMETER"
EXCEPTION_ASSERTION_FAILURE = 0xC0000420
ecode2str[0xC0000420] = "EXCEPTION_ASSERTION_FAILURE"
EXCEPTION_ENCLAVE_VIOLATION = 0xC00004A2
ecode2str[0xC00004A2] = "EXCEPTION_ENCLAVE_VIOLATION"
EXCEPTION_INTERRUPTED = 0xC0000515
ecode2str[0xC0000515] = "EXCEPTION_INTERRUPTED"
EXCEPTION_THREAD_NOT_RUNNING = 0xC0000516
ecode2str[0xC0000516] = "EXCEPTION_THREAD_NOT_RUNNING"
EXCEPTION_ALREADY_REGISTERED = 0xC0000718
ecode2str[0xC0000718] = "EXCEPTION_ALREADY_REGISTERED"



CREATE_PROCESS_DEBUG_EVENT = 3
CREATE_THREAD_DEBUG_EVENT = 2
EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5
EXIT_THREAD_DEBUG_EVENT = 4
LOAD_DLL_DEBUG_EVENT = 6
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9
UNLOAD_DLL_DEBUG_EVENT = 7
