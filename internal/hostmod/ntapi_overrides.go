//go:build windows

package hostmod

// ntAPINoMirrorArgs maps Nt API names to a bitmask of arg indices whose
// output contents should NOT be scanned by Step 6's mirror logic. These
// APIs write target-process addresses or raw memory into output buffers,
// not host pointers that the guest needs to dereference.
var ntAPINoMirrorArgs = map[string]uint64{
	// Output buffer contains MEMORY_BASIC_INFORMATION with target-process
	// addresses (BaseAddress, AllocationBase) that are NOT host pointers.
	"NtQueryVirtualMemory": 1<<3 | 1<<5,

	// Output buffer contains raw bytes from the target process.
	"NtReadVirtualMemory": 1<<2 | 1<<4,

	// Output buffer contains SYSTEM_PROCESS_INFORMATION with self-referential
	// host pointers that need fixup, not mirroring.
	"NtQuerySystemInformation": 1<<1 | 1<<3,

	// Output buffer contains PROCESS_BASIC_INFORMATION with target-process
	// PEB address (not a host pointer).
	"NtQueryInformationProcess": 1<<2 | 1<<4,

	// Output buffer for TokenUser/TokenOwner/TokenGroups contains self-referential
	// PSID host pointers (wasmMemBase + offset). Same class of issue as
	// GetTokenInformation — needs compaction, not mirroring.
	// TODO: wire Step 6.5 compactTokenInfoBytes for NtQueryInformationToken.
	"NtQueryInformationToken": 1<<2 | 1<<4,

	// Output buffer for ObjectNameInformation contains UNICODE_STRING with
	// Buffer as a host address (wasmMemBase + offset) — same issue as
	// NtQuerySystemInformation ImageName. Guest can't dereference these.
	// TODO: wire Step 6.5 fixup for UNICODE_STRING.Buffer in output.
	"NtQueryObject": 1<<2 | 1<<4,

	// Output buffer for FileNameInformation contains inline WCHAR data (no
	// embedded pointers), but IoStatusBlock.Information is a byte count.
	// Skip mirroring to avoid misinterpreting inline data as pointers.
	"NtQueryInformationFile": 1<<1 | 1<<2,

	// Receive message buffer may contain ALPC_DATA_VIEW_ATTR with ViewBase
	// (a mapped section address) that is NOT a WASM pointer.
	"NtAlpcSendWaitReceivePort": 1<<4 | 1<<5 | 1<<6,
}

// ntapiOverrides provides pointer masks for undocumented Nt*/Zw* syscalls used
// by offensive tools (SysWhispers, HellsGate, direct syscall patterns). These
// APIs are not in win32json so generatedPointerMasks has no entries for them.
//
// Bit N=1 means arg[N] IS a WASM pointer that needs translation.
// Bit N=0 means arg[N] is a handle, scalar, or remote-process address.
//
// Sources: ReactOS headers, j00ru's syscall table, community documentation.
// Signatures are stable across Windows versions (NT6.0+).
var ntapiOverrides = map[string]uint32{
	// --- Virtual memory (injection primitives) ---

	// NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect)
	// args[1,3] are pointers to local variables (IN/OUT).
	"NtAllocateVirtualMemory": 1<<1 | 1<<3, // 0x0A

	// NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
	// args[1,2,4] are pointers to local variables.
	"NtProtectVirtualMemory": 1<<1 | 1<<2 | 1<<4, // 0x16

	// NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType)
	// args[1,2] are pointers to local variables.
	"NtFreeVirtualMemory": 1<<1 | 1<<2, // 0x06

	// NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemInfoClass, MemInfo*, MemInfoLength, ReturnLength*)
	// arg[1] is the queried address (value, not pointer to value — like VirtualQueryEx).
	// args[3,5] are output buffers in WASM.
	"NtQueryVirtualMemory": 1<<3 | 1<<5, // 0x28

	// NtReadVirtualMemory and NtWriteVirtualMemory are already in semanticOverrides.

	// --- Thread operations (CreateRemoteThread alternatives) ---

	// NtCreateThreadEx(*ThreadHandle, DesiredAccess, ObjectAttributes*, ProcessHandle,
	//                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList*)
	// arg[0] OUT ThreadHandle: WASM ptr.
	// arg[2] ObjectAttributes: usually NULL, WASM ptr if non-NULL.
	// arg[4] StartRoutine: remote address when injecting (NOT WASM).
	// arg[5] Argument: remote/function ptr (NOT WASM).
	// arg[10] AttributeList: can be WASM ptr.
	"NtCreateThreadEx": 1<<0 | 1<<2 | 1<<10, // 0x405

	// NtCreateThread(*ThreadHandle, DesiredAccess, ObjectAttributes*, ProcessHandle,
	//                ClientId*, Context*, InitialTeb*, CreateSuspended)
	// args[0,2,4,5,6] are WASM ptrs.
	"NtCreateThread": 1<<0 | 1<<2 | 1<<4 | 1<<5 | 1<<6, // 0x75

	// NtResumeThread(ThreadHandle, PreviousSuspendCount*)
	"NtResumeThread": 1 << 1, // 0x02

	// NtSuspendThread(ThreadHandle, PreviousSuspendCount*)
	"NtSuspendThread": 1 << 1, // 0x02

	// NtGetContextThread(ThreadHandle, Context*)
	"NtGetContextThread": 1 << 1, // 0x02

	// NtSetContextThread(ThreadHandle, Context*)
	"NtSetContextThread": 1 << 1, // 0x02

	// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, ApcStatusBlock*, ApcReserved)
	// ApcRoutine and ApcContext are remote addrs for APC injection.
	// ApcStatusBlock is technically a pointer but usually NULL.
	"NtQueueApcThread": 1 << 3, // 0x08

	// NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcContext1, ApcContext2, ApcContext3)
	// ApcRoutine and contexts are remote.
	"NtQueueApcThreadEx": 0x00,

	// --- Process operations ---

	// NtOpenProcess(*ProcessHandle, DesiredAccess, ObjectAttributes*, ClientId*)
	// args[0,2,3] are WASM ptrs.
	"NtOpenProcess": 1<<0 | 1<<2 | 1<<3, // 0x0D

	// NtQueryInformationProcess(ProcessHandle, InfoClass, ProcessInfo*, InfoLength, ReturnLength*)
	// args[2,4] are WASM ptrs.
	"NtQueryInformationProcess": 1<<2 | 1<<4, // 0x14

	// NtSetInformationProcess(ProcessHandle, InfoClass, ProcessInfo*, InfoLength)
	"NtSetInformationProcess": 1 << 2, // 0x04

	// NtQuerySystemInformation(InfoClass, SystemInfo*, InfoLength, ReturnLength*)
	// args[1,3] are WASM ptrs.
	"NtQuerySystemInformation": 1<<1 | 1<<3, // 0x0A

	// NtClose(Handle) — all scalar.
	"NtClose": 0x00,

	// NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, *TargetHandle, DesiredAccess, HandleAttributes, Options)
	// arg[3] is WASM ptr (OUT TargetHandle).
	"NtDuplicateObject": 1 << 3, // 0x08

	// --- Section operations (process hollowing) ---

	// NtCreateSection(*SectionHandle, DesiredAccess, ObjectAttributes*, *MaximumSize, PageProtection, AllocAttributes, FileHandle)
	// args[0,2,3] are WASM ptrs.
	"NtCreateSection": 1<<0 | 1<<2 | 1<<3, // 0x0D

	// NtOpenSection(*SectionHandle, DesiredAccess, ObjectAttributes*)
	// args[0,2] are WASM ptrs.
	"NtOpenSection": 1<<0 | 1<<2, // 0x05

	// NtMapViewOfSection(SectionHandle, ProcessHandle, *BaseAddress, ZeroBits, CommitSize,
	//                    *SectionOffset, *ViewSize, InheritDisposition, AllocationType, Win32Protect)
	// args[2,5,6] are local variable pointers.
	// arg[2] *BaseAddress value may be remote if ProcessHandle is remote.
	"NtMapViewOfSection": 1<<2 | 1<<5 | 1<<6, // 0x64

	// NtUnmapViewOfSection(ProcessHandle, BaseAddress)
	// BaseAddress is a direct value (like lpAddress in VirtualFreeEx).
	"NtUnmapViewOfSection": 0x00,

	// --- Token operations ---

	// NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle)
	"NtOpenProcessToken": 1 << 2, // 0x04

	// NtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes, *TokenHandle)
	"NtOpenProcessTokenEx": 1 << 3, // 0x08

	// NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, *TokenHandle)
	"NtOpenThreadToken": 1 << 3, // 0x08

	// NtOpenThreadTokenEx(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, *TokenHandle)
	"NtOpenThreadTokenEx": 1 << 4, // 0x10

	// --- Wait/timing ---

	// NtWaitForSingleObject(Handle, Alertable, *Timeout)
	"NtWaitForSingleObject": 1 << 2, // 0x04

	// NtWaitForMultipleObjects(Count, *Handles, WaitType, Alertable, *Timeout)
	"NtWaitForMultipleObjects": 1<<1 | 1<<4, // 0x12

	// NtDelayExecution(Alertable, *DelayInterval)
	"NtDelayExecution": 1 << 1, // 0x02

	// --- Object queries ---

	// NtQueryObject(Handle, InfoClass, ObjectInfo*, InfoLength, *ReturnLength)
	"NtQueryObject": 1<<2 | 1<<4, // 0x14

	// --- Thread info ---

	// NtQueryInformationThread(ThreadHandle, InfoClass, ThreadInfo*, InfoLength, *ReturnLength)
	"NtQueryInformationThread": 1<<2 | 1<<4, // 0x14

	// NtSetInformationThread(ThreadHandle, InfoClass, ThreadInfo*, InfoLength)
	"NtSetInformationThread": 1 << 2, // 0x04

	// NtOpenThread(*ThreadHandle, DesiredAccess, ObjectAttributes*, ClientId*)
	"NtOpenThread": 1<<0 | 1<<2 | 1<<3, // 0x0D

	// --- Token query/manipulation (nanodump: token_priv.c, impersonate.c) ---

	// NtQueryInformationToken(TokenHandle, TokenInfoClass, TokenInfo*, TokenInfoLength, *ReturnLength)
	// args[2,4] are WASM ptrs.
	"NtQueryInformationToken": 1<<2 | 1<<4, // 0x14

	// NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, *NewState, BufferLength, *PreviousState, *ReturnLength)
	// args[2,4,5] are WASM ptrs.
	"NtAdjustPrivilegesToken": 1<<2 | 1<<4 | 1<<5, // 0x34

	// NtDuplicateToken(ExistingToken, DesiredAccess, *ObjectAttributes, EffectiveOnly, TokenType, *NewToken)
	// args[2,5] are WASM ptrs. ObjectAttributes contains SECURITY_QUALITY_OF_SERVICE.
	"NtDuplicateToken": 1<<2 | 1<<5, // 0x24

	// NtPrivilegeCheck(ClientToken, *RequiredPrivileges, *Result)
	// args[1,2] are WASM ptrs.
	"NtPrivilegeCheck": 1<<1 | 1<<2, // 0x06

	// --- Process creation/enumeration (nanodump: handle.c) ---

	// NtCreateProcessEx(*ProcessHandle, DesiredAccess, *ObjectAttributes, ParentProcess,
	//                   Flags, SectionHandle, DebugPort, ExceptionPort)
	// args[0,2] are WASM ptrs.
	"NtCreateProcessEx": 1<<0 | 1<<2, // 0x05

	// NtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, *NewProcessHandle)
	// arg[4] is WASM ptr (OUT).
	"NtGetNextProcess": 1 << 4, // 0x10

	// NtGetNextThread(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, *NewThreadHandle)
	// arg[5] is WASM ptr (OUT).
	"NtGetNextThread": 1 << 5, // 0x20

	// NtTerminateProcess(ProcessHandle, ExitStatus) — all scalar.
	"NtTerminateProcess": 0x00,

	// NtTerminateThread(ThreadHandle, ExitStatus) — all scalar.
	"NtTerminateThread": 0x00,

	// --- File operations (nanodump: shtinkering.c, malseclogon.c) ---

	// NtCreateFile(*FileHandle, DesiredAccess, *ObjectAttributes, *IoStatusBlock,
	//              *AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
	//              CreateOptions, *EaBuffer, EaLength)
	// args[0,2,3,4,9] are WASM ptrs.
	"NtCreateFile": 1<<0 | 1<<2 | 1<<3 | 1<<4 | 1<<9, // 0x21D

	// NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
	//             *Buffer, Length, *ByteOffset, *Key)
	// args[4,5,7,8] are WASM ptrs. ApcRoutine/ApcContext are callbacks (NOT WASM).
	"NtWriteFile": 1<<4 | 1<<5 | 1<<7 | 1<<8, // 0x1B0

	// NtQueryInformationFile(FileHandle, *IoStatusBlock, FileInfo*, InfoLength, FileInfoClass)
	// args[1,2] are WASM ptrs.
	"NtQueryInformationFile": 1<<1 | 1<<2, // 0x06

	// NtDeleteFile(*ObjectAttributes)
	// arg[0] is WASM ptr.
	"NtDeleteFile": 1 << 0, // 0x01

	// NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, *IoStatusBlock,
	//                 FsControlCode, *InputBuffer, InputLen, *OutputBuffer, OutputLen)
	// args[4,6,8] are WASM ptrs. ApcRoutine/ApcContext are callbacks (NOT WASM).
	"NtFsControlFile": 1<<4 | 1<<6 | 1<<8, // 0x150

	// --- Event/synchronization (nanodump: shtinkering.c) ---

	// NtCreateEvent(*EventHandle, DesiredAccess, *ObjectAttributes, EventType, InitialState)
	// args[0,2] are WASM ptrs.
	"NtCreateEvent": 1<<0 | 1<<2, // 0x05

	// NtOpenEvent(*EventHandle, DesiredAccess, *ObjectAttributes)
	// args[0,2] are WASM ptrs.
	"NtOpenEvent": 1<<0 | 1<<2, // 0x05

	// --- Registry (nanodump: shtinkering.c) ---

	// NtCreateKey(*KeyHandle, DesiredAccess, *ObjectAttributes, TitleIndex,
	//             *Class, CreateOptions, *Disposition)
	// args[0,2,4,6] are WASM ptrs.
	"NtCreateKey": 1<<0 | 1<<2 | 1<<4 | 1<<6, // 0x55

	// NtSetValueKey(KeyHandle, *ValueName, TitleIndex, Type, *Data, DataSize)
	// args[1,4] are WASM ptrs.
	"NtSetValueKey": 1<<1 | 1<<4, // 0x12

	// NtDeleteKey(KeyHandle) — all scalar.
	"NtDeleteKey": 0x00,

	// --- WNF (nanodump: shtinkering.c — Windows Notification Facility) ---

	// NtUpdateWnfStateData(*StateName, *Buffer, Length, *TypeId, *ExplicitScope,
	//                      MatchingChangeStamp, CheckStamp)
	// args[0,1,3,4] are WASM ptrs.
	"NtUpdateWnfStateData": 1<<0 | 1<<1 | 1<<3 | 1<<4, // 0x1B

	// --- ALPC (nanodump: shtinkering.c — Advanced Local Procedure Call) ---

	// NtAlpcConnectPort(*PortHandle, *PortName, *ObjectAttributes, *PortAttributes,
	//                   Flags, *RequiredServerSid, *ConnectionMessage, *BufferLength,
	//                   *OutMessageAttributes, *InMessageAttributes, *Timeout)
	// args[0,1,2,3,5,6,7,8,9,10] are WASM ptrs. arg[4] is scalar Flags.
	"NtAlpcConnectPort": 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<5 | 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<10, // 0x7EF

	// NtAlpcSendWaitReceivePort(PortHandle, Flags, *SendMessage, *SendMessageAttributes,
	//                           *ReceiveMessage, *BufferLength, *ReceiveMessageAttributes, *Timeout)
	// args[2,3,4,5,6,7] are WASM ptrs. args[0,1] are handle/scalar.
	"NtAlpcSendWaitReceivePort": 1<<2 | 1<<3 | 1<<4 | 1<<5 | 1<<6 | 1<<7, // 0xFC

	// NtAlpcCreatePort(*PortHandle, *ObjectAttributes, *PortAttributes)
	// args[0,1,2] are WASM ptrs.
	"NtAlpcCreatePort": 1<<0 | 1<<1 | 1<<2, // 0x07

	// NtAlpcDisconnectPort(PortHandle, Flags) — all scalar.
	"NtAlpcDisconnectPort": 0x00,
}

func init() {
	// Merge ntapiOverrides into semanticOverrides (which takes priority
	// over generatedPointerMasks in getPointerMask). Skip any entries
	// already present in semanticOverrides to avoid overriding manual
	// corrections.
	for name, mask := range ntapiOverrides {
		if _, exists := semanticOverrides[name]; !exists {
			semanticOverrides[name] = mask
		}
	}

	// Also add Zw* variants. In user-mode ntdll.dll, Zw* and Nt* point to
	// the same function. Some offensive tools use Zw* names.
	for name, mask := range ntapiOverrides {
		zwName := "Zw" + name[2:]
		if _, exists := semanticOverrides[zwName]; !exists {
			semanticOverrides[zwName] = mask
		}
	}

	// Add Zw* variants for the no-mirror map too.
	for name, mask := range ntAPINoMirrorArgs {
		zwName := "Zw" + name[2:]
		if _, exists := ntAPINoMirrorArgs[zwName]; !exists {
			ntAPINoMirrorArgs[zwName] = mask
		}
	}
}
