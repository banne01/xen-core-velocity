#include<stdint.h>

#ifndef DUMP_HEADER_H
#define DUMP_HEADER_H

#define uint32 uint32_t
#define uint64 uint64_t
#define uint16 uint16_t
#define uint8 uint8_t
#define PACKED __attribute__((packed))

//list: ['Win2008SP1x86', 'Win7SP1x64', 'Win7SP0x64', 'Win2003SP2x86', 'Win2008R2SP1x64', 'WinXPSP3x86', 'Win2008SP2x64', 'Win2008SP1x64', 'Win2008R2SP0x64', 'Win7SP1x86', 'VistaSP1x86', 'VistaSP2x64', 'VistaSP2x86', 'Win2008SP2x86', 'Win2003SP1x86', 'Win2003SP2x64', 'Win7SP0x86', 'VistaSP0x64', 'VistaSP1x64', 'VistaSP0x86', 'Win2003SP0x86', 'Win2003SP1x64', 'WinXPSP2x64', 'WinXPSP1x64', 'WinXPSP2x86']
	

//KDGBScan {'Win2008SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win7SP1x64': '\x00\xf8\xff\xffKDBG@\x03', 'Win2003SP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2008R2SP1x64': '\x00\xf8\xff\xffKDBG@\x03', 'WinXPSP3x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02', 'Win2008SP2x64': '\x00\xf8\xff\xffKDBG0\x03', 'Win2008SP1x64': '\x00\xf8\xff\xffKDBG0\x03', 'Win2008R2SP0x64': '\x00\xf8\xff\xffKDBG@\x03', 'Win7SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG@\x03', 'VistaSP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'VistaSP2x64': '\x00\xf8\xff\xffKDBG0\x03', 'WinXPSP2x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'VistaSP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win2008SP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win2003SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2003SP2x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'Win7SP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG@\x03', 'VistaSP0x64': '\x00\xf8\xff\xffKDBG(\x03', 'Win7SP0x64': '\x00\xf8\xff\xffKDBG@\x03', 'VistaSP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG(\x03', 'Win2003SP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2003SP1x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'VistaSP1x64': '\x00\xf8\xff\xffKDBG0\x03', 'WinXPSP1x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'WinXPSP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02'}




struct WinDbg_MemRun32 { /* size 8 id 139 */
  uint32 BasePage; /* bitsize 32, bitpos 0 */
  uint32 PageCount; /* bitsize 32, bitpos 32 */
};
typedef struct WinDbg_MemRun32 /* id 139 */ WinDbg_MemRun32;
struct WinDbg_MemRun64 { /* size 16 id 140 */
  uint64 BasePage; /* bitsize 64, bitpos 0 */
  uint64 PageCount; /* bitsize 64, bitpos 64 */
};
typedef struct WinDbg_MemRun64 /* id 140 */ WinDbg_MemRun64;
struct WinDbg_Regs64 { /* size 208 id 141 */
  uint32 magic; /* bitsize 32, bitpos 0 */
  uint32 mxcsr; /* bitsize 32, bitpos 32 */
  uint16 cs; /* bitsize 16, bitpos 64 */
  uint16 ds; /* bitsize 16, bitpos 80 */
  uint16 es; /* bitsize 16, bitpos 96 */
  uint16 fs; /* bitsize 16, bitpos 112 */
  uint16 gs; /* bitsize 16, bitpos 128 */
  uint16 ss; /* bitsize 16, bitpos 144 */
  uint32 eflags; /* bitsize 32, bitpos 160 */
  uint64 __pad00[6]; /* bitsize 384, bitpos 192 */
  uint64 rax; /* bitsize 64, bitpos 576 */
  uint64 rcx; /* bitsize 64, bitpos 640 */
  uint64 rdx; /* bitsize 64, bitpos 704 */
  uint64 rbx; /* bitsize 64, bitpos 768 */
  uint64 rsp; /* bitsize 64, bitpos 832 */
  uint64 rbp; /* bitsize 64, bitpos 896 */
  uint64 rsi; /* bitsize 64, bitpos 960 */
  uint64 rdi; /* bitsize 64, bitpos 1024 */
  uint64 r8; /* bitsize 64, bitpos 1088 */
  uint64 r9; /* bitsize 64, bitpos 1152 */
  uint64 r10; /* bitsize 64, bitpos 1216 */
  uint64 r11; /* bitsize 64, bitpos 1280 */
  uint64 r12; /* bitsize 64, bitpos 1344 */
  uint64 r13; /* bitsize 64, bitpos 1408 */
  uint64 r14; /* bitsize 64, bitpos 1472 */
  uint64 r15; /* bitsize 64, bitpos 1536 */
  uint64 rip; /* bitsize 64, bitpos 1600 */
}PACKED;
typedef struct WinDbg_Regs64 /* id 141 */ WinDbg_Regs64;
struct WinDbg_SysContext64 { /* size 172 id 142 */
  uint64 cr0; /* bitsize 64, bitpos 0 */
  uint64 cr2; /* bitsize 64, bitpos 64 */
  uint64 cr3; /* bitsize 64, bitpos 128 */
  uint64 cr4; /* bitsize 64, bitpos 192 */
  uint64 dr0; /* bitsize 64, bitpos 256 */
  uint64 dr1; /* bitsize 64, bitpos 320 */
  uint64 dr2; /* bitsize 64, bitpos 384 */
  uint64 dr3; /* bitsize 64, bitpos 448 */
  uint64 dr6; /* bitsize 64, bitpos 512 */
  uint64 dr7; /* bitsize 64, bitpos 576 */
  uint16 __pad01[3]; /* bitsize 48, bitpos 640 */
  uint16 gdtLimit; /* bitsize 16, bitpos 688 */
  uint64 gdtBase; /* bitsize 64, bitpos 704 */
  uint16 __pad02[3]; /* bitsize 48, bitpos 768 */
  uint16 idtLimit; /* bitsize 16, bitpos 816 */
  uint64 idtBase; /* bitsize 64, bitpos 832 */
  uint16 trSelector; /* bitsize 16, bitpos 896 */
  uint16 ldtSelector; /* bitsize 16, bitpos 912 */
  uint32 mxcsr; /* bitsize 32, bitpos 928 */
  uint32 __pad03[11]; /* bitsize 352, bitpos 960 */
  uint64 cr8; /* bitsize 64, bitpos 1312 */
}PACKED;

typedef struct WinDbg_SysContext64 /* id 142 */ WinDbg_SysContext64;
struct WinDbg_Regs32 { /* size 64 id 143 */
  uint32 gs; /* bitsize 32, bitpos 0 */
  uint32 fs; /* bitsize 32, bitpos 32 */
  uint32 es; /* bitsize 32, bitpos 64 */
  uint32 ds; /* bitsize 32, bitpos 96 */
  uint32 edi; /* bitsize 32, bitpos 128 */
  uint32 esi; /* bitsize 32, bitpos 160 */
  uint32 ebx; /* bitsize 32, bitpos 192 */
  uint32 edx; /* bitsize 32, bitpos 224 */
  uint32 ecx; /* bitsize 32, bitpos 256 */
  uint32 eax; /* bitsize 32, bitpos 288 */
  uint32 ebp; /* bitsize 32, bitpos 320 */
  uint32 eip; /* bitsize 32, bitpos 352 */
  uint32 cs; /* bitsize 32, bitpos 384 */
  uint32 eflags; /* bitsize 32, bitpos 416 */
  uint32 esp; /* bitsize 32, bitpos 448 */
  uint32 ss; /* bitsize 32, bitpos 480 */
}PACKED;

typedef struct WinDbg_Regs32 /* id 143 */ WinDbg_Regs32;
struct WinDbg_SysContext32 { /* size 60 id 144 */
  uint32 cr0; /* bitsize 32, bitpos 0 */
  uint32 cr2; /* bitsize 32, bitpos 32 */
  uint32 cr3; /* bitsize 32, bitpos 64 */
  uint32 cr4; /* bitsize 32, bitpos 96 */
  uint32 dr0; /* bitsize 32, bitpos 128 */
  uint32 dr1; /* bitsize 32, bitpos 160 */
  uint32 dr2; /* bitsize 32, bitpos 192 */
  uint32 dr3; /* bitsize 32, bitpos 224 */
  uint32 dr6; /* bitsize 32, bitpos 256 */
  uint32 dr7; /* bitsize 32, bitpos 288 */
  uint16 __pad01; /* bitsize 16, bitpos 320 */
  uint16 gdtLimit; /* bitsize 16, bitpos 336 */
  uint32 gdtBase; /* bitsize 32, bitpos 352 */
  uint16 __pad02; /* bitsize 16, bitpos 384 */
  uint16 idtLimit; /* bitsize 16, bitpos 400 */
  uint32 idtBase; /* bitsize 32, bitpos 416 */
  uint16 trSelector; /* bitsize 16, bitpos 448 */
  uint16 ldtSelector; /* bitsize 16, bitpos 464 */
}PACKED;
typedef struct WinDbg_SysContext32 /* id 144 */ WinDbg_SysContext32;
struct WinDbg_Header32 { /* size 4096 id 145 */
  uint32 Signature; /* bitsize 32, bitpos 0 */
  uint32 ValidDump; /* bitsize 32, bitpos 32 */
  uint32 MajorVersion; /* bitsize 32, bitpos 64 */
  uint32 MinorVersion; /* bitsize 32, bitpos 96 */
  uint32 DirectoryTableBase; /* bitsize 32, bitpos 128 */
  uint32 PfnDataBase; /* bitsize 32, bitpos 160 */
  uint32 PsLoadedModuleList; /* bitsize 32, bitpos 192 */
  uint32 PsActiveProcessHead; /* bitsize 32, bitpos 224 */
  uint32 MachineImageType; /* bitsize 32, bitpos 256 */
  uint32 NumberProcessors; /* bitsize 32, bitpos 288 */
  uint32 BugCheckCode; /* bitsize 32, bitpos 320 */
  uint32 BugCheckParameter[4]; /* bitsize 128, bitpos 352 */
  uint8 VersionUser[32]; /* bitsize 256, bitpos 480 */
  uint8 PaeEnabled; /* bitsize 8, bitpos 736 */
  uint8 KdSecondaryVersion; /* bitsize 8, bitpos 744 */
  uint8 __pad00[2]; /* bitsize 16, bitpos 752 */
  uint32 KdDebuggerDataBlock; /* bitsize 32, bitpos 768 */
  uint32 NumberOfRuns; /* bitsize 32, bitpos 800 */
  uint32 NumberOfPages; /* bitsize 32, bitpos 832 */
  WinDbg_MemRun32 PhysMemRun[86]; /* bitsize 5504, bitpos 864 */
  uint32 __pad01; /* bitsize 32, bitpos 6368 */
  uint32 __pad02[35]; /* bitsize 1120, bitpos 6400 */
  WinDbg_Regs32 Regs; /* bitsize 512, bitpos 7520 */
  uint32 __pad03[249]; /* bitsize 7968, bitpos 8032 */
  uint32 ExceptionCode; /* bitsize 32, bitpos 16000 */
  uint32 ExceptionFlags; /* bitsize 32, bitpos 16032 */
  uint32 ExceptionRecord; /* bitsize 32, bitpos 16064 */
  uint32 ExceptionAddress; /* bitsize 32, bitpos 16096 */
  uint32 NumberParameters; /* bitsize 32, bitpos 16128 */
  uint32 ExceptionInformation[15]; /* bitsize 480, bitpos 16160 */
  uint8 Comment[128]; /* bitsize 1024, bitpos 16640 */
  uint8 __pad04[1768]; /* bitsize 14144, bitpos 17664 */
  uint32 DumpType; /* bitsize 32, bitpos 31808 */
  uint32 MiniDumpFields; /* bitsize 32, bitpos 31840 */
  uint32 SecondaryDataState; /* bitsize 32, bitpos 31872 */
  uint32 ProductType; /* bitsize 32, bitpos 31904 */
  uint32 SuiteMask; /* bitsize 32, bitpos 31936 */
  uint32 WriterStatus; /* bitsize 32, bitpos 31968 */
  uint64 RequiredDumpSpace; /* bitsize 64, bitpos 32000 */
  uint8 __pad05[16]; /* bitsize 128, bitpos 32064 */
  uint64 SystemUpTime; /* bitsize 64, bitpos 32192 */
  uint64 SystemTime; /* bitsize 64, bitpos 32256 */
  uint8 __pad06[56]; /* bitsize 448, bitpos 32320 */
}PACKED;
typedef struct WinDbg_Header32 /* id 145 */ WinDbg_Header32;
struct WinDbg_Header64 { /* size 8192 id 146 */
  uint32 Signature; /* bitsize 32, bitpos 0 */
  uint32 ValidDump; /* bitsize 32, bitpos 32 */
  uint32 MajorVersion; /* bitsize 32, bitpos 64 */
  uint32 MinorVersion; /* bitsize 32, bitpos 96 */
  uint64 DirectoryTableBase; /* bitsize 64, bitpos 128 */
  uint64 PfnDataBase; /* bitsize 64, bitpos 192 */
  uint64 PsLoadedModuleList; /* bitsize 64, bitpos 256 */
  uint64 PsActiveProcessHead; /* bitsize 64, bitpos 320 */
  uint32 MachineImageType; /* bitsize 32, bitpos 384 */
  uint32 NumberProcessors; /* bitsize 32, bitpos 416 */
  uint32 BugCheckCode; /* bitsize 32, bitpos 448 */
  uint32 __pad00; /* bitsize 32, bitpos 480 */
  uint64 BugCheckParameter[4]; /* bitsize 256, bitpos 512 */
  uint8 VersionUser[32]; /* bitsize 256, bitpos 768 */
  uint64 KdDebuggerDataBlock; /* bitsize 64, bitpos 1024 */
  uint64 NumberOfRuns; /* bitsize 64, bitpos 1088 */
  uint64 NumberOfPages; /* bitsize 64, bitpos 1152 */
  WinDbg_MemRun64 PhysMemRun[43]; /* bitsize 5504, bitpos 1216 */
  uint32 __pad02[12]; /* bitsize 384, bitpos 6720 */
  WinDbg_Regs64 Regs; /* bitsize 1664, bitpos 7104 */
  uint32 __pad03[686]; /* bitsize 21952, bitpos 8768 */
  uint32 ExceptionCode; /* bitsize 32, bitpos 30720 */
  uint32 ExceptionFlags; /* bitsize 32, bitpos 30752 */
  uint64 ExceptionRecord; /* bitsize 64, bitpos 30784 */
  uint64 ExceptionAddress; /* bitsize 64, bitpos 30848 */
  uint32 NumberParameters; /* bitsize 32, bitpos 30912 */
  uint32 ExceptionInformation[31]; /* bitsize 992, bitpos 30944 */
  uint32 DumpType; /* bitsize 32, bitpos 31936 */
  uint32 __pad04; /* bitsize 32, bitpos 31968 */
  uint64 RequiredDumpSpace; /* bitsize 64, bitpos 32000 */
  uint64 SystemTime; /* bitsize 64, bitpos 32064 */
  uint32 __pad05[32]; /* bitsize 1024, bitpos 32128 */
  uint64 SystemUpTime; /* bitsize 64, bitpos 33152 */
  uint32 __pad06; /* bitsize 32, bitpos 33216 */
  uint32 SecondaryDataState; /* bitsize 32, bitpos 33248 */
  uint32 ProductType; /* bitsize 32, bitpos 33280 */
  uint32 SuiteMask; /* bitsize 32, bitpos 33312 */
  uint32 WriterStatus; /* bitsize 32, bitpos 33344 */
  uint8 __pad08; /* bitsize 8, bitpos 33376 */
  uint8 KdSecondaryVersion; /* bitsize 8, bitpos 33384 */
  uint8 __pad09[2]; /* bitsize 16, bitpos 33392 */
  uint32 __pad10[1004]; /* bitsize 32128, bitpos 33408 */
}PACKED;
typedef struct WinDbg_Header64 /* id 146 */ WinDbg_Header64;
union CoreHeader { /* size 8192 id 147 */
  WinDbg_Header32 windbg32; /* bitsize 32768, bitpos 0 */
  WinDbg_Header64 windbg64; /* bitsize 65536, bitpos 0 */
};
typedef union CoreHeader /* id 147 */ CoreHeader;
struct WinDbg_ExtHeader32 { /* size 32 id 148 */
  uint32 DumpOptions; /* bitsize 32, bitpos 0 */
  uint32 ValidDump; /* bitsize 32, bitpos 32 */
  uint32 __unused2; /* bitsize 32, bitpos 64 */
  uint32 ExtHeaderSize; /* bitsize 32, bitpos 96 */
  uint32 NumberOfBits; /* bitsize 32, bitpos 128 */
  uint32 NumberOfSetBits; /* bitsize 32, bitpos 160 */
  uint32 NumberOfBits2; /* bitsize 32, bitpos 192 */
  uint32 BitmapStart32; /* bitsize 32, bitpos 224 */
};
typedef struct WinDbg_ExtHeader32 /* id 148 */ WinDbg_ExtHeader32;
struct ExtHeader { /* size 40 id 149 */
  WinDbg_ExtHeader32 ext32; /* bitsize 256, bitpos 0 */
  uint64 BitmapStart64; /* bitsize 64, bitpos 256 */
};
typedef struct ExtHeader /* id 149 */ ExtHeader;

struct _DBGKD_DEBUG_DATA_HEADER64 { /* size 24 id 159 */
  uint64 Flink; /* bitsize 64, bitpos 0 */
  uint64 Blink; /* bitsize 64, bitpos 64 */
  uint32 OwnerTag; /* bitsize 32, bitpos 128 */
  uint32 Size; /* bitsize 32, bitpos 160 */
};
typedef struct _DBGKD_DEBUG_DATA_HEADER64 /* id 159 */ DBGKD_DEBUG_DATA_HEADER64;
typedef struct _DBGKD_DEBUG_DATA_HEADER64 /* id 159 */ *PDBGKD_DEBUG_DATA_HEADER64;


struct _KDDEBUGGER_DATA64 { /* size 812 id 154 */
  DBGKD_DEBUG_DATA_HEADER64 Header; /* bitsize 192, bitpos 0 */
  uint64 KernBase; /* bitsize 64, bitpos 192 */
  uint64 BreakpointWithStatus; /* bitsize 64, bitpos 256 */
  uint64 SavedContext; /* bitsize 64, bitpos 320 */
  uint16 ThCallbackStack; /* bitsize 16, bitpos 384 */
  uint16 NextCallback; /* bitsize 16, bitpos 400 */
  uint16 FramePointer; /* bitsize 16, bitpos 416 */
  uint16 PaeEnabled; /* bitsize 1, bitpos 432 */
  uint64 KiCallUserMode; /* bitsize 64, bitpos 448 */
  uint64 KeUserCallbackDispatcher; /* bitsize 64, bitpos 512 */
  uint64 PsLoadedModuleList; /* bitsize 64, bitpos 576 */
  uint64 PsActiveProcessHead; /* bitsize 64, bitpos 640 */
  uint64 PspCidTable; /* bitsize 64, bitpos 704 */
  uint64 ExpSystemResourcesList; /* bitsize 64, bitpos 768 */
  uint64 ExpPagedPoolDescriptor; /* bitsize 64, bitpos 832 */
  uint64 ExpNumberOfPagedPools; /* bitsize 64, bitpos 896 */
  uint64 KeTimeIncrement; /* bitsize 64, bitpos 960 */
  uint64 KeBugCheckCallbackListHead; /* bitsize 64, bitpos 1024 */
  uint64 KiBugcheckData; /* bitsize 64, bitpos 1088 */
  uint64 IopErrorLogListHead; /* bitsize 64, bitpos 1152 */
  uint64 ObpRootDirectoryObject; /* bitsize 64, bitpos 1216 */
  uint64 ObpTypeObjectType; /* bitsize 64, bitpos 1280 */
  uint64 MmSystemCacheStart; /* bitsize 64, bitpos 1344 */
  uint64 MmSystemCacheEnd; /* bitsize 64, bitpos 1408 */
  uint64 MmSystemCacheWs; /* bitsize 64, bitpos 1472 */
  uint64 MmPfnDatabase; /* bitsize 64, bitpos 1536 */
  uint64 MmSystemPtesStart; /* bitsize 64, bitpos 1600 */
  uint64 MmSystemPtesEnd; /* bitsize 64, bitpos 1664 */
  uint64 MmSubsectionBase; /* bitsize 64, bitpos 1728 */
  uint64 MmNumberOfPagingFiles; /* bitsize 64, bitpos 1792 */
  uint64 MmLowestPhysicalPage; /* bitsize 64, bitpos 1856 */
  uint64 MmHighestPhysicalPage; /* bitsize 64, bitpos 1920 */
  uint64 MmNumberOfPhysicalPages; /* bitsize 64, bitpos 1984 */
  uint64 MmMaximumNonPagedPoolInBytes; /* bitsize 64, bitpos 2048 */
  uint64 MmNonPagedSystemStart; /* bitsize 64, bitpos 2112 */
  uint64 MmNonPagedPoolStart; /* bitsize 64, bitpos 2176 */
  uint64 MmNonPagedPoolEnd; /* bitsize 64, bitpos 2240 */
  uint64 MmPagedPoolStart; /* bitsize 64, bitpos 2304 */
  uint64 MmPagedPoolEnd; /* bitsize 64, bitpos 2368 */
  uint64 MmPagedPoolInformation; /* bitsize 64, bitpos 2432 */
  uint64 MmPageSize; /* bitsize 64, bitpos 2496 */
  uint64 MmSizeOfPagedPoolInBytes; /* bitsize 64, bitpos 2560 */
  uint64 MmTotalCommitLimit; /* bitsize 64, bitpos 2624 */
  uint64 MmTotalCommittedPages; /* bitsize 64, bitpos 2688 */
  uint64 MmSharedCommit; /* bitsize 64, bitpos 2752 */
  uint64 MmDriverCommit; /* bitsize 64, bitpos 2816 */
  uint64 MmProcessCommit; /* bitsize 64, bitpos 2880 */
  uint64 MmPagedPoolCommit; /* bitsize 64, bitpos 2944 */
  uint64 MmExtendedCommit; /* bitsize 64, bitpos 3008 */
  uint64 MmZeroedPageListHead; /* bitsize 64, bitpos 3072 */
  uint64 MmFreePageListHead; /* bitsize 64, bitpos 3136 */
  uint64 MmStandbyPageListHead; /* bitsize 64, bitpos 3200 */
  uint64 MmModifiedPageListHead; /* bitsize 64, bitpos 3264 */
  uint64 MmModifiedNoWritePageListHead; /* bitsize 64, bitpos 3328 */
  uint64 MmAvailablePages; /* bitsize 64, bitpos 3392 */
  uint64 MmResidentAvailablePages; /* bitsize 64, bitpos 3456 */
  uint64 PoolTrackTable; /* bitsize 64, bitpos 3520 */
  uint64 NonPagedPoolDescriptor; /* bitsize 64, bitpos 3584 */
  uint64 MmHighestUserAddress; /* bitsize 64, bitpos 3648 */
  uint64 MmSystemRangeStart; /* bitsize 64, bitpos 3712 */
  uint64 MmUserProbeAddress; /* bitsize 64, bitpos 3776 */
  uint64 KdPrintCircularBuffer; /* bitsize 64, bitpos 3840 */
  uint64 KdPrintCircularBufferEnd; /* bitsize 64, bitpos 3904 */
  uint64 KdPrintWritePointer; /* bitsize 64, bitpos 3968 */
  uint64 KdPrintRolloverCount; /* bitsize 64, bitpos 4032 */
  uint64 MmLoadedUserImageList; /* bitsize 64, bitpos 4096 */
  uint64 NtBuildLab; /* bitsize 64, bitpos 4160 */
  uint64 KiNormalSystemCall; /* bitsize 64, bitpos 4224 */
  uint64 KiProcessorBlock; /* bitsize 64, bitpos 4288 */
  uint64 MmUnloadedDrivers; /* bitsize 64, bitpos 4352 */
  uint64 MmLastUnloadedDriver; /* bitsize 64, bitpos 4416 */
  uint64 MmTriageActionTaken; /* bitsize 64, bitpos 4480 */
  uint64 MmSpecialPoolTag; /* bitsize 64, bitpos 4544 */
  uint64 KernelVerifier; /* bitsize 64, bitpos 4608 */
  uint64 MmVerifierData; /* bitsize 64, bitpos 4672 */
  uint64 MmAllocatedNonPagedPool; /* bitsize 64, bitpos 4736 */
  uint64 MmPeakCommitment; /* bitsize 64, bitpos 4800 */
  uint64 MmTotalCommitLimitMaximum; /* bitsize 64, bitpos 4864 */
  uint64 CmNtCSDVersion; /* bitsize 64, bitpos 4928 */
  uint64 MmPhysicalMemoryBlock; /* bitsize 64, bitpos 4992 */
  uint64 MmSessionBase; /* bitsize 64, bitpos 5056 */
  uint64 MmSessionSize; /* bitsize 64, bitpos 5120 */
  uint64 MmSystemParentTablePage; /* bitsize 64, bitpos 5184 */
  uint64 MmVirtualTranslationBase; /* bitsize 64, bitpos 5248 */
  uint16 OffsetKThreadNextProcessor; /* bitsize 16, bitpos 5312 */
  uint16 OffsetKThreadTeb; /* bitsize 16, bitpos 5328 */
  uint16 OffsetKThreadKernelStack; /* bitsize 16, bitpos 5344 */
  uint16 OffsetKThreadInitialStack; /* bitsize 16, bitpos 5360 */
  uint16 OffsetKThreadApcProcess; /* bitsize 16, bitpos 5376 */
  uint16 OffsetKThreadState; /* bitsize 16, bitpos 5392 */
  uint16 OffsetKThreadBStore; /* bitsize 16, bitpos 5408 */
  uint16 OffsetKThreadBStoreLimit; /* bitsize 16, bitpos 5424 */
  uint16 SizeEProcess; /* bitsize 16, bitpos 5440 */
  uint16 OffsetEprocessPeb; /* bitsize 16, bitpos 5456 */
  uint16 OffsetEprocessParentCID; /* bitsize 16, bitpos 5472 */
  uint16 OffsetEprocessDirectoryTableBase; /* bitsize 16, bitpos 5488 */
  uint16 SizePrcb; /* bitsize 16, bitpos 5504 */
  uint16 OffsetPrcbDpcRoutine; /* bitsize 16, bitpos 5520 */
  uint16 OffsetPrcbCurrentThread; /* bitsize 16, bitpos 5536 */
  uint16 OffsetPrcbMhz; /* bitsize 16, bitpos 5552 */
  uint16 OffsetPrcbCpuType; /* bitsize 16, bitpos 5568 */
  uint16 OffsetPrcbVendorString; /* bitsize 16, bitpos 5584 */
  uint16 OffsetPrcbProcStateContext; /* bitsize 16, bitpos 5600 */
  uint16 OffsetPrcbNumber; /* bitsize 16, bitpos 5616 */
  uint16 SizeEThread; /* bitsize 16, bitpos 5632 */
  uint64 KdPrintCircularBufferPtr; /* bitsize 64, bitpos 5664 */
  uint64 KdPrintBufferSize; /* bitsize 64, bitpos 5728 */
  uint64 KeLoaderBlock; /* bitsize 64, bitpos 5792 */
  uint16 SizePcr; /* bitsize 16, bitpos 5856 */
  uint16 OffsetPcrSelfPcr; /* bitsize 16, bitpos 5872 */
  uint16 OffsetPcrCurrentPrcb; /* bitsize 16, bitpos 5888 */
  uint16 OffsetPcrContainedPrcb; /* bitsize 16, bitpos 5904 */
  uint16 OffsetPcrInitialBStore; /* bitsize 16, bitpos 5920 */
  uint16 OffsetPcrBStoreLimit; /* bitsize 16, bitpos 5936 */
  uint16 OffsetPcrInitialStack; /* bitsize 16, bitpos 5952 */
  uint16 OffsetPcrStackLimit; /* bitsize 16, bitpos 5968 */
  uint16 OffsetPrcbPcrPage; /* bitsize 16, bitpos 5984 */
  uint16 OffsetPrcbProcStateSpecialReg; /* bitsize 16, bitpos 6000 */
  uint16 GdtR0Code; /* bitsize 16, bitpos 6016 */
  uint16 GdtR0Data; /* bitsize 16, bitpos 6032 */
  uint16 GdtR0Pcr; /* bitsize 16, bitpos 6048 */
  uint16 GdtR3Code; /* bitsize 16, bitpos 6064 */
  uint16 GdtR3Data; /* bitsize 16, bitpos 6080 */
  uint16 GdtR3Teb; /* bitsize 16, bitpos 6096 */
  uint16 GdtLdt; /* bitsize 16, bitpos 6112 */
  uint16 GdtTss; /* bitsize 16, bitpos 6128 */
  uint16 Gdt64R3CmCode; /* bitsize 16, bitpos 6144 */
  uint16 Gdt64R3CmTeb; /* bitsize 16, bitpos 6160 */
  uint64 IopNumTriageDumpDataBlocks; /* bitsize 64, bitpos 6176 */
  uint64 IopTriageDumpDataBlocks; /* bitsize 64, bitpos 6240 */
  uint64 VfCrashDataBlock; /* bitsize 64, bitpos 6304 */
  uint64 MmBadPagesDetected; /* bitsize 64, bitpos 6368 */
  uint64 MmZeroedPageSingleBitErrorsDetected; /* bitsize 64, bitpos 6432 */
}PACKED;
typedef struct _KDDEBUGGER_DATA64 /* id 154 */ KDDEBUGGER_DATA64;
typedef struct _KDDEBUGGER_DATA64 /* id 154 */ *PKDDEBUGGER_DATA64;


/*our dump header 
 *kdd_os
 *cpu_regs,
 *ctrl_regs
 * */

typedef struct {
    uint32_t build;
    int w64;
    int mp;
    char *name;
    uint64_t base;              /* KernBase: start looking here */
    uint32_t range;             /* |         and search an area this size */
    uint32_t version;           /* +-> NtBuildNumber */
    uint32_t modules;           /* +-> PsLoadedModuleList */
    uint32_t prcbs;             /* +-> KiProcessorBlock */
} kdd_os;


typedef union {
    uint32_t pad[179];
    struct {
        uint32_t u1[7];         /* Flags, DRx?? */
        uint8_t fp[112];        /* FP save state (why 112 not 108?) */
        int32_t gs;
        int32_t fs;
        int32_t es;
        int32_t ds;
        int32_t edi;
        int32_t esi;
        int32_t ebx;
        int32_t edx;
        int32_t ecx;
        int32_t eax;
        int32_t ebp;
        int32_t eip;
        int32_t cs;
        int32_t eflags;
        int32_t esp;
        int32_t ss;
        uint32_t sp2[37];       /* More 0x20202020. fp? */
        uint32_t sp3;           /* 0x00202020 */
    };
} PACKED kdd_regs_x86_32;

typedef union {
    uint64_t pad[154];
    struct {

        uint64_t u1[7];

        uint16_t cs; //2*1c
        uint16_t ds;
        uint16_t es;
        uint16_t fs;
        uint16_t gs;
        uint16_t ss;
        uint32_t rflags;
        uint64_t dr0;
        uint64_t dr1;
        uint64_t dr2;
        uint64_t dr3;
        uint64_t dr6;
        uint64_t dr7;
        int64_t rax;
        int64_t rcx;
        int64_t rdx;
        int64_t rbx;
        int64_t rsp;
        int64_t rbp;
        int64_t rsi;
        int64_t rdi;
        int64_t r8;
        int64_t r9;
        int64_t r10;
        int64_t r11;
        int64_t r12;
        int64_t r13;
        int64_t r14;
        int64_t r15;
        int64_t rip; //2*7c

        uint64_t u2[32];

        uint8_t fp[512]; // fp @2*100 .. 150 (+ more??)

        uint64_t u3[26];
    };
} PACKED kdd_regs_x86_64;

typedef union {
    kdd_regs_x86_32 r32;
    kdd_regs_x86_64 r64;
} PACKED kdd_regs;


/* System registers */
typedef struct {
    uint32_t cr0;
    uint32_t cr2;
    uint32_t cr3;
    uint32_t cr4;
    uint32_t dr0;
    uint32_t dr1;
    uint32_t dr2;
    uint32_t dr3;
    uint32_t dr6;
    uint32_t dr7;
    uint16_t gdt_pad;
    uint16_t gdt_limit;
    uint32_t gdt_base;
    uint16_t idt_pad;
    uint16_t idt_limit;
    uint32_t idt_base;
    uint16_t tss_sel;
    uint16_t ldt_sel;
    uint8_t u1[24];
} PACKED kdd_ctrl_x86_32;

typedef struct {
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint8_t  gdt_pad[6];
    uint16_t gdt_limit;
    uint64_t gdt_base;
    uint8_t  idt_pad[6];
    uint16_t idt_limit;
    uint64_t idt_base;
    uint16_t tss_sel;
    uint16_t ldt_sel;
    uint8_t u1[44];
    uint64_t cr8;
    uint8_t u2[40];
    uint64_t efer; // XXX find out where EFER actually goes
} PACKED kdd_ctrl_x86_64;

typedef union {
    kdd_ctrl_x86_32 c32;
    kdd_ctrl_x86_64 c64;
} kdd_ctrl;

#endif
