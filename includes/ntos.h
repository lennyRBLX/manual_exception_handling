#pragma once

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#pragma comment(lib, "ntdll.lib")

#define PAGE_SIZE 0x1000
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40

namespace {
	namespace nt_c {
		constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
		constexpr auto STATUS_SUCCESS = 0x0;

		constexpr auto SeLoadDriverPrivilege = 10ull;
		constexpr auto AdjustCurrentProcess = 0ull;
		constexpr auto SystemModuleInformation = 11ull;
		constexpr auto SystemHandleInformation = 16ull;
		constexpr auto SystemExtendedHandleInformation = 64ull;

		typedef struct _SYSTEM_HANDLE {
			PVOID Object;
			HANDLE UniqueProcessId;
			HANDLE HandleValue;
			ULONG GrantedAccess;
			USHORT CreatorBackTraceIndex;
			USHORT ObjectTypeIndex;
			ULONG HandleAttributes;
			ULONG Reserved;
		} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

		typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
			ULONG_PTR HandleCount;
			ULONG_PTR Reserved;
			SYSTEM_HANDLE Handles[1];
		} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

		typedef enum _POOL_TYPE {
			NonPagedPool,
			NonPagedPoolExecute,
			PagedPool,
			NonPagedPoolMustSucceed,
			DontUseThisType,
			NonPagedPoolCacheAligned,
			PagedPoolCacheAligned,
			NonPagedPoolCacheAlignedMustS,
			MaxPoolType,
			NonPagedPoolBase,
			NonPagedPoolBaseMustSucceed,
			NonPagedPoolBaseCacheAligned,
			NonPagedPoolBaseCacheAlignedMustS,
			NonPagedPoolSession,
			PagedPoolSession,
			NonPagedPoolMustSucceedSession,
			DontUseThisTypeSession,
			NonPagedPoolCacheAlignedSession,
			PagedPoolCacheAlignedSession,
			NonPagedPoolCacheAlignedMustSSession,
			NonPagedPoolNx,
			NonPagedPoolNxCacheAligned,
			NonPagedPoolSessionNx
		} POOL_TYPE;

		typedef struct _RTL_PROCESS_MODULE_INFORMATION {
			HANDLE Section;
			PVOID MappedBase;
			PVOID ImageBase;
			ULONG ImageSize;
			ULONG Flags;
			USHORT LoadOrderIndex;
			USHORT InitOrderIndex;
			USHORT LoadCount;
			USHORT OffsetToFileName;
			UCHAR FullPathName[256];
		} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

		typedef struct _RTL_PROCESS_MODULES {
			ULONG NumberOfModules;
			RTL_PROCESS_MODULE_INFORMATION Modules[1];
		} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

		typedef struct _MMPTE_SOFTWARE {
			ULONG Valid : 1;
			ULONG PageFileLow : 4;
			ULONG Protection : 5;
			ULONG Prototype : 1;
			ULONG Transition : 1;
			ULONG Unused : 20;
			ULONG PageFileHigh : 32;
		} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;

		typedef struct _HARDWARE_PTE { /* 16 / 16 elements; 0x0008 / 0x0008 Bytes */
			UINT64 Valid : 1; // ------ / 0x0000; Bit:   0
			UINT64 Write : 1; // ------ / 0x0000; Bit:   1
			UINT64 Owner : 1; // ------ / 0x0000; Bit:   2
			UINT64 WriteThrough : 1; // ------ / 0x0000; Bit:   3
			UINT64 CacheDisable : 1; // ------ / 0x0000; Bit:   4
			UINT64 Accessed : 1; // ------ / 0x0000; Bit:   5
			UINT64 Dirty : 1; // ------ / 0x0000; Bit:   6
			UINT64 LargePage : 1; // ------ / 0x0000; Bit:   7
			UINT64 Global : 1; // ------ / 0x0000; Bit:   8
			UINT64 CopyOnWrite : 1; // ------ / 0x0000; Bit:   9
			UINT64 Prototype : 1; // ------ / 0x0000; Bit:  10
			UINT64 reserved0 : 1; // ------ / 0x0000; Bit:  11
			UINT64 PageFrameNumber : 36; // ------ / 0x0000; Bits: 12 - 47
			UINT64 reserved1 : 4; // ------ / 0x0000; Bits: 48 - 51
			UINT64 SoftwareWsIndex : 11; // ------ / 0x0000; Bits: 52 - 62
			UINT64 NoExecute : 1; // ------ / 0x0000; Bit:  63
		} HARDWARE_PTE, * PHARDWARE_PTE;

		typedef struct _MMPTE_HARDWARE {
			ULONG64 Valid : 1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
			ULONG64 Dirty1 : 1;
#else
#ifdef CONFIG_SMP
			ULONG64 Writable : 1;
#else
			ULONG64 Write : 1;
#endif
#endif
			ULONG64 Owner : 1;
			ULONG64 WriteThrough : 1;
			ULONG64 CacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 LargePage : 1;
			ULONG64 Global : 1;
			ULONG64 CopyOnWrite : 1;
			ULONG64 Prototype : 1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
			ULONG64 Write : 1;
			ULONG64 PageFrameNumber : 36;
			ULONG64 reserved1 : 4;
#else
#ifdef CONFIG_SMP
			ULONG64 Write : 1;
#else
			ULONG64 reserved0 : 1;
#endif
			ULONG64 PageFrameNumber : 28;
			ULONG64 reserved1 : 12;
#endif
			ULONG64 SoftwareWsIndex : 11;
			ULONG64 NoExecute : 1;
		} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

		typedef struct _MMPTE_PROTOTYPE {
			ULONG64 Valid : 1;
			ULONG64 Unused0 : 7;
			ULONG64 ReadOnly : 1;
			ULONG64 Unused1 : 1;
			ULONG64 Prototype : 1;
			ULONG64 Protection : 5;
			LONG64 ProtoAddress : 48;
		} MMPTE_PROTOTYPE;

		typedef enum _MI_SYSTEM_VA_TYPE { /* 17 / 16 elements; 0x0004 / 0x0004 Bytes */
			MiVaUnused = 0,
			MiVaSessionSpace = 1,
			MiVaProcessSpace = 2,
			MiVaBootLoaded = 3,
			MiVaPfnDatabase = 4,
			MiVaNonPagedPool = 5,
			MiVaPagedPool = 6,
			MiVaSpecialPoolPaged = 7,
			MiVaSystemCache = 8,
			MiVaSystemPtes = 9,
			MiVaHal = 10,
			MiVaSessionGlobalSpace = 11,
			MiVaDriverImages = 12,
			MiVaSpecialPoolNonPaged = 13,
#if defined(_M_X64)
			MiVaMaximumType = 14,
			MiVaSystemPtesLarge = 15
#else                                                                           // #if defined(_M_X64)
			MiVaPagedProtoPool = 14,
			MiVaMaximumType = 15,
			MiVaSystemPtesLarge = 16
#endif                                                                          // #if defined(_M_X64)
		} MI_SYSTEM_VA_TYPE, * PMI_SYSTEM_VA_TYPE;

		typedef struct _MMPTE {
			uint64_t Long;
			MMPTE_HARDWARE Hard;
			MMPTE_PROTOTYPE Proto;
			MMPTE_SOFTWARE Soft;
		} MMPTE, * PMMPTE;
	};
};

namespace nt {
	const NTSTATUS STATUS_ACCESS_DENIED = 0xC0000022;
	const NTSTATUS STATUS_SECTION_PROTECTION = 0xC000004E;
	const NTSTATUS STATUS_PROCEDURE_NOT_FOUND = 0xC000007A;
	const NTSTATUS STATUS_INVALID_PAGE_PROTECTION = 0xC0000045;

	template <typename T>
	struct _LIST_ENTRY_T
	{
		T Flink;
		T Blink;
	};

	template <typename T>
	struct _UNICODE_STRING_T
	{
		using type = T;

		uint16_t Length;
		uint16_t MaximumLength;
		T Buffer;
	};

	template<typename T>
	struct _LDR_DATA_TABLE_ENTRY_BASE_T
	{
		_LIST_ENTRY_T<T> InLoadOrderLinks;
		_LIST_ENTRY_T<T> InMemoryOrderLinks;
		_LIST_ENTRY_T<T> InInitializationOrderLinks;
		T DllBase;
		T EntryPoint;
		uint32_t SizeOfImage;
		_UNICODE_STRING_T<T> FullDllName;
		_UNICODE_STRING_T<T> BaseDllName;
		uint32_t Flags;
		uint16_t LoadCount;
		uint16_t TlsIndex;
		_LIST_ENTRY_T<T> HashLinks;
		uint32_t TimeDateStamp;
		T EntryPointActivationContext;
		T PatchInformation;
	};

	typedef enum _SECTION_INHERIT
	{
		ViewShare = 1,
		ViewUnmap = 2
	} SECTION_INHERIT;

#ifndef DRIVER

	NTSTATUS
	NTAPI
	NtCreateSection(
		_Out_    PHANDLE            SectionHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER     MaximumSize,
		_In_     ULONG              SectionPageProtection,
		_In_     ULONG              AllocationAttributes,
		_In_opt_ HANDLE             FileHandle
	);

	NTSTATUS
	NTAPI
	NtMapViewOfSection(
		_In_        HANDLE          SectionHandle,
		_In_        HANDLE          ProcessHandle,
		_Inout_     PVOID* BaseAddress,
		_In_        ULONG_PTR       ZeroBits,
		_In_        SIZE_T          CommitSize,
		_Inout_opt_ PLARGE_INTEGER  SectionOffset,
		_Inout_     PSIZE_T         ViewSize,
		_In_        SECTION_INHERIT InheritDisposition,
		_In_        ULONG           AllocationType,
		_In_        ULONG           Win32Protect
	);

	NTSTATUS
	NTAPI
	NtUnmapViewOfSection(
		_In_     HANDLE ProcessHandle,
		_In_opt_ PVOID  BaseAddress
	);

	NTSTATUS
	NTAPI
	NtCreateThreadEx(
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
		_In_opt_ PVOID Argument,
		_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
		_In_ SIZE_T ZeroBits,
		_In_ SIZE_T StackSize,
		_In_ SIZE_T MaximumStackSize,
		_In_opt_ PVOID AttributeList
	);

#endif
};

using _LDR_DATA_TABLE_ENTRY_BASE64 = nt::_LDR_DATA_TABLE_ENTRY_BASE_T<uint64_t>;

// definitions
typedef LARGE_INTEGER PHYSICAL_ADDRESS;
using ExAllocatePoolFn = PVOID(NTAPI*)(unsigned long PoolType, SIZE_T NumberOfBytes);

#define NtCurrentProcess() ( HANDLE(-1) )

/*typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		} data;
	};

	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;*/