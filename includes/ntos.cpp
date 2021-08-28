#include "ntos.h"

#ifndef DRIVER

namespace nt {
	NTSTATUS
		NTAPI
		NtCreateSection(
			_Out_    PHANDLE            SectionHandle,
			_In_     ACCESS_MASK        DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER     MaximumSize,
			_In_     ULONG              SectionPageProtection,
			_In_     ULONG              AllocationAttributes,
			_In_opt_ HANDLE             FileHandle)
	{
		typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
		static NtCreateSection_t Fn = NtCreateSection_t(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateSection"));
		if (Fn)
			return Fn(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
		SetLastError(ERROR_PROC_NOT_FOUND);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

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
			_In_        ULONG           Win32Protect)
	{
		typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
		static NtMapViewOfSection_t Fn = NtMapViewOfSection_t(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtMapViewOfSection"));
		if (Fn)
			return Fn(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
		SetLastError(ERROR_PROC_NOT_FOUND);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	NTSTATUS
		NTAPI
		NtUnmapViewOfSection(
			_In_     HANDLE ProcessHandle,
			_In_opt_ PVOID  BaseAddress)
	{
		typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
		static NtUnmapViewOfSection_t Fn = NtUnmapViewOfSection_t(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection"));
		if (Fn)
			return Fn(ProcessHandle, BaseAddress);
		SetLastError(ERROR_PROC_NOT_FOUND);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	NTSTATUS NtCreateThreadEx(
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
		_In_opt_ PVOID AttributeList)
	{
		typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
		static NtCreateThreadEx_t Fn = NtCreateThreadEx_t(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThreadEx"));
		if (Fn)
			return Fn(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		SetLastError(ERROR_PROC_NOT_FOUND);
		return STATUS_PROCEDURE_NOT_FOUND;
	}
};

#endif