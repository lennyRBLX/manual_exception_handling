#pragma once

#include <Windows.h>
#include <cstdint>
#include <memory>
#include <ehdata.h>
#include <psapi.h>
#include <intrin.h>

#define SW_IMPL
#include "stackwalker.h"

#include "ntos.h"
#include "pe.h"

#ifndef DRIVER

namespace {
	namespace memory {
		DWORD protect(uint64_t address, DWORD flags, size_t size = 0) {
			DWORD old = 0;
			if (!VirtualProtect((void*)address, size, flags, &old))
				return NULL;

			return old;
		}

		template <typename R, typename A>
		R* allocate(A size = 0, ULONG protect = PAGE_READWRITE) {
			return reinterpret_cast<R*>(
				VirtualAlloc(NULL, static_cast<size_t>(size) * sizeof(R), MEM_COMMIT | MEM_RESERVE, protect)
				);
		}

		template <typename A>
		bool free(A* memory_block) {
			return VirtualFree(memory_block, NULL, MEM_RELEASE);
		}

		void* resolve_relative(_In_ void* Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
			__try {
				if (Instruction != 0) {
					uint64_t Instr = (uint64_t)Instruction;
					long RipOffset = *(long*)(Instr + OffsetOffset);
					void* ResolvedAddr = (void*)(Instr + InstructionSize + RipOffset);

					return ResolvedAddr;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

			return 0;
		}

		// bbsearchpattern
		int pattern_scan(IN CONST UCHAR* pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, IN INT iterations) {
			assert(ppFound != NULL && pattern != NULL && base != NULL);
			if (ppFound == NULL || pattern == NULL || base == NULL)
				return 0;

			for (ULONG_PTR i = 0; i < size - len; i++)
			{
				int found = 1;
				for (ULONG_PTR j = 0; j < len; j++)
				{
					if (pattern[j] != wildcard && pattern[j] != ((CONST UCHAR*)base)[i + j])
					{
						found = 0;
						break;
					}
				}

				if (found == 1 && iterations == 1)
				{
					*ppFound = (PUCHAR)base + i;
					return 1;
				}
				else if (found == 1) {
					--iterations;
				}
			}

			return 0;
		}

		size_t query(uint64_t address, void* buffer) {
			return VirtualQuery(reinterpret_cast<void*>(address), reinterpret_cast<MEMORY_BASIC_INFORMATION*>(buffer), sizeof(MEMORY_BASIC_INFORMATION));
		}

		template <typename A, typename B>
		bool read(A address, B* buffer, size_t size = 0, bool set_protect = false) {
			__try {
				DWORD old_flags; if (set_protect) old_flags = protect((uint64_t)address, PAGE_EXECUTE_READWRITE, size);

				size_t copied = 0;
				bool result = ReadProcessMemory(GetCurrentProcess(), (void*)address, buffer, size, &copied);

				if (set_protect) protect((uint64_t)address, old_flags, size);
				return result;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { return false; }

			return false;
		}

		template <typename A, typename B>
		bool write(A address, B* buffer, size_t size = 0) {
			__try {
				DWORD old_flags = protect((uint64_t)address, PAGE_EXECUTE_READWRITE, size);

				size_t copied = 0;
				bool result = WriteProcessMemory(GetCurrentProcess(), (void*)address, buffer, size, &copied);

				protect((uint64_t)address, old_flags, size);

				return result;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { return false; }

			return false;
		}

		bool memcpy_l(void* destination, void* source, size_t size = 0) { // unused
			bool locked = VirtualLock(source, size);
			if (locked) {
				memcpy(destination, source, size);
				locked = VirtualUnlock(source, size);
			}

			return !locked;
		}

		template <class F>
		void enum_current_modules(F callback) { // unused
			HMODULE modules[1024];
			DWORD needed;

			if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
				for (size_t i = 0; i < (needed / sizeof(HMODULE)); i++) {
					if (callback(pe::pe(modules[i])))
						break;
				}
			}
		}

		/* initialization */
		bool init_static_tls(void* dll) { // unused
			pe::pe module_ = reinterpret_cast<HMODULE>(dll);
			auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(reinterpret_cast<uint64_t>(dll) + module_.nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			if (tls && tls->AddressOfIndex) {
				pe::pe ntdll(LoadLibraryA("ntdll.dll"));
				uint64_t ldrp_handle_tls_data; memory::pattern_scan((UCHAR*)"\x48\x8b\xCC\xCC\x66\x39\xCC\x6e\x75\xCC\xe8\xCC\xCC\xCC\xCC", 0xCC, 15, reinterpret_cast<void*>(ntdll.get_image_base()), ntdll.get_image_size(), reinterpret_cast<void**>(&ldrp_handle_tls_data), 1);
				ldrp_handle_tls_data = reinterpret_cast<uint64_t>(memory::resolve_relative(reinterpret_cast<void*>(ldrp_handle_tls_data + 10), 1, 5));

				using LdrpHandleTlsData_ = NTSTATUS(__thiscall*)(_LDR_DATA_TABLE_ENTRY_BASE64* Entry);
				auto LdrpHandleTlsData = reinterpret_cast<LdrpHandleTlsData_>(ldrp_handle_tls_data);

				_LDR_DATA_TABLE_ENTRY_BASE64 entry = {}; entry.DllBase = reinterpret_cast<uint64_t>(dll);
				auto status = LdrpHandleTlsData(&entry);
				return NT_SUCCESS(status);
			}

			return false;
		}

		/* exception handling */
		namespace exceptions {
			uint64_t image_base;
			size_t image_size;

			IMAGE_RUNTIME_FUNCTION_ENTRY* exception_table;
			size_t exception_size;

			DWORD main_thread_id;

#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PEXCEPTION_ROUTINE)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PULONG)((PULONG)GetLanguageSpecificDataPtr(info) + 1))

			// from <ehdata.h>
//#define EH_MAGIC_NUMBER1 0x19930520    
//#define EH_PURE_MAGIC_NUMBER1 0x01994000
//#define EH_EXCEPTION_NUMBER ('msc' | 0xE0000000)

			bool call_stack_available;
			size_t last_used_call_stack;
			uint64_t call_stack[SW_MAX_FRAMES];
			void callstack_entry(const sw_callstack_entry* entry, void* userptr) {
				if (!call_stack_available) {
					call_stack_available = true;
					last_used_call_stack = 0;
				}

				call_stack[last_used_call_stack++] = entry->address;
			}

			using RaiseException_t = void(*)(DWORD code, DWORD flags, DWORD num_args, const uint64_t* arguments);
			RaiseException_t RaiseException_o;

			void RaiseException_hk(DWORD code, DWORD flags, DWORD num_args, const uint64_t* arguments) {
				if (code == EH_EXCEPTION_NUMBER) {
					sw_callbacks callbacks = {};
					callbacks.callstack_entry = memory::exceptions::callstack_entry;

					sw_context* stackwalk = sw_create_context_capture(SW_OPTIONS_NONE, callbacks, NULL);
					if (stackwalk) {
						sw_show_callstack(stackwalk, NULL);
						sw_destroy_context(stackwalk);
					}
				}

				return RaiseException_o(code, flags, num_args, arguments);
			}

			bool allow_logs = true;
			bool allow_console_logs = true;
			LONG NTAPI exception_handler(_In_ PEXCEPTION_POINTERS exception) {
				// verify exception address to our image boundaries
				auto exception_address = exception->ContextRecord->Rip; // exception->ExceptionRecord->ExceptionInformation[2] is NULL, and worthless...
				auto exception_code_ = exception->ExceptionRecord->ExceptionCode;

				// c++ exception support
				if (exception_code_ == EH_EXCEPTION_NUMBER) {
					// specific to this image
					bool this_image = exception->ExceptionRecord->ExceptionInformation[2] >= image_base && exception->ExceptionRecord->ExceptionInformation[2] <= image_base + image_size;
					if (this_image) {
						if (exception->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 || exception->ExceptionRecord->ExceptionInformation[3] != image_base) {
							exception->ExceptionRecord->ExceptionInformation[0] = static_cast<uint64_t>(EH_MAGIC_NUMBER1);
							exception->ExceptionRecord->ExceptionInformation[3] = image_base;
						}
					}

					if (exception_table && call_stack_available && this_image) {
						for (size_t i = 0; i < SW_MAX_FRAMES; i++) {
							uint64_t stack_entry = call_stack[i];
							if (stack_entry == NULL) break;

							for (size_t i = 0; i < (exception_size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)); i++) {
								auto entry = exception_table[i];
								UNWIND_INFO unwind_info = {}; memory::read(exceptions::image_base + entry.UnwindData, &unwind_info, sizeof(UNWIND_INFO));

								// check if exception occured in this runtime entry, as well as if it has a handler
								auto start = image_base + entry.BeginAddress, end = image_base + entry.EndAddress;
								if ((stack_entry >= start && stack_entry <= end) && (unwind_info.Flags & UNW_FLAG_EHANDLER || unwind_info.Flags & UNW_FLAG_UHANDLER)) {
									auto control_pc = stack_entry;

									UNWIND_HISTORY_TABLE history_table = {};
									auto function_entry = RtlLookupFunctionEntry(control_pc, &image_base, &history_table);
									if (function_entry) {
										call_stack_available = false;
										memset(call_stack, '\0', sizeof(uint64_t) * SW_MAX_FRAMES);
										
										void* handler_data = NULL;
										uint64_t establisher_frame = NULL;
										auto language_handler = RtlVirtualUnwind(UNW_FLAG_EHANDLER, image_base, control_pc, function_entry, exception->ContextRecord, &handler_data, &establisher_frame, NULL);

										DISPATCHER_CONTEXT new_dc = {};
										new_dc.ControlPc = control_pc;
										new_dc.ImageBase = image_base;
										new_dc.FunctionEntry = function_entry;
										new_dc.EstablisherFrame = establisher_frame;
										new_dc.TargetIp = reinterpret_cast<uint64_t>(&function_entry);
										new_dc.ContextRecord = exception->ContextRecord;
										new_dc.LanguageHandler = language_handler;
										new_dc.HandlerData = handler_data;

										auto result = language_handler(exception->ExceptionRecord, reinterpret_cast<void*>(establisher_frame), exception->ContextRecord, &new_dc);
										return result;
									}
								}
							}
						}
					}
				}

				/*
				    DWORD64 Rax;
					DWORD64 Rcx;
					DWORD64 Rdx;
					DWORD64 Rbx;
					DWORD64 Rsp;
					DWORD64 Rbp;
					DWORD64 Rsi;
					DWORD64 Rdi;
					DWORD64 R8;
					DWORD64 R9;
					DWORD64 R10;
					DWORD64 R11;
					DWORD64 R12;
					DWORD64 R13;
					DWORD64 R14;
					DWORD64 R15;
				*/
				
				// __try / __except exception support
				if (exception_address >= image_base && exception_address <= (image_base + image_size)) {
					// enumerate exception table
					if (exception_table) {
						for (size_t i = 0; i < (exception_size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)); i++) {
							auto entry = exception_table[i];
							UNWIND_INFO unwind_info = {}; memory::read(exceptions::image_base + entry.UnwindData, &unwind_info, sizeof(UNWIND_INFO));
							auto exception_data_ptr = reinterpret_cast<uint64_t>(GetExceptionDataPtr(&unwind_info));
							ULONG frame_count = NULL; bool got_frame_count = memory::read(exception_data_ptr, &frame_count, sizeof(ULONG));
							if (frame_count < 0 || !got_frame_count)
								continue;

							// check if exception occured in this runtime entry, as well as if it has a handler, and if it has a frame
							auto start = image_base + entry.BeginAddress, end = image_base + entry.EndAddress;
							if ((exception_address >= start && exception_address <= end) && (unwind_info.Flags & UNW_FLAG_EHANDLER || unwind_info.Flags & UNW_FLAG_UHANDLER) && frame_count > 0) {
								for (size_t i = 0; i < frame_count; i++) { // enum frames
									auto frame_index = 1 + (i * 4);
									ULONG exception_frame_offset = NULL; memory::read(exception_data_ptr + (sizeof(ULONG) * (frame_index + 3)), &exception_frame_offset, sizeof(ULONG));
									uint64_t exception_frame = exceptions::image_base + exception_frame_offset;
									
									ULONG frame_start_offset = NULL; memory::read(exception_data_ptr + (sizeof(ULONG) * frame_index), &frame_start_offset, sizeof(ULONG));
									ULONG frame_end_offset = NULL; memory::read(exception_data_ptr + (sizeof(ULONG) * (frame_index + 1)), &frame_start_offset, sizeof(ULONG));

									auto start = exceptions::image_base + entry.BeginAddress, end = exceptions::image_base + entry.EndAddress;
									auto frame_start = exceptions::image_base + frame_start_offset, frame_end = exceptions::image_base + frame_end_offset;
									if (exception_address >= frame_start && exception_address <= frame_end) { // hop to __except statement/s
										// winapi stuff
										SetLastError(exception->ExceptionRecord->ExceptionCode);

										// hop
										exception->ContextRecord->Rip = exception_frame;
										return EXCEPTION_CONTINUE_EXECUTION;
									}
								}
							}
						}
					}
				}

				return EXCEPTION_CONTINUE_SEARCH;
			}

			template<typename T>
			struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY {
				T     ExceptionDirectory;   // PIMAGE_RUNTIME_FUNCTION_ENTRY
				T     ImageBase;
				uint32_t ImageSize;
				uint32_t SizeOfTable;
			};

			template<typename T>
			struct _RTL_INVERTED_FUNCTION_TABLE {
				ULONG Count;
				ULONG MaxCount;
				ULONG Epoch;
				ULONG Overflow;
				_RTL_INVERTED_FUNCTION_TABLE_ENTRY<T> Entries[0x200];
			};

			bool insert_inverted_func_table(void* dll, size_t size) {
				_RTL_INVERTED_FUNCTION_TABLE<DWORD64>* LdrpInvertedFunctionTable = reinterpret_cast<_RTL_INVERTED_FUNCTION_TABLE<DWORD64>*>(GetProcAddress(LoadLibraryA("ntdll.dll"), "KiUserInvertedFunctionTable"));
				
				pe::pe ntdll(LoadLibraryA("ntdll.dll"));
				uint64_t rtl_insert_inverted_func_table; memory::pattern_scan((UCHAR*)"\x41\x8B\x56\xCC\x48\x8B\x4C", 0xCC, 7, reinterpret_cast<void*>(ntdll.get_image_base()), ntdll.get_image_size(), reinterpret_cast<void**>(&rtl_insert_inverted_func_table), 1);
				rtl_insert_inverted_func_table = reinterpret_cast<uint64_t>(memory::resolve_relative(reinterpret_cast<void*>(rtl_insert_inverted_func_table + 9), 1, 5));
				
				using RtlInsertInvertedFunctionTable_ = LONG(__fastcall*)(void* ImageBase, size_t ImageSize);
				auto RtlInsertInvertedFunctionTable = reinterpret_cast<RtlInsertInvertedFunctionTable_>(rtl_insert_inverted_func_table);
				for (ULONG i = 0; i < LdrpInvertedFunctionTable->Count; i++) {
					if (LdrpInvertedFunctionTable->Entries[i].ImageBase == reinterpret_cast<uint64_t>(dll))
						return true;
				}

				RtlInsertInvertedFunctionTable(dll, size);

				for (ULONG i = 0; i < LdrpInvertedFunctionTable->Count; i++) {
					auto entry = LdrpInvertedFunctionTable->Entries[i];
					if (entry.ImageBase != reinterpret_cast<uint64_t>(dll))
						continue;

					if (entry.SizeOfTable != 0)
						return true; // safeseh

					auto exception_dir = memory::allocate<DWORD>(sizeof(DWORD) * 0x800);
					if (!exception_dir)
						return false;

					// EncodeSystemPointer( mem->ptr() )
					uint32_t size = sizeof(uint64_t);
					uint32_t cookie = *reinterpret_cast<uint32_t*>(0x7FFE0330);
					uint64_t pEncoded = _rotr64(cookie ^ reinterpret_cast<uint64_t>(exception_dir), cookie & 0x3F);

					// m_LdrpInvertedFunctionTable->Entries[i].ExceptionDirectory
					uint64_t field_offset = offsetof(_RTL_INVERTED_FUNCTION_TABLE<DWORD64>, Entries) + (i * sizeof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY<DWORD64>)) + offsetof(_RTL_INVERTED_FUNCTION_TABLE_ENTRY<DWORD64>, ExceptionDirectory);

					// In Win10 LdrpInvertedFunctionTable is located in mrdata section
					// mrdata is read-only by default 
					// LdrProtectMrdata is used to make it writable when needed
					auto old_protect = memory::protect(reinterpret_cast<uint64_t>(LdrpInvertedFunctionTable) + field_offset, PAGE_EXECUTE_READWRITE, sizeof(uint64_t));
					auto result = memory::write(reinterpret_cast<uint64_t>(LdrpInvertedFunctionTable) + field_offset, &pEncoded, size);
					memory::protect(reinterpret_cast<uint64_t>(LdrpInvertedFunctionTable) + field_offset, old_protect, sizeof(uint64_t));

					return result;
				}

				return false;
			}

			bool remove_inverted_func_table(void* dll) { // unused
				_RTL_INVERTED_FUNCTION_TABLE<DWORD64>* LdrpInvertedFunctionTable = reinterpret_cast<_RTL_INVERTED_FUNCTION_TABLE<DWORD64>*>(GetProcAddress(LoadLibraryA("ntdll.dll"), "KiUserInvertedFunctionTable"));
				
				pe::pe ntdll(LoadLibraryA("ntdll.dll"));
				uint64_t rtl_remove_inverted_func_table; memory::pattern_scan((UCHAR*)"\xe8\xCC\xCC\xCC\xCC\xb9\x01\x00\x00\x00\x48", 0xCC, 11, reinterpret_cast<void*>(ntdll.get_image_base()), ntdll.get_image_size(), reinterpret_cast<void**>(&rtl_remove_inverted_func_table), 1);
				rtl_remove_inverted_func_table = reinterpret_cast<uint64_t>(memory::resolve_relative(reinterpret_cast<void*>(rtl_remove_inverted_func_table), 1, 5));

				using RtlRemoveInvertedFunctionTable_ = LONG(__fastcall*)(void* ImageBase);
				auto RtlRemoveInvertedFunctionTable = reinterpret_cast<RtlRemoveInvertedFunctionTable_>(rtl_remove_inverted_func_table);
				
				bool found = false;
				for (ULONG i = 0; i < LdrpInvertedFunctionTable->Count; i++) {
					if (LdrpInvertedFunctionTable->Entries[i].ImageBase == reinterpret_cast<uint64_t>(dll)) {
						found = true;
						break;
					}
				}

				if (!found) return true;

				RtlRemoveInvertedFunctionTable(dll);

				found = false;
				for (ULONG i = 0; i < LdrpInvertedFunctionTable->Count; i++) {
					if (LdrpInvertedFunctionTable->Entries[i].ImageBase == reinterpret_cast<uint64_t>(dll)) {
						found = true;
						break;
					}
				}

				return !found;
			}
		};

		bool enable_exceptions(void* dll) { // limits: only supports single target module
			auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dll);
			auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint64_t>(dll) + dos->e_lfanew);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE)
				return false; // :(

			exceptions::image_base = NULL;
			exceptions::image_size = NULL;
			exceptions::exception_table = NULL;
			exceptions::exception_size = NULL;

			auto exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			auto exception_table = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(reinterpret_cast<uint64_t>(dll) + exception_dir.VirtualAddress); auto exception_size = exception_dir.Size;
			if (exception_table) {
				exceptions::image_base = reinterpret_cast<uint64_t>(dll);
				exceptions::image_size = nt->OptionalHeader.SizeOfImage;
				exceptions::exception_table = exception_table;
				exceptions::exception_size = exception_size;

				pe::pe m = reinterpret_cast<HMODULE>(dll);
				exceptions::RaiseException_o = reinterpret_cast<exceptions::RaiseException_t>(m.hook_import("kernel32.dll", "RaiseException", exceptions::RaiseException_hk)); // collect call stack for thrown exceptions

				// insert inverted
				bool inserted = exceptions::insert_inverted_func_table(dll, exceptions::image_size);
				
				// add function table
				if (!inserted) {
					ULONG size = 0;
					auto table = ImageDirectoryEntryToData(dll, true, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size);
					bool added = RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(table), size / sizeof(PRUNTIME_FUNCTION), reinterpret_cast<uint64_t>(dll));
				}

				// add veh
				AddVectoredExceptionHandler(1, &exceptions::exception_handler);
				return true;
			}

			return false;
		}
	}
}

#define cxx_try() memory::exceptions::cxx_try()

#endif