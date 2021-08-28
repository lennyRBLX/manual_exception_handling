#include "pe.h"

#include "memory.h"

namespace pe {
	pe::pe() {}

	pe::pe(uint8_t* address) {
		this->buffer = address;

		__try {
			this->dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(address);
			if (!(dos_header->e_magic == IMAGE_DOS_SIGNATURE))
				return;

			this->nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(address + this->dos_header->e_lfanew);
			if (!(nt_headers->Signature == IMAGE_NT_SIGNATURE))
				return;

			this->file_header = this->nt_headers->FileHeader;
			this->optional_header = this->nt_headers->OptionalHeader;
			this->first_section = IMAGE_FIRST_SECTION(this->nt_headers);

			IMAGE_DATA_DIRECTORY export_entry = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			this->export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(address + export_entry.VirtualAddress);
			this->exports_size = export_entry.Size;

			this->export_names = reinterpret_cast<DWORD*>(address + this->export_dir->AddressOfNames);
			this->export_functions = reinterpret_cast<DWORD*>(address + this->export_dir->AddressOfFunctions);
			this->export_ordinals = reinterpret_cast<USHORT*>(address + this->export_dir->AddressOfNameOrdinals);

			IMAGE_DATA_DIRECTORY import_entry = this->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			this->first_import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(address + import_entry.VirtualAddress);
			this->import_size = import_entry.Size;

			this->valid = true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	pe::pe(HMODULE dll) {
		*this = pe(reinterpret_cast<uint8_t*>(dll));
	}

	bool pe::is_valid() {
		bool result = true;
		if (!valid || !dos_header || !(dos_header->e_magic == IMAGE_DOS_SIGNATURE) || !nt_headers || !(nt_headers->Signature == IMAGE_NT_SIGNATURE))
			result = false;

		return result;
	}

	uint64_t pe::get_image_base() {
		return this->optional_header.ImageBase;
	}

	size_t pe::get_image_size() {
		return this->optional_header.SizeOfImage;
	}

	section_data pe::get_section(const char* section_name) {
		section_data result = { NULL, NULL, 0, 0, 0 };

		for (size_t i = 0; i < this->file_header.NumberOfSections; i++) {
			IMAGE_SECTION_HEADER* section = &first_section[i];
			if (!strncmp(reinterpret_cast<char*>(section->Name), section_name, strlen(section_name))) {
				result = get_section_data(section);
				break;
			}
		}

		return result;
	}

	section_data pe::get_section_data(IMAGE_SECTION_HEADER* section) {
		return {
			buffer + section->VirtualAddress,
			buffer + section->VirtualAddress + section->Misc.VirtualSize,
			section->VirtualAddress,
			section->Misc.VirtualSize,
			section->Characteristics
		};
	}

	export_data pe::get_export(const char* export_name) {
		export_data result = { 0, 0, NULL };

		for (size_t i = 0; i < this->export_dir->NumberOfNames; i++) {
			auto name = reinterpret_cast<const char*>(buffer + export_names[i]);
			auto ordinal = export_ordinals[i];
			if (ordinal > export_dir->NumberOfFunctions)
				continue;

			auto function = reinterpret_cast<uint64_t>(buffer + export_functions[ordinal]);
			if (function >= reinterpret_cast<uint64_t>(export_dir) && function <= (reinterpret_cast<uint64_t>(export_dir) + exports_size))
				continue;

			if (!strncmp(name, export_name, strlen(export_name))) {
				result = get_export_data(name, function, ordinal);
				break;
			}
		}

		return result;
	}

	export_data pe::get_export_data(const char* name, uint64_t address, unsigned short ordinal) {
		return {
			address,
			ordinal,
			name
		};
	}

	IMAGE_SECTION_HEADER* pe::translate_raw_section(DWORD rva) {
		auto section = IMAGE_FIRST_SECTION(this->nt_headers);
		for (auto i = 0; i < this->nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
			if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
				return section;
		}

		return NULL;
	}

	void* pe::translate_raw(DWORD rva) {
		auto section = translate_raw_section(rva);
		if (!section) return NULL;
		return this->buffer + section->PointerToRawData + (rva - section->VirtualAddress);
	}

	void* pe::hook_import(const char* module_name, const char* function_name, void* hook, bool strict_search) {
		void* result = NULL;
		enum_imports(
			[&result, &module_name, &function_name, &hook, &strict_search](bool is_ordinal, char* module_n, char* buffer, IMAGE_THUNK_DATA* thunk) {
				if (!is_ordinal && ((strict_search && !_strcmpi(function_name, buffer)) || std::string(buffer).find(function_name) != std::string::npos)) {
					MEMORY_BASIC_INFORMATION mbi = {};
					if (memory::query(reinterpret_cast<uint64_t>(thunk), &mbi) == sizeof(MEMORY_BASIC_INFORMATION)) {
						auto old_protect = memory::protect(reinterpret_cast<uint64_t>(mbi.BaseAddress), PAGE_READWRITE, mbi.RegionSize);
						if (old_protect != NULL) {
							result = reinterpret_cast<void*>(thunk->u1.Function);
							thunk->u1.Function = reinterpret_cast<uint64_t>(hook);
							memory::protect(reinterpret_cast<uint64_t>(mbi.BaseAddress), old_protect, mbi.RegionSize);
						}
					}

					return false;
				}

				return true;
			}
		);

		return result;
	}
};