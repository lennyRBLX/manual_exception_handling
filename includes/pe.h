#pragma once

#include <Windows.h>
#include <cstdint>

struct section_data {
	uint8_t* start;
	uint8_t* end;
	uint32_t v_start;
	uint32_t size;
	uint32_t characteristics;
};

struct export_data {
	uint64_t address;
	unsigned short ordinal;
	const char* name;
};

namespace pe {
	class pe {
	private:
		bool valid;
	public:
		pe();
		pe(uint8_t* address);
		pe(HMODULE dll);

		IMAGE_DOS_HEADER* dos_header;
		IMAGE_NT_HEADERS64* nt_headers;
		IMAGE_OPTIONAL_HEADER64 optional_header;
		IMAGE_FILE_HEADER file_header;
		IMAGE_SECTION_HEADER* first_section;

		IMAGE_EXPORT_DIRECTORY* export_dir;
		
		DWORD* export_names;
		DWORD* export_functions;
		USHORT* export_ordinals;
		size_t exports_size;

		IMAGE_IMPORT_DESCRIPTOR* first_import;

		size_t import_size;

		bool is_valid();
		uint64_t get_image_base();
		size_t get_image_size();

		section_data get_section(const char* section_name);
		section_data get_section_data(IMAGE_SECTION_HEADER* section);

		export_data get_export(const char* export_name);
		export_data get_export_data(const char* name, uint64_t address, unsigned short ordinal);

		IMAGE_SECTION_HEADER* translate_raw_section(DWORD rva);
		void* translate_raw(DWORD rva);

		template <class F>
		void enum_sections(F func) {
			for (size_t i = 0; i < this->file_header.NumberOfSections; i++) {
				IMAGE_SECTION_HEADER* section = &first_section[i];
				if (!func(section))
					break;
			}
		}

		template <class F>
		void enum_exports(F func) {
			for (size_t i = 0; i < this->export_dir->NumberOfNames; i++) {
				auto name = reinterpret_cast<const char*>(buffer + export_names[i]);
				auto ordinal = export_ordinals[i];
				if (ordinal > export_dir->NumberOfFunctions)
					continue;

				auto function = reinterpret_cast<uint64_t>(buffer + export_functions[ordinal]);
				if (!func(name, function, ordinal))
					break;
			}
		}

		template <class F>
		void enum_imports(F func) {
			auto import = this->first_import;
			if (!import) return;

			for (; import->FirstThunk; ++import) {
				auto module_name = reinterpret_cast<char*>(this->buffer + import->Name);
				if (!module_name)
					break;

				size_t i = 0;
				for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->buffer + import->OriginalFirstThunk); thunk->u1.AddressOfData; ++thunk) {
					if (thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
						if (!func(true, module_name, reinterpret_cast<char*>(&thunk->u1.Ordinal), reinterpret_cast<PIMAGE_THUNK_DATA>(this->buffer + import->FirstThunk)))
							break;
					}
					else {
						auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->buffer + static_cast<DWORD>(thunk->u1.AddressOfData));
						auto iat_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->buffer + import->FirstThunk); iat_thunk += i;
						if (!func(false, module_name, by_name->Name, iat_thunk))
							break;
					}

					i++;
				}
			}
		}

		void* hook_import(const char* module_name, const char* function_name, void* hook, bool strict_search = false);

	private:
		uint8_t* buffer;
	};
};