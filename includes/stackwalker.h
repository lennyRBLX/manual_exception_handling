
// Windows single header stack walker in C (DbgHelp)
// Copyright (c) 2021, Sepehr Taghdisian.
// Copyright (c) 2005 - 2019, Jochen Kalmbach. All rights reserved.
// Usage:
//  #define SW_IMPL
//  #include "stackwalkerc.h"
// 
//  sw_context* ctx = sw_create_context_capture(SW_OPTIONS_ALL, callbacks, NULL);
//  sw_show_callstack(ctx);
//  
// The usage is super simple, you can see the options/callbacks and check example.cpp
// 
// History:
//      1.0.0: Initial version
//      1.0.1: Bugs fixed, taking more sw_option flags into action
//      1.1.0: Added extra userptr to show_callstack_userptr to override the callbacks ptr per-callstack
//      1.2.0: Added fast backtrace implementation for captures in current thread. 
//             Added utility function sw_load_dbghelp
//             Added limiter function sw_set_callstack_limits
//      1.3.0  Added more advanced functions for resolving callstack lazily, sw_capture_current, sw_resolve_callstack
//      1.4.0  Added module cache and reload modules on-demand
//      1.5.0  House cleaning, added sw_set_dbghelp_hintpath, ditched error_msg callback for SW_LOG_ERROR macro
//      1.6.0  [BREAKING] added optional "hash" argument to `sw_capture_current`
//      1.6.1  sw_resolve_callstack skips non-existing symbols with "NA" entries
//
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifndef SW_API_DECL
#define SW_API_DECL
#endif

#ifndef SW_API_IMPL
#define SW_API_IMPL SW_API_DECL
#endif

#ifndef SW_MAX_NAME_LEN
#define SW_MAX_NAME_LEN 1024
#endif

#ifndef SW_MAX_FRAMES
#define SW_MAX_FRAMES 64
#endif

typedef enum sw_options
{
    SW_OPTIONS_NONE          = 0,
    SW_OPTIONS_SYMBOL        = 0x1,     // Get symbol names
    SW_OPTIONS_SOURCEPOS     = 0x2,     // Get symbol file+line
    SW_OPTIONS_MODULEINFO    = 0x4,     // Get module information
    SW_OPTIONS_VERBOSE       = 0xf,     // All above options
    SW_OPTIONS_SYMBUILDPATH  = 0x10,    // Generate a good symbol search path
    SW_OPTIONS_SYMUSESERVER  = 0x20,    // Use public microsoft symbol server
    SW_OPTIONS_SYMALL        = 0x30,    // All symbol options
    SW_OPTIONS_ALL           = 0x3f     // All options
} sw_options;

typedef void* sw_sys_handle;            // HANDLE
typedef void* sw_exception_pointers;    // PEXCEPTION_POINTERS
typedef struct sw_context sw_context;

typedef struct sw_callstack_entry
{
    uint64_t    address;
    uint64_t    offset;
    char        name[SW_MAX_NAME_LEN];
    char        und_name[SW_MAX_NAME_LEN];
    uint64_t    offset_from_symbol;
    uint32_t    offset_from_line;
    uint32_t    line;
    char        line_filename[SW_MAX_NAME_LEN];
    uint32_t    symbol_type;
    const char* symbol_type_str;
    char        module_name[SW_MAX_NAME_LEN];
    uint64_t    baseof_image;
    char        loaded_image_name[SW_MAX_NAME_LEN];
} sw_callstack_entry;

typedef struct sw_callbacks
{
    void (*symbol_init)(const char* search_path, uint32_t sym_opts, void* userptr);
    void (*load_module)(const char* img, const char* module, uint64_t base_addr, uint32_t size, void* userptr);
    void (*callstack_begin)(void* userptr);
    void (*callstack_entry)(const sw_callstack_entry* entry, void* userptr);
    void (*callstack_end)(void* userptr);
} sw_callbacks;

#ifdef __cplusplus
extern "C" {
#endif

SW_API_DECL sw_context* sw_create_context_capture(uint32_t options, sw_callbacks callbacks, void* userptr);
SW_API_DECL sw_context* sw_create_context_capture_other(uint32_t options, uint32_t process_id,
                                                        sw_sys_handle process, sw_callbacks callbacks, void* userptr);
SW_API_DECL sw_context* sw_create_context_exception(uint32_t options, 
                                                    sw_exception_pointers exp_ptrs,
                                                    sw_callbacks callbacks, void* userptr);
SW_API_DECL sw_context* sw_create_context_catch(uint32_t options, sw_callbacks callbacks, void* userptr);

SW_API_DECL void sw_destroy_context(sw_context* ctx);

SW_API_DECL void sw_set_symbol_path(sw_context* ctx, const char* sympath);
SW_API_DECL void sw_set_callstack_limits(sw_context* ctx, uint32_t frames_to_skip, uint32_t frames_to_capture);
SW_API_DECL bool sw_show_callstack_userptr(sw_context* ctx, sw_sys_handle thread_hdl /*=NULL*/, void* callbacks_userptr);
SW_API_DECL bool sw_show_callstack(sw_context* ctx, sw_sys_handle thread_hdl /*=NULL*/);

// manual/advanced functions
SW_API_DECL sw_sys_handle sw_load_dbghelp(void);
SW_API_DECL uint16_t sw_capture_current(sw_context* ctx, void* symbols[SW_MAX_FRAMES], uint32_t* hash);
SW_API_DECL uint16_t sw_resolve_callstack(sw_context* ctx, void* symbols[SW_MAX_FRAMES], 
                                          sw_callstack_entry entries[SW_MAX_FRAMES], uint16_t num_entries);
SW_API_DECL void sw_reload_modules(sw_context* ctx);
SW_API_DECL bool sw_get_symbol_module(sw_context* ctx, void* symbol, char module_name[32]);
SW_API_DECL void sw_set_dbghelp_hintpath(const char* path);

#ifdef __cplusplus
}
#endif

#ifdef SW_IMPL

#ifndef _WIN32
#error "Platforms other than Windows are not supported"
#endif

#define WIN32_LEAN_AND_MEAN
#pragma warning(push)
#pragma warning(disable : 5105)
#include <windows.h>
#pragma warning(pop)
#include <malloc.h> // alloca, malloc
#include <string.h> // strlen, strcat_s

#ifndef SW_ASSERT
#   include <assert.h>
#   define SW_ASSERT(e)   assert(e)
#endif

#ifndef SW_LOG_ERROR
#   include <stdio.h>
#   define SW_LOG_ERROR(err_fmt, ...) printf(err_fmt "\n", ##__VA_ARGS__)
#endif

#ifndef SW_MALLOC
#   define SW_MALLOC(size)        malloc(size)
#   define SW_FREE(ptr)           free(ptr)
#endif

#define _SW_UNUSED(x) (void)(x)

#ifndef _SW_PRIVATE
#   if defined(__GNUC__) || defined(__clang__)
#       define _SW_PRIVATE __attribute__((unused)) static
#   else
#       define _SW_PRIVATE static
#   endif
#endif

_SW_PRIVATE char* sw__strcpy(char* dst, size_t dst_sz, const char* src)
{
    SW_ASSERT(dst);
    SW_ASSERT(src);
    SW_ASSERT(dst_sz > 0);

    const size_t len = strlen(src);
    const size_t _max = dst_sz - 1;
    const size_t num = (len < _max ? len : _max);
    memcpy(dst, src, num);
    dst[num] = '\0';

    return dst;
}

#pragma pack(push, 8)
#include <DbgHelp.h>

typedef struct _IMAGEHLP_MODULE64_V3
{
    DWORD SizeOfStruct;        // set to sizeof(IMAGEHLP_MODULE64)
    DWORD64 BaseOfImage;       // base load address of module
    DWORD ImageSize;           // virtual size of the loaded module
    DWORD TimeDateStamp;       // date/time stamp from pe header
    DWORD CheckSum;            // checksum from the pe header
    DWORD NumSyms;             // number of symbols in the symbol table
    SYM_TYPE SymType;          // type of symbols loaded
    CHAR ModuleName[32];       // module name
    CHAR ImageName[256];       // image name
    CHAR LoadedImageName[256]; // symbol file name
    // new elements: 07-Jun-2002
    CHAR LoadedPdbName[256];   // pdb file name
    DWORD CVSig;               // Signature of the CV record in the debug directories
    CHAR CVData[MAX_PATH * 3]; // Contents of the CV record
    DWORD PdbSig;              // Signature of PDB
    GUID PdbSig70;             // Signature of PDB (VC 7 and up)
    DWORD PdbAge;              // DBI age of pdb
    BOOL PdbUnmatched;         // loaded an unmatched pdb
    BOOL DbgUnmatched;         // loaded an unmatched dbg
    BOOL LineNumbers;          // we have line number information
    BOOL GlobalSymbols;        // we have internal symbol information
    BOOL TypeInfo;             // we have type information
    // new elements: 17-Dec-2003
    BOOL SourceIndexed; // pdb supports source server
    BOOL Publics;       // contains public symbols
} IMAGEHLP_MODULE64_V3, *PIMAGEHLP_MODULE64_V3;

typedef struct _IMAGEHLP_MODULE64_V2
{
    DWORD SizeOfStruct;        // set to sizeof(IMAGEHLP_MODULE64)
    DWORD64 BaseOfImage;       // base load address of module
    DWORD ImageSize;           // virtual size of the loaded module
    DWORD TimeDateStamp;       // date/time stamp from pe header
    DWORD CheckSum;            // checksum from the pe header
    DWORD NumSyms;             // number of symbols in the symbol table
    SYM_TYPE SymType;          // type of symbols loaded
    CHAR ModuleName[32];       // module name
    CHAR ImageName[256];       // image name
    CHAR LoadedImageName[256]; // symbol file name
} IMAGEHLP_MODULE64_V2, *PIMAGEHLP_MODULE64_V2;
#pragma pack(pop)
  
typedef BOOL(__stdcall* SymCleanup_t)(IN HANDLE process); 
typedef PVOID(__stdcall* SymFunctionTableAccess64_t)(HANDLE process, DWORD64 AddrBase); 
typedef BOOL(__stdcall* SymGetLineFromAddr64_t)(IN HANDLE process,
                                                IN DWORD64 dwAddr,
                                                OUT PDWORD pdwDisplacement,
                                                OUT PIMAGEHLP_LINE64 line);  
typedef DWORD64(__stdcall* SymGetModuleBase64_t)(IN HANDLE process, IN DWORD64 dwAddr);                              
typedef BOOL(__stdcall* SymGetModuleInfo64_t)(IN HANDLE process,
                                              IN DWORD64 dwAddr,
                                              OUT IMAGEHLP_MODULE64_V3* ModuleInfo);
typedef DWORD(__stdcall* SymGetOptions_t)(VOID);
typedef BOOL(__stdcall* SymGetSymFromAddr64_t)(IN HANDLE process,
                                               IN DWORD64 dwAddr,
                                               OUT PDWORD64 pdwDisplacement,
                                               OUT PIMAGEHLP_SYMBOL64 Symbol);
typedef BOOL(__stdcall* SymInitialize_t)(IN HANDLE process, IN LPCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64(__stdcall* SymLoadModule64_t)(IN HANDLE process,
                                              IN HANDLE hFile,
                                              IN LPCSTR ImageName,
                                              IN LPCSTR ModuleName,
                                              IN DWORD64 BaseOfDll,
                                              IN DWORD SizeOfDll);
typedef BOOL(__stdcall* SymUnloadModule64_t)(IN HANDLE hProcess, IN DWORD64 BaseOfDll);                                              
typedef DWORD(__stdcall* SymSetOptions_t)(IN DWORD SymOptions);
typedef BOOL(__stdcall* StackWalk64_t)(DWORD                           MachineType,
                                       HANDLE                           process,
                                       HANDLE                           hThread,
                                       LPSTACKFRAME64                   StackFrame,
                                       PVOID                            ContextRecord,
                                       PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
                                       PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                                       PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
                                       PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress);
typedef DWORD(__stdcall WINAPI* UnDecorateSymbolName_t)(PCSTR DecoratedName,
                                                        PSTR  UnDecoratedName,
                                                        DWORD UndecoratedLength,
                                                        DWORD Flags);
typedef BOOL(__stdcall WINAPI* SymGetSearchPath_t)(HANDLE process, PSTR SearchPath, DWORD SearchPathLength);
typedef BOOL(__stdcall WINAPI* EnumerateLoadedModules64_t)(HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64  EnumLoadedModulesCallback, PVOID UserContext);

typedef BOOL(__stdcall* ReadProcessMemoryRoutine_t)(
      HANDLE  process,
      DWORD64 qwBaseAddress,
      PVOID   lpBuffer,
      DWORD   nSize,
      LPDWORD lpNumberOfBytesRead,
      LPVOID  pUserData); // optional data, which was passed in "show_callstack"
    
  
// **************************************** ToolHelp32 ************************
#include <TlHelp32.h>

// **************************************** PSAPI ************************
#include <Psapi.h>

// Normally it should be enough to use 'CONTEXT_FULL' (better would be 'CONTEXT_ALL')
#define USED_CONTEXT_FLAGS CONTEXT_FULL

// only available on msvc2015+ (_MSC_VER >= 1900)
#ifdef __cplusplus
extern "C" {
#endif
void** __cdecl __current_exception_context();
#ifdef __cplusplus
}
#endif

typedef struct sw_module_cache_item
{
    char    name[32];
    DWORD64 base_addr;
} sw_module_cache_item;

typedef struct sw_context_internal
{
    sw_context* parent;
    CONTEXT ctx;
    HMODULE dbg_help;
    HANDLE  process;
    SymCleanup_t fSymCleanup;
    SymFunctionTableAccess64_t fSymFunctionTableAccess64;
    SymGetModuleBase64_t fSymGetModuleBase64;
    SymGetModuleInfo64_t fSymGetModuleInfo64;
    
    SymGetOptions_t fSymGetOptions;
    SymGetSymFromAddr64_t fSymGetSymFromAddr64;
    SymGetLineFromAddr64_t fSymGetLineFromAddr64;
    SymInitialize_t fSymInitialize;
    SymLoadModule64_t fSymLoadModule64;
    SymUnloadModule64_t fSymUnloadModule64;
    
    SymSetOptions_t fSymSetOptions;
    StackWalk64_t fStackWalk64;
    UnDecorateSymbolName_t fUnDecorateSymbolName;
    SymGetSearchPath_t fSymGetSearchPath;
    EnumerateLoadedModules64_t fEnumerateLoadedModules64;

    CRITICAL_SECTION modules_cs;
    uint32_t num_modules;
    uint32_t max_modules;
    sw_module_cache_item* modules;
} sw_context_internal;

typedef struct sw_context
{
    sw_callbacks callbacks;
    void* callbacks_userptr;
    sw_sys_handle process;
    uint32_t process_id;
    bool modules_loaded;
    bool reload_modules;
    bool fatal_error;       // cannot recover anymore
    char sympath[SW_MAX_NAME_LEN];
    uint32_t options;
    uint32_t max_recursion;
    sw_context_internal internal;
    uint32_t    frames_to_skip;
    uint32_t    frames_to_capture;
} sw_context;

static char sw__dbghelp_hintpath[SW_MAX_NAME_LEN];

#endif // SW_IMPL
