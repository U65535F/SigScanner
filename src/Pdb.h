#pragma once
#include <Windows.h>
#include <WinHTTP.h>
#include <DbgHelp.h>
#include "Error.h"
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "WinHTTP.lib")

#define PDB_BASE (DWORD64)0x10000000

typedef struct PdbInfo {
    GUID guid;
    DWORD age;
    CHAR* pdbName;
} PdbInfo;

typedef struct PDBLookupContext {
    struct PdbInfo pdbInfo;
    HANDLE hProcess;
    HANDLE hPdbFile;
} PdbLookupContext;

Error GetPEInfo(LPCWSTR filePath, struct PDBLookupContext* pPdbLookupCtx);
Error DownloadPDB(struct PDBLookupContext* pPdbLookupCtx, LPCWSTR outputPath);
Error InitializePDBLookup(LPCWSTR pdbPath, struct PDBLookupContext* pPdbLookupCtx);
void CleanupPDBLookupCtx(struct PDBLookupContext* pPdbLookupCtx);
int GetFunctionRVA(LPCWSTR symbolName, struct PDBLookupContext* pPdbLookupCtx);
ULONG GetAttributeOffset(LPCWSTR structName, LPCWSTR propertyName, struct PDBLookupContext* pPdbLookupCtx);
ULONG GetStructSize(LPCWSTR StructName, struct PDBLookupContext* pPdbLookupCtx);
DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER sections, WORD numSections);