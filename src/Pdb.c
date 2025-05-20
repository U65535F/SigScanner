#include "Pdb.h"

Error GetPEInfo(LPCWSTR filePath, struct PDBLookupContext* pPdbLookupCtx)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NewError(__FUNCTION__, -1, L"CreateFileW failed", GetLastError());

    Error e = NewNoError();
    do {
        DWORD bytesRead;
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS64 ntHeader;
        IMAGE_SECTION_HEADER sectionHeader;

        if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            e = NewError(__FUNCTION__, -2, L"ReadFile failed", GetLastError());
            break;
        }

        if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            e = NewError(__FUNCTION__, -3, L"SetFilePointer failed", GetLastError());
            break;
        }

        if (!ReadFile(hFile, &ntHeader, sizeof(ntHeader), &bytesRead, NULL) || bytesRead != sizeof(ntHeader) || ntHeader.Signature != IMAGE_NT_SIGNATURE) {
            e = NewError(__FUNCTION__, -4, L"ReadFile failed", GetLastError());
            break;
        }

        DWORD debugSectionRVA = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DWORD nSections = ntHeader.FileHeader.NumberOfSections;

        for (DWORD i = 0; i < nSections; i++)
        {
            if (!ReadFile(hFile, &sectionHeader, sizeof(sectionHeader), &bytesRead, NULL) || bytesRead != sizeof(sectionHeader)) {
                e = NewError(__FUNCTION__, -5, L"ReadFile failed", GetLastError());
                break;
            }

            DWORD vaStart = sectionHeader.VirtualAddress;
            DWORD vaEnd = vaStart + sectionHeader.Misc.VirtualSize;
            if (debugSectionRVA >= vaStart && debugSectionRVA < vaEnd)
            {
                DWORD offset = (debugSectionRVA - vaStart) + sectionHeader.PointerToRawData;
                if (SetFilePointer(hFile, offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                    e = NewError(__FUNCTION__, -6, L"SetFilePointer failed", GetLastError());
                    break;
                }
                IMAGE_DEBUG_DIRECTORY debugDirectory;
                if (!ReadFile(hFile, &debugDirectory, sizeof(debugDirectory), &bytesRead, NULL) || bytesRead != sizeof(debugDirectory)) {
                    e = NewError(__FUNCTION__, -7, L"ReadFile failed", GetLastError());
                    break;
                }

                if (debugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW)
                {
                    if (SetFilePointer(hFile, debugDirectory.PointerToRawData, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                        e = NewError(__FUNCTION__, -8, L"SetFilePointer failed", GetLastError());
                        break;
                    }
                    DWORD signature;
                    // 'RSDS' little‑endian
                    if (!ReadFile(hFile, &signature, sizeof(signature), &bytesRead, NULL) || bytesRead != sizeof(signature) || signature != 'SDSR') {
                        e = NewError(__FUNCTION__, -9, L"ReadFile failed", GetLastError());
                        break;
                    }
                    if (!ReadFile(hFile, &pPdbLookupCtx->pdbInfo.guid, sizeof(GUID), &bytesRead, NULL) || bytesRead != sizeof(GUID)) {
                        e = NewError(__FUNCTION__, -10, L"ReadFile failed", GetLastError());
                        break;
                    }
                    if (!ReadFile(hFile, &pPdbLookupCtx->pdbInfo.age, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD)) {
                        e = NewError(__FUNCTION__, -11, L"ReadFile failed", GetLastError());
                        break;
                    }

                    CHAR* nameBuffer = (CHAR*)malloc(MAX_PATH * 3);
                    if (!nameBuffer) {
                        e = NewError(__FUNCTION__, -12, L"malloc failed", GetLastError());
                        break;
                    }
                    DWORD idx = 0;
                    CHAR character;
                    while (idx + 1 < (MAX_PATH * 3) && ReadFile(hFile, &character, 1, &bytesRead, NULL) && bytesRead == 1 && character != '\0')
                        nameBuffer[idx++] = character;
                    nameBuffer[idx] = '\0';
                    pPdbLookupCtx->pdbInfo.pdbName = nameBuffer;
                }
                break;
            }
        }
    } while (FALSE);

    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return e;
}

Error DownloadPDB(struct PDBLookupContext* pPdbLookupCtx, LPCWSTR outputPath) {
    LPCWSTR UserAgent = L"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
    // guid format: {Data1}{Data2}{Data3}{Data4}{age}
    WCHAR guidString[64];
    swprintf_s(
        guidString, _countof(guidString),
        L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        pPdbLookupCtx->pdbInfo.guid.Data1, pPdbLookupCtx->pdbInfo.guid.Data2, pPdbLookupCtx->pdbInfo.guid.Data3,
        pPdbLookupCtx->pdbInfo.guid.Data4[0], pPdbLookupCtx->pdbInfo.guid.Data4[1],
        pPdbLookupCtx->pdbInfo.guid.Data4[2], pPdbLookupCtx->pdbInfo.guid.Data4[3],
        pPdbLookupCtx->pdbInfo.guid.Data4[4], pPdbLookupCtx->pdbInfo.guid.Data4[5],
        pPdbLookupCtx->pdbInfo.guid.Data4[6], pPdbLookupCtx->pdbInfo.guid.Data4[7],
        pPdbLookupCtx->pdbInfo.age);

    // format: /download/symbols/<pdbName>/<guidStr>/<pdbName>
    WCHAR url[MAX_PATH * 2 + 64];
    swprintf_s(url, _countof(url), L"/download/symbols/%S/%s/%S", pPdbLookupCtx->pdbInfo.pdbName, guidString, pPdbLookupCtx->pdbInfo.pdbName);
    Error e = NewNoError();

    HINTERNET hWinHttp = NULL, hConnect = NULL, hRequest = NULL;
    HANDLE hOut = INVALID_HANDLE_VALUE;
    do {
        hWinHttp = WinHttpOpen(UserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hWinHttp) {
            e = NewError(__FUNCTION__, -1, L"WinHttpOpen failed", GetLastError());
            break;
        }

        hConnect = WinHttpConnect(hWinHttp, L"msdl.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            e = NewError(__FUNCTION__, -2, L"WinHttpConnect failed", GetLastError());
            break;
        }

        hRequest = WinHttpOpenRequest(hConnect, L"GET", url, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            e = NewError(__FUNCTION__, -3, L"WinHttpOpenRequest failed", GetLastError());
            break;
        }

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            e = NewError(__FUNCTION__, -4, L"WinHttpSendRequest failed", GetLastError());
            break;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            e = NewError(__FUNCTION__, -5, L"WinHttpReceiveResponse failed", GetLastError());
            break;
        }

        hOut = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut == INVALID_HANDLE_VALUE) {
            e = NewError(__FUNCTION__, -6, L"CreateFileW failed", GetLastError());
            break;
        }

        BYTE buffer[1 << 16]; // 64kb
        DWORD downloadedSize = 0, writtenSize = 0;
        while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &downloadedSize) && downloadedSize > 0)
        {
            if (!WriteFile(hOut, buffer, downloadedSize, &writtenSize, NULL) || writtenSize != downloadedSize)
            {
                e = NewError(__FUNCTION__, -7, L"WriteFile failed", GetLastError());
                break;
            }
        }
    } while (FALSE);

    if (hOut) CloseHandle(hOut);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hWinHttp) WinHttpCloseHandle(hWinHttp);
    return e;
}

Error InitializePDBLookup(LPCWSTR pdbPath, struct PDBLookupContext* pPdbLookupCtx) {
    HANDLE hPdbFile = CreateFileW(pdbPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hPdbFile == INVALID_HANDLE_VALUE)
        return NewError(__FUNCTION__, -1, L"CreateFileW failed", GetLastError());

    DWORD pdbSize = GetFileSize(hPdbFile, NULL);
    if (pdbSize <= 0) {
        return NewError(__FUNCTION__, -2, L"GetFileSize failed", GetLastError());
    }
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!hProcess) {
        CloseHandle(hPdbFile);
        return NewError(__FUNCTION__, -3, L"OpenProcess failed", GetLastError());
    }

    if (!SymInitializeW(hProcess, pdbPath, FALSE)) {
        CloseHandle(hProcess);
        CloseHandle(hPdbFile);
        return NewError(__FUNCTION__, -4, L"SymInitializeW failed", GetLastError());
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING);
    DWORD64 symbolTable = SymLoadModuleExW(hProcess, NULL, pdbPath, NULL, PDB_BASE, pdbSize, NULL, 0);
    if (!symbolTable) {
        SymCleanup(hProcess);
        CloseHandle(hProcess);
        CloseHandle(hPdbFile);
        return NewError(__FUNCTION__, -5, L"SymLoadModuleExW failed", GetLastError());
    }

    pPdbLookupCtx->hPdbFile = hPdbFile;
    pPdbLookupCtx->hProcess = hProcess;
    return NewNoError();
}

void CleanupPDBLookupCtx(struct PDBLookupContext* pPdbLookupCtx) {
    SymUnloadModule64(pPdbLookupCtx->hProcess, PDB_BASE);
    SymCleanup(pPdbLookupCtx->hProcess);
    CloseHandle(pPdbLookupCtx->hProcess);
    CloseHandle(pPdbLookupCtx->hPdbFile);
    free(pPdbLookupCtx->pdbInfo.pdbName);
    ZeroMemory(pPdbLookupCtx, sizeof(struct PDBLookupContext));
}

int GetFunctionRVA(LPCWSTR symbolName, struct PDBLookupContext* pPdbLookupCtx) {
    SYMBOL_INFOW symbolInfo = { 0 };
    symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFOW);
    if (!SymFromNameW(pPdbLookupCtx->hProcess, symbolName, &symbolInfo)) return -1;
    return (int)(symbolInfo.Address - symbolInfo.ModBase);
}

ULONG GetAttributeOffset(LPCWSTR structName, LPCWSTR propertyName, struct PDBLookupContext* pPdbLookupCtx)
{
    ULONG symbolInfoSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
    SYMBOL_INFOW* symbolInfo = (SYMBOL_INFOW*)malloc(symbolInfoSize);
    if (!symbolInfo)
        return 0;

    ZeroMemory(symbolInfo, symbolInfoSize);
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = MAX_SYM_NAME;
    if (!SymGetTypeFromNameW(pPdbLookupCtx->hProcess, PDB_BASE, structName, symbolInfo)) {
        free(symbolInfo);
        return 0;
    }
    
    TI_FINDCHILDREN_PARAMS tempFp = { 0 };
    if (!SymGetTypeInfo(pPdbLookupCtx->hProcess, PDB_BASE, symbolInfo->TypeIndex, TI_GET_CHILDRENCOUNT, &tempFp)) {
        free(symbolInfo);
        return 0;
    }

    ULONG childParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + tempFp.Count * sizeof(ULONG);
    TI_FINDCHILDREN_PARAMS* childParams = (TI_FINDCHILDREN_PARAMS*)malloc(childParamsSize);
    if (childParams == NULL)
    {
        free(symbolInfo);
        return 0;
    }
    ZeroMemory(childParams, childParamsSize);
    childParams->Count = tempFp.Count;
    childParams->Start = tempFp.Start;
    do {
        if (!SymGetTypeInfo(pPdbLookupCtx->hProcess, PDB_BASE, symbolInfo->TypeIndex, TI_FINDCHILDREN, childParams))
            break;
        for (ULONG i = childParams->Start; i < childParams->Count; i++)
        {
            WCHAR* pSymName = NULL;
            ULONG Offset = 0;
            if (!SymGetTypeInfo(pPdbLookupCtx->hProcess, PDB_BASE, childParams->ChildId[i], TI_GET_OFFSET, &Offset))
                break;
            if (!SymGetTypeInfo(pPdbLookupCtx->hProcess, PDB_BASE, childParams->ChildId[i], TI_GET_SYMNAME, &pSymName))
                break;
            if (pSymName)
            {
                if (wcscmp(pSymName, propertyName) == 0)
                {
                    LocalFree(pSymName);
                    free(childParams);
                    free(symbolInfo);
                    return Offset;
                }
            }
        }
    } while (FALSE);
    free(childParams);
    free(symbolInfo);
    return 0;
}

ULONG GetStructSize(LPCWSTR StructName, struct PDBLookupContext* pPdbLookupCtx)
{
    ULONG symbolInfoSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
    SYMBOL_INFOW* symbolInfo = (SYMBOL_INFOW*)malloc(symbolInfoSize);
    if (!symbolInfo)
        return 0;
    ZeroMemory(symbolInfo, symbolInfoSize);
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = MAX_SYM_NAME;
    if (!SymGetTypeFromNameW(pPdbLookupCtx->hProcess, PDB_BASE, StructName, symbolInfo))
        return 0;

    return symbolInfo->Size;
}

DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER sections, WORD numSections)
{
    for (WORD i = 0; i < numSections; i++) {
        DWORD vaStart = sections[i].VirtualAddress;
        DWORD vaEnd = vaStart + sections[i].Misc.VirtualSize;
        if (rva >= vaStart && rva < vaEnd)
            return (rva - vaStart) + sections[i].PointerToRawData;
    }

    return 0;
}
