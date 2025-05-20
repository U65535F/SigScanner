#include "Signature.h"

wchar_t* GetFolderPathFromFileName(const wchar_t* fullPath) {
    const wchar_t* lastSlash = wcsrchr(fullPath, L'\\');
    size_t folderLength;
    wchar_t* folderPath;

    if (!lastSlash) {
        wchar_t exePath[MAX_PATH*3];
        DWORD length = GetModuleFileNameW(NULL, exePath, MAX_PATH*3);
        if (length == 0 || length == MAX_PATH*3) return NULL;

        wchar_t* exeDirectory = wcsrchr(exePath, L'\\');
        if (!exeDirectory) return NULL;

        folderLength = exeDirectory - exePath + 1;
        folderPath = (wchar_t*)malloc((folderLength + 1) * sizeof(wchar_t));
        if (!folderPath) return NULL;

        wcsncpy_s(folderPath, folderLength + 1, exePath, folderLength);
        folderPath[folderLength] = L'\0';
        return folderPath;
    }

    folderLength = lastSlash - fullPath + 1;
    folderPath = (wchar_t*)malloc((folderLength + 1) * sizeof(wchar_t));
    if (!folderPath) return NULL;

    wcsncpy_s(folderPath, folderLength + 1, fullPath, folderLength);
    folderPath[folderLength] = L'\0';
    return folderPath;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 4) {
        wprintf(L"Usage: %s <pePath> <functionName> <sigLength>\n", argv[0]);
        return 1;
    }

    WCHAR* pePath = argv[1];
    WCHAR* funcName = argv[2];
    DWORD sigLength = _wtoi(argv[3]);
    wprintf(L"[+] Supplied PE path: %s\n", pePath);
    wprintf(L"[+] Supplied function name: %s\n", funcName);
    wprintf(L"[+] Signature length: %lu\n", sigLength);
    wprintf(L"[+] Extracting PE information\n");
    struct PDBLookupContext ctx;
    Error e = GetPEInfo(pePath, &ctx);
    if (e.ContainsError) {
        fwprintf(stderr, L"[-] Get PE info failed: %s\n", e.Format(&e));
        return 1;
    }

    wprintf(L"[+] PDB file name in the PE is: %S\n", ctx.pdbInfo.pdbName);
    WCHAR* folderPath = GetFolderPathFromFileName(pePath);
    if (!folderPath) {
        fwprintf(stderr, L"[-] Failed to get folder path: %lu\n", GetLastError());
        return 1;
    }

    size_t fullPdbPathBufferLength = wcslen(folderPath) + strlen(ctx.pdbInfo.pdbName) + 1;
    WCHAR* fullPdbPath = (WCHAR*)malloc(fullPdbPathBufferLength * sizeof(WCHAR));
    if (!fullPdbPath) {
        fwprintf(stderr, L"[-] malloc failed, out of memory\n");
        return 1;
    }
    swprintf_s(fullPdbPath, fullPdbPathBufferLength, L"%s%S", folderPath, ctx.pdbInfo.pdbName);

    wprintf(L"[+] Downloading PDB file to %s\n", fullPdbPath);
    e = DownloadPDB(&ctx, fullPdbPath);
    if (e.ContainsError) {
        fwprintf(stderr, L"[-] PDB download failed: %s\n", e.Format(&e));
        return 1;
    }

    wprintf(L"[+] Initializing DbgHelp\n");
    e = InitializePDBLookup(fullPdbPath, &ctx);
    if (e.ContainsError) {
        fwprintf(stderr, L"[-] InitializePDBLookup failed: %s\n", e.Format(&e));
        free(ctx.pdbInfo.pdbName);
        return 1;
    }

    wprintf(L"[+] Retrieving function relative virtual address\n");
    int funcRVA = GetFunctionRVA(funcName, &ctx);
    if (funcRVA < 0) {
        fwprintf(stderr, L"[-] Symbol '%s' not found in PDB\n", funcName);
        CleanupPDBLookupCtx(&ctx);
        return 1;
    }
    wprintf(L"Function '%s' RVA = 0x%08X\n", funcName, funcRVA);

    wprintf(L"[+] Fetching function signature\n");
    BYTE* sigBuffer;
    e = GetFunctionSignatureFromPE(pePath, sigLength, funcRVA, &sigBuffer);
    if (e.ContainsError) {
        fwprintf(stderr, L"[-] Failed to read %d-byte signature at RVA 0x%08X from %s\n", sigLength, funcRVA, pePath);
        fwprintf(stderr, L"  (%s)\n", e.Format(&e));
        CleanupPDBLookupCtx(&ctx);
        return 1;
    }

    wprintf(L"Signature (%d bytes):\n", sigLength);
    for (DWORD i = 0; i < sigLength; i++) {
        wprintf(L"0x%02X", sigBuffer[i]);
        if ((i + 1) < sigLength)
            wprintf(L", ");
    }
    wprintf(L"\n");
    free(sigBuffer);

    return 0;
}
