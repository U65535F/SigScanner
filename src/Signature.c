#include "Signature.h"

Error GetFunctionSignatureFromPE(WCHAR* pePath, DWORD signatureLength, int functionRVA, BYTE** signatureBuffer) {
    HANDLE hFile = CreateFileW(pePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NewError(__FUNCTION__, -1, L"CreateFileW failed", GetLastError());

    Error e = NewNoError();
    IMAGE_SECTION_HEADER* sectionHeader = NULL;
    BYTE* buffer = NULL;
    do {
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            e = NewError(__FUNCTION__, -2, L"ReadFile failed", GetLastError());
            break;
        }

        if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            e = NewError(__FUNCTION__, -2, L"ReadFile failed", GetLastError());
            break;
        }

        IMAGE_NT_HEADERS64 ntHeaders;
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL) || bytesRead != sizeof(ntHeaders) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            e = NewError(__FUNCTION__, -3, L"ReadFile failed", GetLastError());
            break;
        }

        WORD nSections = ntHeaders.FileHeader.NumberOfSections;
        sectionHeader = (IMAGE_SECTION_HEADER*)malloc(nSections * sizeof(IMAGE_SECTION_HEADER));
        if (!sectionHeader) {
            e = NewError(__FUNCTION__, -4, L"malloc failed", GetLastError());
            break;
        }

        for (WORD i = 0; i < nSections; i++) {
            if (!ReadFile(hFile, &sectionHeader[i], sizeof(sectionHeader[i]), &bytesRead, NULL) || bytesRead != sizeof(sectionHeader[i])) {
                e = NewError(__FUNCTION__, -5, L"ReadFile failed", GetLastError());
                break;
            }
        }

        DWORD fileOffset = RvaToOffset((DWORD)functionRVA, sectionHeader, nSections);
        free(sectionHeader);
        sectionHeader = NULL;

        if (fileOffset == 0) {
            e = NewError(__FUNCTION__, -6, L"RvaToOffset failed", GetLastError());
            break;
        }

        if (SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            e = NewError(__FUNCTION__, -7, L"SetFilePointer failed", GetLastError());
            break;
        }

        buffer = (BYTE*)malloc(signatureLength);
        if (!buffer) {
            e = NewError(__FUNCTION__, -8, L"malloc failed", GetLastError());
            break;
        }

        if (!ReadFile(hFile, buffer, signatureLength, &bytesRead, NULL) || (int)bytesRead != signatureLength) {
            free(buffer);
            buffer = NULL;
            e = NewError(__FUNCTION__, -9, L"ReadFile failed", GetLastError());
            break;
        }
    } while (FALSE);

    if (sectionHeader) free(sectionHeader);
    if (hFile) CloseHandle(hFile);
    if (buffer) *signatureBuffer = buffer;
    return e;
}