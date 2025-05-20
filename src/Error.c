#include "Error.h"

/* Helper: count digits in an integer (including a '-' sign if needed) */
static int count_digits(int n) {
    int count = 0;
    if (n == 0) return 1;
    if (n < 0) {
        count++; // account for '-' sign
        n = -n;
    }
    while (n > 0) {
        count++;
        n /= 10;
    }
    return count;
}

/* Helper: count digits in an unsigned number (for LastErrorCode) */
static int count_udigits(DWORD n) {
    int count = 0;
    if (n == 0) return 1;
    while (n > 0) {
        count++;
        n /= 10;
    }
    return count;
}

// Adds a new function call to the error’s stack trace.
void Error_AddNewFunctionToStack(void* pvErr, const char* FunctionName, int ErrorCode) {
    Error* err = (Error*)pvErr;
    if (!err) return;

    /* grow the dynamic array if needed */
    if (err->StackCount == err->StackCapacity) {
        size_t NewCapacity = (err->StackCapacity == 0) ? 4 : err->StackCapacity * 2;
        StackEntry* NewStack = (StackEntry*)realloc(err->StackTrace, NewCapacity * sizeof(StackEntry));
        if (!NewStack) {
            return;
        }
        err->StackTrace = NewStack;
        err->StackCapacity = NewCapacity;
    }

    /* allocate and copy function name */
    size_t len = strlen(FunctionName) + 1;
    char* copy = (char*)malloc(len);
    if (copy) strcpy_s(copy, len, FunctionName);
    err->StackTrace[err->StackCount].FunctionName = copy;
    err->StackTrace[err->StackCount].ErrorCode = ErrorCode;
    err->StackCount++;
}

// Formats the error information (stack trace, description, error codes) into a wide string. The returned buffer is allocated on the heap and must be freed by the caller.
// Awful code, Unreadable 102%.
wchar_t* Error_Format(void* pvErr) {
    Error* err = (Error*)pvErr;
    if (!err || !err->_bInitialized) {
        wchar_t* empty = (wchar_t*)malloc(sizeof(wchar_t));
        if (empty)
            empty[0] = L'\0';
        return empty;
    }

    /* First, calculate how many wide characters we will need.
       For each stack entry we need: length of function name (each ASCII char maps to one wide char)
       plus extra characters for the formatting "[", "]", error code digits and " -> ".
       Then we add the ": " separator, the description, and optionally ";LEC=" with LastErrorCode. */
    size_t szTotalLength = 0;
    for (size_t i = 0; i < err->StackCount; i++) {
        size_t szFnLen = strlen(err->StackTrace[i].FunctionName);
        int CodeDigits = count_digits(err->StackTrace[i].ErrorCode);
        szTotalLength += szFnLen + CodeDigits + 6;  // "[", "]", " -> " (6 extra characters)
    }
    if (err->StackCount > 0) szTotalLength -= 4;  // remove trailing " -> " from the last entry

    szTotalLength += 2;  // for ": "
    if (err->Description) szTotalLength += wcslen(err->Description);

    if (err->LastErrorCode != 0) {
        szTotalLength += 5; // for ";LEC="
        szTotalLength += count_udigits(err->LastErrorCode);
    }
    szTotalLength += 1; // null terminator

    wchar_t* OutBuffer = (wchar_t*)malloc(szTotalLength * sizeof(wchar_t));
    if (!OutBuffer)
        return NULL;
    OutBuffer[0] = L'\0';
    size_t Offset = 0;

    /* Process the stack trace in reverse order (most recent call first) */
    for (size_t i = 0; i < err->StackCount; i++) {
        size_t idx = err->StackCount - 1 - i;
        /* Convert ASCII function name to wide string using safe function */
        wchar_t* wFuncName = (wchar_t*)malloc((strlen(err->StackTrace[idx].FunctionName) + 1) * sizeof(wchar_t));
        if (wFuncName) {
            size_t szConvertedStringSize = 0;
            mbstowcs_s(&szConvertedStringSize, wFuncName, strlen(err->StackTrace[idx].FunctionName) + 1, err->StackTrace[idx].FunctionName, _TRUNCATE);
        }
        else wFuncName = (wchar_t*)L"";

        int written = swprintf_s(OutBuffer + Offset, szTotalLength - Offset, L"%s[%d] -> ", wFuncName, err->StackTrace[idx].ErrorCode);
        if (written < 0) {
            free(wFuncName);
            free(OutBuffer);
            return NULL;
        }
        Offset += written;
        free(wFuncName);
    }
    if (err->StackCount > 0 && Offset >= 4) {
        Offset -= 4;  // Remove the last " -> "
        OutBuffer[Offset] = L'\0';
    }
    int Written = swprintf_s(OutBuffer + Offset, szTotalLength - Offset, L": %s", err->Description ? err->Description : L"");
    if (Written < 0) {
        free(OutBuffer);
        return NULL;
    }
    Offset += Written;
    if (err->LastErrorCode != 0) {
        Written = swprintf_s(OutBuffer + Offset, szTotalLength - Offset, L";LEC=%lu", err->LastErrorCode);
        if (Written < 0) {
            free(OutBuffer);
            return NULL;
        }
        Offset += Written;
    }

    return OutBuffer;
}

Error NewNoError() {
    Error err;

    err.ContainsError = FALSE;
    err.StackTrace = NULL;
    err.StackCount = 0;
    err.StackCapacity = 0;
    err.Description = NULL;
    err.ErrorCode = 0;
    err.LastErrorCode = 0;
    err._bInitialized = TRUE;
    err._bAllocated = FALSE;
    err.AddFunctionToStack = Error_AddNewFunctionToStack;
    err.Format = Error_Format;

    return err;
}

// Creates an Error object on the stack. The returned Error will have its first stack entry added.
// Free after use with Error_Free.
Error NewError(const char* FunctionName, int ErrorCode, const wchar_t* Description, DWORD LastErrorCode) {
    Error err;
    err.StackTrace = NULL;
    err.StackCount = 0;
    err.StackCapacity = 0;
    err.Description = Description ? _wcsdup(Description) : NULL;
    err.ErrorCode = ErrorCode;
    err.LastErrorCode = LastErrorCode;
    err._bInitialized = TRUE;
    err._bAllocated = FALSE;
    err.ContainsError = TRUE;

    err.AddFunctionToStack = Error_AddNewFunctionToStack;
    err.Format = Error_Format;

    err.AddFunctionToStack(&err, FunctionName, ErrorCode);
    return err;
}

// Same as NewError but the object will be fully on the heap. Free after use with Error_Free.
Error* AllocateError(const char* FunctionName, int ErrorCode, const wchar_t* Description, DWORD LastErrorCode) {
    Error* err = (Error*)malloc(sizeof(Error));
    if (err) {
        err->StackTrace = NULL;
        err->StackCount = 0;
        err->StackCapacity = 0;
        err->Description = Description ? _wcsdup(Description) : NULL;
        err->ErrorCode = ErrorCode;
        err->LastErrorCode = LastErrorCode;
        err->_bInitialized = TRUE;
        err->_bAllocated = TRUE;
        err->ContainsError = TRUE;

        err->AddFunctionToStack = Error_AddNewFunctionToStack;
        err->Format = Error_Format;

        err->AddFunctionToStack(err, FunctionName, ErrorCode);
    }
    return err;
}

// frees internal allocations held by the error object.
void Error_Free(Error* err) {
    if (!err) return;

    if (err->_bAllocated) {
        free(err);
        return;
    }

    /* Free each duplicated function name */
    for (size_t i = 0; i < err->StackCount; i++) free(err->StackTrace[i].FunctionName);

    free(err->StackTrace);
    free(err->Description);
}
