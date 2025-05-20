#pragma once
#include <Windows.h>
#include <stdio.h>

// A structure representing each entry in the error stack trace
typedef struct {
    char* FunctionName; // The name of the function where the error occurred, in ASCII format
    int ErrorCode;      // The error code associated with the function
} StackEntry;

/*
 * The Error structure holds a dynamic array of stack trace entries,
 * a wide-string description, the main error code, an optional last error code,
 * and an initialization flag.
 */
typedef struct {
    StackEntry* StackTrace;   // Dynamically allocated array of stack entries
    size_t StackCount;        // Number of valid entries in the stack
    size_t StackCapacity;     // Allocated capacity for stackTrace
    wchar_t* Description;     // Error description (wide string)
    int ErrorCode;            // Main error code
    DWORD LastErrorCode;      // Optional last error code (0 if unused)
    BOOL ContainsError;       // Flag indicating that if error object actually contains an error
    BOOL _bAllocated;		  // Flag indicating that the error object was allocated on the heap
    BOOL _bInitialized;       // Flag indicating that the error object is properly initialized

    void (*AddFunctionToStack)(void* pvErr, const char* FunctionName, int ErrorCode);
    wchar_t* (*Format)(void* pvErr);
} Error;

/* Helper: count digits in an integer (including a '-' sign if needed) */
static int count_digits(int n);

/* Helper: count digits in an unsigned number (for LastErrorCode) */
static int count_udigits(DWORD n);

// Adds a new function call to the error’s stack trace.
void Error_AddNewFunctionToStack(void* pvErr, const char* FunctionName, int ErrorCode);

// Formats the error information (stack trace, description, error codes) into a wide string. The returned buffer is allocated on the heap and must be freed by the caller.
// Awful code, Unreadable 102%.
wchar_t* Error_Format(void* pvErr);

Error NewNoError();

// Creates an Error object on the stack. The returned Error will have its first stack entry added.
// Free after use with Error_Free.
Error NewError(const char* FunctionName, int ErrorCode, const wchar_t* Description, DWORD LastErrorCode);

// Same as NewError but the object will be fully on the heap. Free after use with Error_Free.
Error* AllocateError(const char* FunctionName, int ErrorCode, const wchar_t* Description, DWORD LastErrorCode);

// frees internal allocations held by the error object.
void Error_Free(Error* err);