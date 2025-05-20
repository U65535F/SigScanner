#pragma once
#include "Pdb.h"

Error GetFunctionSignatureFromPE(LPCWSTR pePath, DWORD signatureLength, int functionRVA, BYTE** signatureBuffer);
Error FindUniqueSignature(LPCWSTR pePath, BYTE* signature, DWORD signatureLength, int functionRVA, BOOL* isUnique, BYTE** uniqueSignature, DWORD* uniqueSignatureLength);
