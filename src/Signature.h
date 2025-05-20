#pragma once
#include "Pdb.h"

Error GetFunctionSignatureFromPE(WCHAR* pePath, DWORD signatureLength, int functionRVA, BYTE** signatureBuffer);