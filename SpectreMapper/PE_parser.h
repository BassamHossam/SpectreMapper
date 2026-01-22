#pragma once
BYTE* _ReadFile(IN const char* Path, OUT DWORD* outFileSize);
PIMAGE_NT_HEADERS GetNtHeader(BYTE* FileBuffer);