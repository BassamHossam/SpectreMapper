#include <Windows.h>
#include <stdio.h>
#include "PE_parser.h"
#include "debug.h"

BYTE* _ReadFile(IN const char* Path, OUT DWORD* outFileSize) {
	FILE* file = fopen(Path, "rb");
	if (!file) {
		DEBUG_PRINT("[-] Failed to Open File\n");
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	*outFileSize= ftell(file);
	fseek(file, 0, SEEK_SET);

	BYTE* buffer = (BYTE*)malloc(*outFileSize);
	fread(buffer, 1, *outFileSize, file);
	return buffer;
}
PIMAGE_NT_HEADERS GetNtHeader(BYTE* FileBuffer) {
	PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)FileBuffer;
	if (DOSheader->e_magic != IMAGE_DOS_SIGNATURE) {
		DEBUG_PRINT("[-] Invalid PE File\n");
		return NULL;
	}
	return (PIMAGE_NT_HEADERS)(FileBuffer + DOSheader->e_lfanew);
}

