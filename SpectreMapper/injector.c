#include <Windows.h>
#include <stdio.h>
#include "injector.h"
#include "debug.h"

void PerformRelocation(BYTE* buffer, PIMAGE_NT_HEADERS ntHeaders, LPVOID remoteBase) {
    DWORD_PTR delta = (DWORD_PTR)remoteBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) {
        DEBUG_PRINT("[+] No relocation needed.\n");
        return;
    }

    DEBUG_PRINT("[+] Relocating with Delta: 0x%p\n", (void*)delta);

    PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0 || relocDir->VirtualAddress == 0) {
        DEBUG_PRINT("[-] No Relocation Table found.\n");
        return;
    }

    PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(buffer + relocDir->VirtualAddress);

    // Processing Relocation Blocks
    while (relocBlock->VirtualAddress != 0) {
        DEBUG_PRINT("[DEBUG] Block VA: 0x%X, Size: %d\n", relocBlock->VirtualAddress, relocBlock->SizeOfBlock);

        if (relocBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

        DWORD entryCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relEntry = (WORD*)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entryCount; i++) {
            WORD type = relEntry[i] >> 12;
            WORD offset = relEntry[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD_PTR* patchAddr = (DWORD_PTR*)(buffer + relocBlock->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }
        relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock);
    }
    DEBUG_PRINT("[+] Relocation Completed.\n");
}

void ResolveImports(BYTE* buffer, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + importDir->VirtualAddress);

    while (importDesc->Name != 0) {
        char* libName = (char*)(buffer + importDesc->Name);
        DEBUG_PRINT("[DEBUG] Loading Library: %s\n", libName);

        HMODULE hLib = LoadLibraryA(libName);
        if (!hLib) {
            DEBUG_PRINT("[-] LoadLibraryA failed for %s: %d\n", libName, GetLastError());
            return;
        }

        // Resolve Thunks
        DWORD thunkOffset = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(buffer + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(buffer + thunkOffset);

        while (origThunk->u1.AddressOfData != 0) {
            DWORD_PTR funcAddr = 0;

            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                funcAddr = (DWORD_PTR)GetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(buffer + origThunk->u1.AddressOfData);
                funcAddr = (DWORD_PTR)GetProcAddress(hLib, importByName->Name);
                DEBUG_PRINT("[DEBUG]   -> Found Function: %s\n", importByName->Name);
            }

            if (!funcAddr) {
                DEBUG_PRINT("[-] GetProcAddress failed.\n");
                return;
            }

            thunk->u1.Function = funcAddr;
            thunk++;
            origThunk++;
        }
        importDesc++;
    }
    DEBUG_PRINT("[+] Imports Resolved.\n");
}