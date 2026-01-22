#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <tchar.h>
#include "injector.h"
#include "PE_parser.h"
#include "debug.h"

DWORD GetTargetPid(const char* procName) {
    DWORD pid = 0;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT("[-] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    else {
        DEBUG_PRINT("[-] Process32First failed: %d\n", GetLastError());
    }

    CloseHandle(hSnap);
    return pid;
}
void ManualMap(HANDLE hProc, BYTE* rawPeBuffer) {
    PIMAGE_NT_HEADERS ntHeaders = GetNtHeader(rawPeBuffer);
    DEBUG_PRINT("[+] Target ImageBase: 0x%p, Size: 0x%X\n", (void*)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage);

    LPVOID remoteImageBase = VirtualAllocEx(hProc, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImageBase) {
        DEBUG_PRINT("[-] VirtualAllocEx failed: %d\n", GetLastError());
        return;
    }
    DEBUG_PRINT("[+] Allocated Remote Base: 0x%p\n", remoteImageBase);

    BYTE* localImage = (BYTE*)VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    DEBUG_PRINT("[+] Copying Headers...\n");
    memcpy(localImage, rawPeBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    DEBUG_PRINT("[+] Copying Sections...\n");
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        memcpy(localImage + section[i].VirtualAddress, rawPeBuffer + section[i].PointerToRawData, section[i].SizeOfRawData);
    }

    DEBUG_PRINT("[+] Starting Relocation...\n");
    PerformRelocation(localImage, ntHeaders, remoteImageBase);
    
    DEBUG_PRINT("[+] Resolving Imports...\n");
    ResolveImports(localImage, ntHeaders);
    DEBUG_PRINT("[+] Imports Resolved.\n");

    DEBUG_PRINT("[+] Writing to Target Process...\n");
    if (!WriteProcessMemory(hProc, remoteImageBase, localImage, ntHeaders->OptionalHeader.SizeOfImage, NULL)) {
        DEBUG_PRINT("[-] WriteProcessMemory failed: %d\n", GetLastError());
        return;
    }

    LPVOID entryPoint = (LPVOID)((BYTE*)remoteImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    DEBUG_PRINT("[+] Remote EntryPoint: 0x%p\n", entryPoint);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (!hThread) {
        DEBUG_PRINT("[-] CreateRemoteThread failed: %d\n", GetLastError());
    } else {
        DEBUG_PRINT("[+] Thread Created. Check MessageBox.\n");
        WaitForSingleObject(hThread, 2000); 
        CloseHandle(hThread);
    }

    VirtualFree(localImage, 0, MEM_RELEASE);
}
int main(int argc, char* argv[]) {
    if (argc < 3) {
        DEBUG_PRINT("Usage: %s <Target.exe> <Payload.exe>\n", argv[0]);
        return -1;
    }

    DWORD fileSize = 0;
    BYTE* peBuffer = _ReadFile(argv[2], &fileSize);
    DWORD pid = GetTargetPid(argv[1]);
    DEBUG_PRINT("PID of %s: %d\n", argv[1], pid);  
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc) {
        ManualMap(hProc, peBuffer); 
        CloseHandle(hProc);
    }

    free(peBuffer);
    return 0;
}