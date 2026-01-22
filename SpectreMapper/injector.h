#pragma once

void PerformRelocation(BYTE* buffer, PIMAGE_NT_HEADERS ntHeaders, LPVOID remoteBase);
void ResolveImports(BYTE* buffer, PIMAGE_NT_HEADERS ntHeaders);