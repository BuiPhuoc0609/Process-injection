#include <windows.h>
#include <winnt.h>

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

void Start()
{
    char target[] = {
        'L','o','a','d','L','i','b','r','a','r','y','A',0
    };

    char dll[] = {
        'l','m','a','o','.','d','l','l',0
    };

    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* list = &peb->Ldr->InMemoryOrderModuleList;

    LIST_ENTRY* p = list->Flink;
    p = p->Flink;
    p = p->Flink;

    LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(p, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    BYTE* base = entry->DllBase;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    HMODULE(WINAPI * LoadLibraryA)(LPCSTR) = 0;

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* fn = (char*)(base + names[i]);

        int match = 1;
        for (int j = 0; target[j]; j++)
        {
            if (fn[j] != target[j]) {
                match = 0;
                break;
            }
        }

        if (match)
        {
            LoadLibraryA = (void*)(base + funcs[ords[i]]);
            HMODULE mod = LoadLibraryA(dll);

            if (mod)
            {
                BYTE* mbase = (BYTE*)mod;

                IMAGE_DOS_HEADER* mdos = (IMAGE_DOS_HEADER*)mbase;
                IMAGE_NT_HEADERS* mnt = (IMAGE_NT_HEADERS*)(mbase + mdos->e_lfanew);

                DLLMAIN DllMainFunc = (DLLMAIN)(mbase + mnt->OptionalHeader.AddressOfEntryPoint);
                DllMainFunc((HINSTANCE)mod, DLL_PROCESS_ATTACH, NULL);
            }

            break;
        }
    }
}