//Execute shellcode.bin to test it

#include <windows.h>

LPVOID __MEMCPY__(
	__in LPVOID lpDst,
	__in LPVOID lpSrc,
	__in DWORD dwCount)
{
	LPBYTE s = (LPBYTE)lpSrc;
	LPBYTE d = (LPBYTE)lpDst;
	while (dwCount--)
		*d++ = *s++;
	return lpDst;
}
char* ReadBinaryFile(char* FileName, DWORD& FileSize) {

	DWORD NumOfBytesRead;
	HANDLE FileHandle = CreateFileA((LPCSTR)FileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	FileSize = GetFileSize(FileHandle, 0);
	//Allocate memory , FileData is a pointer to that memory we just got
	char* FileData = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize);
	ReadFile(FileHandle, FileData, FileSize, &NumOfBytesRead, 0);

	if (FileData) {
		CloseHandle(FileHandle);
		return FileData;
	}
	return NULL;

}


int main(int argc, char* argv[])
{
#ifdef _WIN64
	char* szFilePath = (char*)"shellcode-x64.bin";
#else
	char* szFilePath = (char*)"shellcode.bin";
#endif
	
	
	//Read the .bin shellcode
	DWORD size;
	char* BinData = ReadBinaryFile(szFilePath, size);

	//Copy the buffer in memory to execute it
	void* sc = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (sc == NULL)
		return 0;
	__MEMCPY__(sc, BinData, size);
	(*(int(*)()) sc)();
	return 0;
}
