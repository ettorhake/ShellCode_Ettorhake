//Generate shellcode.bin of simple MessageBoxA
#include <windows.h>

#pragma optimize( "", off )
void shell_code();
HANDLE GetKernel32Handle();
BOOL __ISUPPER__(__in CHAR c);
CHAR __TOLOWER__(__in CHAR c);
UINT __STRLEN__(__in LPSTR lpStr1);
UINT __STRLENW__(__in LPWSTR lpStr1);
LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
INT __STRCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
INT __STRNCMPIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen);
LPVOID __MEMCPY__(__in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount);

typedef FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryAAPI)(LPCSTR lpLibFileName);
typedef int(WINAPI* MessageBoxAAPI) (HWND   hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT   uType);

void shell_code() {

	//Main Part of the ShellCode (Simple MessageBoxA)
	LoadLibraryAAPI	loadlibraryaapi = 0;
	GetProcAddressAPI getprocaddressapi = 0;
	MessageBoxAAPI messageboxaapi = 0;

	char struser32[] = { 'u', 's', 'e', 'r', '3','2', '.', 'd', 'l', 'l', 0 };
	char MeassageboxA_api[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };

	HANDLE hKernel32 = GetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE) {
		return;
	}

	LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);
	CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0 };
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };
	CHAR msg[] = { 'H','e','l','l','o',' ','A','x','0','n','e','s',' ','!', 0x0 };
	CHAR caption[] = { 'F','r','o','m',' ','E','t','t','o','r','h','a','k','e', 0x0 };

	for (UINT i = 0; i < pExportDir->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);
		if (!__STRCMPI__(pFuncName, strGetProcAddress)) {
			getprocaddressapi = (GetProcAddressAPI)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		else if (!__STRCMPI__(pFuncName, strLoadLibraryA)) {
			loadlibraryaapi = (LoadLibraryAAPI)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		if (getprocaddressapi != nullptr && loadlibraryaapi != nullptr) {
			messageboxaapi = (MessageBoxAAPI)getprocaddressapi(loadlibraryaapi(struser32), MeassageboxA_api);
			messageboxaapi(NULL, msg, caption, MB_SETFOREGROUND);
			return;
		}
	}
}

inline BOOL __ISUPPER__(__in CHAR c) {
	return ('A' <= c) && (c <= 'Z');
};
inline CHAR __TOLOWER__(__in CHAR c) {
	return __ISUPPER__(c) ? c - 'A' + 'a' : c;
};

UINT __STRLEN__(__in LPSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != 0x0)
		i++;
	return i;
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != L'\0')
		i++;
	return i;
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;
	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);
	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRNCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);
	return v;
}

LPSTR __STRCAT__(
	__in LPSTR	strDest,
	__in LPSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = strSource;
	while (*d) d++;
	do { *d++ = *s++; } while (*s);
	*d = 0x0;
	return strDest;
}

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
//import from Winternel.h
typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr; //import
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters; //import
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine; //import
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;  // Windows 2000 only
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#define CONTAINING_RECORD(address, type, field) ((type *)( (PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))


HANDLE GetKernel32Handle() {
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
	PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;
	WCHAR strDllName[MAX_PATH];
	WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };

	while (pListEntry != pListHead) {
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); //import
		if (pModEntry->FullDllName.Length) {
			DWORD dwLen = pModEntry->FullDllName.Length;
			__MEMCPY__(strDllName, pModEntry->FullDllName.Buffer, dwLen);
			strDllName[dwLen / sizeof(WCHAR)] = L'\0';
			if (__STRSTRIW__(strDllName, strKernel32)) {
				hKernel32 = pModEntry->DllBase;
				break;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return hKernel32;
}
void END_SHELLCODE(void) {}

int main()
{

	//This call is for debuging is executing your func 
	shell_code();

	//Write the shellcode output in .bin file 
	DWORD NumOfBytesWriten;
	DWORD ShellCodeSize = (int)END_SHELLCODE - (int)shell_code;
#ifdef _WIN64
	char* szFilePath = (char*)"shellcode-x64.bin";
#else
	char* szFilePath = (char*)"shellcode.bin";
#endif
	HANDLE FileHandle = CreateFileA(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(FileHandle, shell_code, ShellCodeSize, &NumOfBytesWriten, 0);
	CloseHandle(FileHandle);

}
