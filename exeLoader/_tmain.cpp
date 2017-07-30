#include <tchar.h>
#include <windows.h>
#include <ntstatus.h>
#include <string>

#include "SHA256.h"
#include "Decryption/AES/AES128.h"
#include "Decryption/AES/AES192.h"
#include "Decryption/AES/AES256.h"

#ifdef UNICODE
typedef std::wstring _tString;
#else
typedef std::string _tString;
#endif

enum EncryptType { AES128, AES192, AES256 };

HANDLE ConsoleInputHandle = INVALID_HANDLE_VALUE;
HANDLE ConsoleOutputHandle = INVALID_HANDLE_VALUE;

HMODULE h_ntdll = GetModuleHandle(TEXT("ntdll.dll"));
NTSTATUS(NTAPI *ZwUnmapViewOfSection)(HANDLE, PVOID) = (NTSTATUS(NTAPI *)(HANDLE, PVOID))GetProcAddress(h_ntdll, "ZwUnmapViewOfSection");

const ULONG protectAttributeTable[] = { PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };


BOOL GetConsoleIOHandle() {
	if (ConsoleInputHandle == INVALID_HANDLE_VALUE) {
		ConsoleInputHandle = GetStdHandle(STD_INPUT_HANDLE);
		if (ConsoleInputHandle == INVALID_HANDLE_VALUE) return FALSE;
	}

	if (ConsoleOutputHandle == INVALID_HANDLE_VALUE) {
		ConsoleOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		if (ConsoleInputHandle == INVALID_HANDLE_VALUE) return FALSE;
	}

	return TRUE;
}

_tString GetPassword() {
	_tString ret;

	if (GetConsoleIOHandle() == FALSE) return ret;

	DWORD OldConsoleMode = 0;
	if (GetConsoleMode(ConsoleInputHandle, &OldConsoleMode) == FALSE) return ret;
	if (SetConsoleMode(ConsoleInputHandle, OldConsoleMode & ~ENABLE_ECHO_INPUT & ~ENABLE_LINE_INPUT) == FALSE) return ret;

	DWORD count = 0;
	_TCHAR charGotten = 0;
	WriteConsole(ConsoleOutputHandle, TEXT("Password:>"), 10, &count, NULL);
	while (ReadConsole(ConsoleInputHandle, &charGotten, 1, &count, NULL) &&
		   count == 1 &&
		   charGotten != TEXT('\r') &&
		   charGotten != TEXT('\n')) {

		if (charGotten == TEXT('\b')) {
			if (ret.length() != 0) {
				ret.pop_back();
				WriteConsole(ConsoleOutputHandle, TEXT("\b \b"), 3, &count, NULL);
			}
		} else {
			WriteConsole(ConsoleOutputHandle, TEXT("*"), 1, &count, NULL);
			ret.push_back(charGotten);
		}
	}

	SetConsoleMode(ConsoleInputHandle, OldConsoleMode);
	WriteConsole(ConsoleOutputHandle, TEXT("\r\n"), 2, &count, NULL);

	return ret;
}

BOOL decryptData(const _tString& pass, BYTE* srcData, UINT64 DataLength ,EncryptType encryptType = EncryptType::AES256) {
	if (DataLength % 16 != 0) return FALSE;

	SHA256::SHA256HashResult passwordHash = SHA256::GetHash((const BYTE*)pass.c_str(), pass.length() * sizeof(_TCHAR));
	SHA256::ToBigEndian(passwordHash);

	void(*InverseCipherFunc)(BYTE*, const UINT32*) = nullptr;
	UINT32 ExpandedKey[60] = { 0 };
	switch (encryptType) {
		case EncryptType::AES128:
			Decryption::AES128::KeyExpansion((const BYTE*)&passwordHash, ExpandedKey);
			InverseCipherFunc = Decryption::AES128::InverseCipher;
			break;
		case EncryptType::AES192:
			Decryption::AES192::KeyExpansion((const BYTE*)&passwordHash, ExpandedKey);
			InverseCipherFunc = Decryption::AES192::InverseCipher;
			break;
		case EncryptType::AES256:
			Decryption::AES256::KeyExpansion((const BYTE*)&passwordHash, ExpandedKey);
			InverseCipherFunc = Decryption::AES256::InverseCipher;
			break;
		default:
			return FALSE;
	}

	auto rounds = DataLength >> 4;
	for (decltype(rounds) i = 0; i < rounds; ++i)
		InverseCipherFunc(srcData + (i << 4), ExpandedKey);
	LARGE_INTEGER sourceDataLength = { 0 };
	sourceDataLength.QuadPart = *(decltype(LARGE_INTEGER::QuadPart)*)(srcData + DataLength - 8);
	auto PaddedLength = (decltype(LARGE_INTEGER::QuadPart))DataLength - sourceDataLength.QuadPart;
	if (PaddedLength >= 8 && PaddedLength <= 23) {
		return TRUE;
	} else {
		return FALSE;
	}
}

int _tmain(int argc, _TCHAR* argv[]) {
	GetConsoleIOHandle();

	DWORD count = 0;
	EncryptType type = EncryptType::AES256;
	/*if (argc == 1) {
		WriteConsole(ConsoleOutputHandle, TEXT("No input file.\r\n"), 16, &count, NULL);
		return 0;
	}

	if (argc == 4) {
		_tString argv_3(argv[3]);
		if (argv_3 == TEXT("aes128"))
			type = EncryptType::AES128;
		else if (argv_3 == TEXT("aes192"))
			type = EncryptType::AES192;
		else
			type = EncryptType::AES256;
	}

	if (argc > 4 || argc == 2) {
		WriteConsole(ConsoleOutputHandle, TEXT("Unsupported parameter.\r\n"), 22, &count, NULL);
		return 0;
	}*/
	
	HANDLE EncryptedexeFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (EncryptedexeFile == INVALID_HANDLE_VALUE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Cound not open file.\r\n"), 22, &count, NULL);
		return GetLastError();
	}

	LARGE_INTEGER EncryptedexeFileSize = { 0 };
	GetFileSizeEx(EncryptedexeFile, &EncryptedexeFileSize);
	BYTE* fileBuffer = new BYTE[EncryptedexeFileSize.LowPart];
	if (fileBuffer == nullptr) {
		WriteConsole(ConsoleOutputHandle, TEXT("Cound not allocate memory.\r\n"), 28, &count, NULL);
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	DWORD BytesReadOrWritten = 0;
	SetFilePointer(EncryptedexeFile, 0, NULL, FILE_BEGIN);
	if (!(ReadFile(EncryptedexeFile, fileBuffer, EncryptedexeFileSize.LowPart, &BytesReadOrWritten, NULL) && EncryptedexeFileSize.LowPart == BytesReadOrWritten)) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when reading file.\r\n"), 32, &count, NULL);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	//_tString pass = GetPassword();
	_tString pass(argv[3]);
	if (decryptData(pass, fileBuffer, EncryptedexeFileSize.LowPart, type) == FALSE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when decrypting file.\r\n"), 35, &count, NULL);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}
	
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof si };

	if (CreateProcess(argv[2], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when creating process.\r\n"), 38, &count, NULL);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	CONTEXT context = { CONTEXT_INTEGER };
	if (GetThreadContext(pi.hThread, &context) == FALSE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when fetching process context.\r\n"), 46, &count, NULL);
		TerminateProcess(pi.hProcess, 0);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	PVOID ImageBaseAddress = nullptr;
	if (ReadProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &ImageBaseAddress, sizeof(ImageBaseAddress), 0) == FALSE) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when reading process memory.\r\n"), 44, &count, NULL);
		TerminateProcess(pi.hProcess, 0);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	if (ZwUnmapViewOfSection(pi.hProcess, ImageBaseAddress) != STATUS_SUCCESS) {
		WriteConsole(ConsoleOutputHandle, TEXT("Error occured when unmapping section.\r\n"), 39, &count, NULL);
		TerminateProcess(pi.hProcess, 0);
		delete[] fileBuffer;
		CloseHandle(EncryptedexeFile);
		return GetLastError();
	}

	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS(PCHAR(fileBuffer) + PIMAGE_DOS_HEADER(fileBuffer)->e_lfanew);

	PVOID newImageBaseAddress = VirtualAllocEx(pi.hProcess,
											   PVOID(nt->OptionalHeader.ImageBase),
											   nt->OptionalHeader.SizeOfImage,
											   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(pi.hProcess, newImageBaseAddress, fileBuffer, nt->OptionalHeader.SizeOfHeaders, 0);

	PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		WriteProcessMemory(pi.hProcess,
						   PCHAR(newImageBaseAddress) + sect[i].VirtualAddress,
						   PCHAR(fileBuffer) + sect[i].PointerToRawData,
						   sect[i].SizeOfRawData, 0);

		ULONG OldProtectAttribute = 0;
		VirtualProtectEx(pi.hProcess, PCHAR(newImageBaseAddress) + sect[i].VirtualAddress, sect[i].Misc.VirtualSize,
						 protectAttributeTable[sect[i].Characteristics >> 29], &OldProtectAttribute);
	}

	WriteProcessMemory(pi.hProcess, PCHAR(context.Ebx) + 8, &newImageBaseAddress, sizeof(newImageBaseAddress), NULL);
	context.Eax = ULONG(newImageBaseAddress) + nt->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(pi.hThread, &context);

	ResumeThread(pi.hThread);
	return 0;
}