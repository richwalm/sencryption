/*
	SDecrypt
	Copyright (C) 2012 Richard Walmsley <richwalm@gmail.com>

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

	Using MinGW, compile with; gcc sdecrypt.c -Wall -pedantic -O3 -s -o sdecrypt
*/

#define WIN32_LEAN_AND_MEAN
#define	_WIN32_WINNT	0x0500
#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define AES_KEY_SIZE	256

#define	BUFFER_SIZE		4096

static CONST WCHAR PrivateKeyFilename[] = L"private.key";
static CONST WCHAR EncryptExtension[] = L".enc";

/* This is a PUBLICKEYSTRUC and a seperate ALG_ID. To save space, its been removed. */
static CONST BYTE SessionKeyHeader[] =
	{ 0x01, 0x02, 0x00, 0x00, 0x10, 0x66, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00 };

static HANDLE HeapHandle;
static HCRYPTPROV CryptHandle;
static HCRYPTKEY PrivateKeyHandle;
static HCRYPTKEY SessionKeyHandle;

static WCHAR Directory[MAX_PATH];

static INT CreateCryptContext()
{
	BOOL Return;
	DWORD LastError;

	Return = CryptAcquireContextW(&CryptHandle, NULL, NULL, PROV_RSA_AES, 0);
	if (!Return) {
		LastError = GetLastError();
		if (LastError == NTE_BAD_KEYSET) {
			if (!CryptAcquireContextW(&CryptHandle, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
				return 0;
		} else {
			return 0;
		}
	}

	return 1;
}

static INT ImportKey(CONST WCHAR *Filename)
{
	HANDLE File;
	LARGE_INTEGER FileSize;
	BYTE *PrivateKeyData;
	DWORD PrivateKeyDataSize;
	PUBLICKEYSTRUC *PrivateKeyHeader;

	File = CreateFileW(Filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (File == INVALID_HANDLE_VALUE)
		return 0;

	if (!GetFileSizeEx(File, &FileSize) || FileSize.QuadPart > 1172) {
		CloseHandle(File);
		return 0;
	}

	PrivateKeyData = HeapAlloc(HeapHandle, 0, FileSize.QuadPart);
	if (!PrivateKeyData) {
		CloseHandle(File);
		return 0;
	}

	if (!ReadFile(File, PrivateKeyData, FileSize.QuadPart, &PrivateKeyDataSize, NULL)) {
		HeapFree(HeapHandle, 0, PrivateKeyData);
		CloseHandle(File);
		return 0;
	}

	CloseHandle(File);

	PrivateKeyHeader = (PUBLICKEYSTRUC *)PrivateKeyData;
	if (PrivateKeyHeader->bType != PRIVATEKEYBLOB) {
		HeapFree(HeapHandle, 0, PrivateKeyData);
		return 0;
	}

	if (!CryptImportKey(CryptHandle, PrivateKeyData, PrivateKeyDataSize, 0, 0, &PrivateKeyHandle)) {
		HeapFree(HeapHandle, 0, PrivateKeyData);
		return 0;
	}

	HeapFree(HeapHandle, 0, PrivateKeyData);

	return 1;
}

static INT MakeDecrypted(CONST WCHAR *InputFilename, CONST WCHAR *OutputFilename)
{
	HANDLE Input, Output;
	BYTE Buffer[BUFFER_SIZE];
	DWORD Bytes;
	BOOL Done;

	/* Before we do anything, let's see if we can access and create these files. */
	Input = CreateFileW(InputFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (Input == INVALID_HANDLE_VALUE)
		return 0;

	Output = CreateFileW(OutputFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (Output == INVALID_HANDLE_VALUE) {
		CloseHandle(Input);
		return 0;
	}

	/* We'll obtain the first 256 bytes from the file which is the session key. */
	if (!ReadFile(Input, &Buffer[sizeof(SessionKeyHeader)], AES_KEY_SIZE, &Bytes, NULL) || Bytes < AES_KEY_SIZE) {
		CloseHandle(Output);
		CloseHandle(Input);
		DeleteFileW(OutputFilename);
		return 0;
	}

	/* This was removed to save space but we'll add it back in as it's required. */
	CopyMemory(Buffer, SessionKeyHeader, sizeof(SessionKeyHeader));

	if (!CryptImportKey(CryptHandle, Buffer, sizeof(SessionKeyHeader) + AES_KEY_SIZE, PrivateKeyHandle, CRYPT_OAEP, &SessionKeyHandle)) {
		CloseHandle(Output);
		CloseHandle(Input);
		DeleteFileW(OutputFilename);
		return 0;
	}

	Done = FALSE;
	while (!Done) {
		if (!ReadFile(Input, &Buffer, sizeof(Buffer), &Bytes, NULL)) {
			CryptDestroyKey(SessionKeyHandle);
			CloseHandle(Input);
			CloseHandle(Output);
			return 0;
		}
		if (Bytes < sizeof(Buffer))
			Done = TRUE;

		if (!CryptDecrypt(SessionKeyHandle, 0, Done, 0, Buffer, &Bytes)) {
			CryptDestroyKey(SessionKeyHandle);
			CloseHandle(Output);
			CloseHandle(Input);
			return 0;
		}

		if (!WriteFile(Output, &Buffer, Bytes, &Bytes, NULL)) {
			CryptDestroyKey(SessionKeyHandle);
			CloseHandle(Input);
			CloseHandle(Output);
			return 0;
		}
	}

	CloseHandle(Output);
	CloseHandle(Input);

	return 1;
}

static UINT GetBlock(WCHAR *CONST Search, WCHAR **Start)
{
	BOOL ReachedString = FALSE;
	BOOL InQuotes = FALSE;
	UINT Size = 0;
	WCHAR *Char;

	*Start = Char = Search;

	for (;;) {

		if (isgraph(*Char)) {
			if (!ReachedString) {
				ReachedString = TRUE;
				*Start = Char;
			}
			if (*Char == L'"')
				InQuotes = (InQuotes ? FALSE : TRUE);
		}
		else
		{
			if ((!InQuotes && ReachedString) || *Char == L'\0')
				break;
		}

		if (ReachedString)
			Size++;

		Char++;
	}

	if (!ReachedString)
		*Start = Char;

	return Size;
}

static VOID PrintUsage()
{
	WCHAR *Start;
	UINT Size;

	Size = GetBlock(GetCommandLineW(), &Start);

	wprintf(L"Usage: %.*s file(s)\n", Size, Start);

	return;
}

static VOID PraseCmdLine()
{
	WCHAR *CmdLine;

	WCHAR *Start;
	UINT Size;	/* In characters. */
	UINT EncryptExtensionLength;
	UINT Blocks;

	WCHAR Buffer[MAX_PATH];

	HANDLE FileHandle;
	WIN32_FIND_DATAW FindData;

	WCHAR *String;

	CmdLine = GetCommandLineW();
	EncryptExtensionLength = wcslen(EncryptExtension);

	Blocks = 0;

	/* First one contains the executable's filename. */
	CmdLine += GetBlock(CmdLine, &Start);

	while (*CmdLine) {

		Size = GetBlock(CmdLine, &Start);
		if (Size == 0)
			break;
		CmdLine = Start + Size;
		Blocks++;

		/* Remove the quotes. */
		if (*Start == L'\"') {
			Start++;
			Size--;
			if (Size != 0 && Start[Size - 1] == L'\"')
				Size--;
			if (Size == 0)
				continue;
		}

		/* Add an asterisk if required. */
		if (Size * sizeof(WCHAR) < sizeof(Buffer)) {

			CopyMemory(Buffer, Start, Size * sizeof(WCHAR));
			if (Buffer[Size - 1] == L'\\') {
				Buffer[Size] = L'*';
				Size++;
				if (Size >= MAX_PATH)
					continue;
			}
			Buffer[Size] = L'\0';
		}
		else
			continue;

		FileHandle = FindFirstFileW(Buffer, &FindData);
		if (FileHandle == INVALID_HANDLE_VALUE)
			continue;

		/* Change directory. */
		Start = wcsrchr(Buffer, L'\\');
		if (Start) {
			*(Start + 1) = L'\0';
			String = Buffer;
		}
		else
			String = Directory;
		if (!SetCurrentDirectoryW(String)) {
			FindClose(FileHandle);
			continue;
		}

		do {

			if (FindData.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM))
				continue;

			_putws(FindData.cFileName);

			Start = wcsrchr(FindData.cFileName, L'.');
			if (!(Start && _wcsnicmp(Start, EncryptExtension, EncryptExtensionLength) == 0)) {
				_putws(L"\tNot encrypted.");
				continue;
			}

			/* Remove the encyption extension. */
			Size = wcslen(FindData.cFileName) + 1;
			CopyMemory(Buffer, FindData.cFileName, Size * sizeof(WCHAR));
			Start = wcsrchr(Buffer, L'.');
			*Start = L'\0';

			if (!MakeDecrypted(FindData.cFileName, Buffer)) {
				FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, (WCHAR *)&String, 0, NULL);
				wprintf(L"\t%s\n", String);
				LocalFree(String);
			}
			else
			{
				DeleteFileW(FindData.cFileName);
			}

		} while (FindNextFileW(FileHandle, &FindData));

		FindClose(FileHandle);
	}

	if (Blocks == 0)
		PrintUsage();

	return;
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	DWORD Return;
	WCHAR *Char;

	HeapHandle = GetProcessHeap();
	if (!HeapHandle) {
		fputws(L"Failed to obtain the default heap.\n", stderr);
		return 1;
	}

	if (!CreateCryptContext()) {
		fputws(L"Failed to create a Crypt context.\n", stderr);
		return 1;
	}

	Return = GetModuleFileNameW(hInstance, Directory, MAX_PATH);
	if (Return == 0 || Return >= MAX_PATH) {
		fputws(L"Unable to obtain program's path.\n", stderr);
		CryptReleaseContext(CryptHandle, 0);
		return 1;
	}
	Char = wcsrchr(Directory, L'\\') + 1;
	if (!Char)
		return 1;
	CopyMemory(Char, PrivateKeyFilename, sizeof(PrivateKeyFilename));

	if (!ImportKey(Directory)) {
		fputws(L"Unable to import the private key.\n", stderr);
		CryptReleaseContext(CryptHandle, 0);
		return 1;
	}

	Return = GetCurrentDirectoryW(MAX_PATH, Directory);
	if (Return == 0 || Return > MAX_PATH) {
		fputws(L"Unable to obtain current directory.\n", stderr);
		CryptDestroyKey(PrivateKeyHandle);
		CryptReleaseContext(CryptHandle, 0);
		return 1;
	}

	PraseCmdLine();

	CryptDestroyKey(SessionKeyHandle);
	CryptDestroyKey(PrivateKeyHandle);
	CryptReleaseContext(CryptHandle, 0);

	return 0;
}
