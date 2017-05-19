/*
	SRSAKeygen
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

	Using MinGW, compile with; gcc srsakeygen.c -Wall -pedantic -O3 -s -o srsakeygen
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>

#define KEY_SIZE	2048

static CONST WCHAR PrivateKeyFilename[] = L"private.key";
static CONST WCHAR PublicKeyFilename[] = L"public.key";

static HANDLE HeapHandle;
static HCRYPTPROV CryptHandle;
static HCRYPTKEY KeyHandle;

static INT CreateCryptContext()
{
	BOOL Return;
	DWORD LastError;

	Return = CryptAcquireContextW(&CryptHandle, NULL, NULL, PROV_RSA_FULL, 0);
	if (!Return) {
		LastError = GetLastError();
		if (LastError == NTE_BAD_KEYSET) {
			if (!CryptAcquireContextW(&CryptHandle, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				return 0;
		} else {
			return 0;
		}
	}

	return 1;
}

static INT ExportKey(INT KeyType, CONST WCHAR *Filename)
{
	DWORD KeySize;
	BYTE *Key;
	HANDLE File;
	DWORD BytesWritten;

	if (!CryptExportKey(KeyHandle, 0, KeyType, 0, NULL, &KeySize))
		return 0;

	Key = HeapAlloc(HeapHandle, 0, KeySize);
	if (!Key)
		return 0;

	if (!CryptExportKey(KeyHandle, 0, KeyType, 0, Key, &KeySize)) {
		SecureZeroMemory(Key, KeySize);
		HeapFree(HeapHandle, 0, Key);
		return 0;
	}

	File = CreateFileW(Filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (File == INVALID_HANDLE_VALUE) {
		SecureZeroMemory(Key, KeySize);
		HeapFree(HeapHandle, 0, Key);
		return 0;
	}

	if (!WriteFile(File, Key, KeySize, &BytesWritten, NULL)) {
		SecureZeroMemory(Key, KeySize);
		HeapFree(HeapHandle, 0, Key);
		return 0;
	}

	SecureZeroMemory(Key, KeySize);
	HeapFree(HeapHandle, 0, Key);
	CloseHandle(File);
	return 1;
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	HeapHandle = GetProcessHeap();
	if (!HeapHandle) {
		fputws(L"Failed to obtain the default heap.\n", stderr);
		return 1;
	}

	if (!CreateCryptContext()) {
		fputws(L"Failed to create a Crypt context.\n", stderr);
		return 1;
	}

	if (!CryptGenKey(CryptHandle, AT_KEYEXCHANGE, (KEY_SIZE << 16) | CRYPT_ARCHIVABLE | CRYPT_EXPORTABLE, &KeyHandle)) {
		fputws(L"Unable to generate a 2048-bit RSA public/private key pair.\n", stderr);
		CryptReleaseContext(CryptHandle, 0);
		return 1;
	}

	if (!ExportKey(PRIVATEKEYBLOB, PrivateKeyFilename) ||
		!ExportKey(PUBLICKEYBLOB, PublicKeyFilename)) {
		fputws(L"Unable to export the keys.\n", stderr);
		CryptDestroyKey(KeyHandle);
		CryptReleaseContext(CryptHandle, 0);
		return 1;
	}

	_putws(L"Key generation was successful.");

	CryptDestroyKey(KeyHandle);
	CryptReleaseContext(CryptHandle, 0);

	return 0;
}
