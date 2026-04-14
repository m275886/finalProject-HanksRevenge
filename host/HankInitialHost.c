#include <Windows.h>
#include <stdio.h>

typedef BOOL (*HankInitializeFunction)(PCWSTR host, PCWSTR port);
typedef BOOL (*HankStartFunction)(VOID);
typedef VOID (*HankStopFunction)(VOID);

/**
 * @brief Loads the DLL, resolves the exported runtime entry points, and starts
 *        the polling loop for local testing.
 *
 * The host keeps the DLL loaded until the user presses Enter, then calls the
 * stop export and unloads the library.
 *
 * @return 0 on success, or 1 on failure.
 */
int wmain(int argc, wchar_t* argv[])
{
	HMODULE dllModule = NULL;
	HankInitializeFunction hankInitialize = NULL;
	HankStartFunction hankStart = NULL;
	HankStopFunction hankStop = NULL;
	PCWSTR dllPath = L"hank.dll";
	PCWSTR c2Host = L"127.0.0.1";
	PCWSTR c2Port = L"9001";

	if (argc > 1)
	{
		dllPath = argv[1];
	}

	if (argc > 2)
	{
		c2Host = argv[2];
	}

	if (argc > 3)
	{
		c2Port = argv[3];
	}

	wprintf(L"[*] Loading DLL: %ls\n", dllPath);
	dllModule = LoadLibraryW(dllPath);
	if (dllModule == NULL)
	{
		wprintf(L"[!] LoadLibraryW failed: %lu\n", GetLastError());
		return 1;
	}

	hankInitialize = (HankInitializeFunction)GetProcAddress(
		dllModule,
		"HankInitialize"
	);
	hankStart = (HankStartFunction)GetProcAddress(dllModule, "HankStart");
	hankStop = (HankStopFunction)GetProcAddress(dllModule, "HankStop");
	if (hankInitialize == NULL || hankStart == NULL || hankStop == NULL)
	{
		wprintf(L"[!] Failed to resolve one or more exports.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	if (!hankInitialize(c2Host, c2Port))
	{
		wprintf(L"[!] HankInitialize failed.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	if (!hankStart())
	{
		wprintf(L"[!] HankStart failed.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	wprintf(L"[*] Polling started. Press Enter to stop the host.\n");
	(void)getwchar();

	hankStop();
	FreeLibrary(dllModule);
	wprintf(L"[*] Host stopped.\n");

	return 0;
}
