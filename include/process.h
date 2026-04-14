#pragma once
#include <windows.h>
#include <psapi.h>
#include <wchar.h> 
#include <stdlib.h>
#include "debug.h"
/**
* @brief  Maximum size for process-related buffers.
 *
 * This constant defines the maximum size allocated for process information buffers.
 *
*/
#define MAX_PROCESS_SIZE 4096
/**
* @brief  System process IDs to exclude from listings.
 *
 * These constants define the process IDs for the System Idle Process and System Process,
 * which are typically excluded from user-facing process listings.
 *
*/
#define SYS_IDLE_PS_ID 0
#define SYS_PS_ID 4
/**
* @brief  Success code for process termination.
 *
 * This constant indicates successful termination of a process.
 *
*/
#define SUCCESS_KILL_PROCESS 0

/**
* @brief  Size of the module handle array.
 *
 * This constant defines the size of the array used to store module handles
 * when enumerating modules in a process.
 *
*/
#define HMODS_SIZE 1024
/**
* @brief  Structure to hold information about a module loaded in a process.
 *
 * This structure contains the module's name, file path, and base address in memory.
 *
*/
typedef struct _ModuleInfo_t
{
	WCHAR* name;
	WCHAR* path;
	HMODULE baseAddress;
} ModuleInfo_t;

/**
* @brief  Structure to hold information about running processes.
 *
 * This structure contains an array of process IDs and the total number of processes.
 *
*/
typedef struct _ProcessInfo_t
{
	DWORD* processArray;
	DWORD numProcesses;
} ProcessInfo_t;


/**
* @brief  Terminates a process given its process ID (PID).
 *
 * This function opens the target process with the necessary permissions
 * and attempts to terminate it. It returns a status code indicating success or failure.
 *
 * @param[in]  processId  The process ID of the target process to terminate.
 *
 * @return     DWORD  SUCCESS_KILL_PROCESS on success, or an error code on failure.
*/
DWORD Kill(DWORD processId);

/**
* @brief  Retrieves information about all modules loaded in a specified process.
 *
 * This function opens the target process and enumerates its loaded modules,
 * populating an array of ModuleInfo_t structures with their details.
 *
 * @param[in]  processID  The process ID of the target process.
 * @param[out] cbNeeded   A pointer to a DWORD that receives the size of the module information.
 *
 * @return     ModuleInfo_t*  A pointer to an array of ModuleInfo_t structures containing module information.
*/
ModuleInfo_t* GetModules(DWORD processID, DWORD* cbNeeded);

/**
* @brief  Searches for a process by its process ID (PID).
 *
 * This function converts the input string argument to a DWORD PID and checks
 * if a process with that PID is currently running on the system.
 *
 * @param[in]  arg  A wide-character string representing the PID to search for.
 *
 * @return     BOOL  TRUE if the process is found, FALSE otherwise.
*/

BOOL FindPs(PWSTR arg);

/**
* @brief  Retrieves information about all running processes on the system.
 *
 * This function uses the Windows API to enumerate all currently running processes,
 * populating a ProcessInfo_t structure with their IDs and the total count.
 *
 * @return     ProcessInfo_t  A structure containing an array of process IDs and the number of processes.
*/
ProcessInfo_t GetProcessInfo();

/**
* @brief  Retrieves the name of a process given its process ID (PID).
 *
 * This function opens the specified process and retrieves its executable name.
 *
 * @param[in]  pid  The process ID of the target process.
 *
 * @return     WCHAR*  A pointer to a wide-character string containing the process name.
*/
WCHAR* GetProcessName(DWORD pid);