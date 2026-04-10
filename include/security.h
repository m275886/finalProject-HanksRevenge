#pragma once
#include <Windows.h>
#include <psapi.h>
#include <sddl.h>
#include <strsafe.h>

#include "debug.h"
#include "error.h"

/**
* @brief  System process IDs to exclude from listings.
 *
 * These constants define the process IDs for the System Idle Process and System Process,
 * which are typically excluded from user-facing process listings.
 *
*/
#define SYS_IDLE_PS_ID 0
#define SYS_PS_ID 4

#define TOKEN_IMPERSONATION_SUCCESS 1

#define PRIV_ENABLED_PREVIOUSLY 1
#define PRIV_DISABLED_PREVIOUSLY 0
#define PRIV_ENABLE_SUCCESS 1
#define PRIV_ENABLE_FAILED 0

typedef struct _TOKEN_SUMMARY_HEADER
{
	DWORD elevated;
	DWORD impersonated;
	DWORD userNameLength;
	DWORD userSidLength;
} TOKEN_SUMMARY_HEADER;

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
 * @brief Allocates and packs a binary response buffer for the enable-privilege command.
 * 
 * @param privilegeName A wide-character pointer to the name of the privilege requested.
 * @param enableStatus  The result status of the privilege adjustment attempt (e.g., NO_ERROR or a Windows error code).
 * @param prevStatus    The previous state of the privilege (1 if it was already enabled, 0 if it was not).
 * @param responseData  A pointer to a byte pointer that will receive the allocated binary payload.
 * @param responseLen   A pointer to a DWORD that will receive the total size of the allocated payload in bytes.
 * 
 * @return DWORD Returns NO_ERROR upon successful allocation and packing, or an error code
 */
DWORD BuildTokenEnablePrivilegeResponseFromToken(PCWSTR privilegeName,
	DWORD enableStatus,
	DWORD prevStatus,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
* @brief Check if a privilege is already enabled.
* 
* @param name of the requested privilege
* 
* @return True if the privilege is enabled, false otherwise.
*/
BOOL IsPrivilegeEnabled(PCWSTR privilegeName);

/**
* @brief Builds a TOKEN_IMPERSONATION response from the current thread token, which is expected to be impersonating the target.
*
* @param processId The PID of the process whose token is being impersonated (for inclusion in the response).
* @param responseData Receives the heap-allocated response buffer.
* @param responseLen Receives the response buffer length in bytes.
*
* @return A numeric error or success code.
*/
DWORD BuildTokenImpersonationResponseFromToken(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Builds a response buffer that summarizes the current process token.
 *
 * The response contains a fixed-size TOKEN_SUMMARY_HEADER followed by a
 * UTF-16LE user name string and a UTF-16LE SID string. Both strings include
 * their terminating null characters.
 *
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildCurrentTokenSummaryResponse(PBYTE* responseData, DWORD* responseLen);

/**
 * @brief Builds a response buffer that summarizes a target process token.
 *
 * The intended response format mirrors BuildCurrentTokenSummaryResponse so the
 * Python client can parse local and remote token summaries consistently.
 *
 * @param processId The target process identifier.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildProcessTokenSummaryResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Builds a response buffer containing all privileges on a target token.
 *
 * @param processId The target process identifier.
 * @param responseData Receives an optional heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
DWORD BuildTokenPrivilegesResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
);

/**
 * @brief Attempts to impersonate the token of a target process.
 *
 * @param processId The target process identifier.
 *
 * @return A numeric error or success code.
 */
DWORD ImpersonateProcessToken(DWORD processId);

/**
 * @brief Attempts to enable a privilege on the current process token.
 *
 * @param privilegeName The privilege name to enable.
 *
 * @return A numeric error or success code.
 */
DWORD EnableCurrentTokenPrivilege(PCWSTR privilegeName);


/**
* @brief Builds a response buffer that summarizes a target process token's privileges.
* 
* @param processId The target process identifier.
* @param responseData Receives an optional heap-allocated response buffer.
* @param responseLen Receives the response buffer length in bytes.
* 
* @return A numeric error or success code.s
*/
DWORD BuildTokenStatsResponse(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen);