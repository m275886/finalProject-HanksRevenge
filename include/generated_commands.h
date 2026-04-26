#pragma once

/* Auto-generated from shared/commands.csv. Do not edit directly. */

typedef enum _CMD_ID
{
    CMD_INSPECT_TOKEN = 4,
    CMD_IMPERSONATE_TOKEN = 5,
    CMD_ENABLE_PRIVILEGE = 6,
    CMD_DISABLE_PRIVILEGE = 7,
    CMD_HOSTNAME = 8,
    CMD_WHOAMI = 9,
    CMD_LS = 10,
    CMD_CAT = 11,
    CMD_MKDIR = 12,
    CMD_RM = 13,
    CMD_UPLOAD = 14,
    CMD_DOWNLOAD = 15,
    CMD_PS = 16,
    CMD_GETPID = 17,
    CMD_EXEC = 18,
    CMD_SHELLCODEEXEC = 19,
    CMD_MEMREAD = 20,
    CMD_MODULELIST = 21,
    CMD_HANDLELIST = 22,
    CMD_ENV = 23,
    CMD_GETENV = 24,
    CMD_SETENV = 25,
    CMD_SLEEP = 26,
    CMD_KILL = 27,
    CMD_PERSIST = 28,
    CMD_UNPERSIST = 29,
    CMD_MIGRATE = 30,
    CMD_HANK = 31,
    CMD_UNK
} CMD_ID;
