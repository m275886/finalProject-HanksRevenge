#include "network.h"

#define WINSOCK_VERSION_MAJOR 2
#define WINSOCK_VERSION_MINOR 2

static BOOL G_WinsockInitialized = FALSE;

BOOL NetworkStartup(VOID)
{
	WSADATA wsaData = { 0 };
	INT status = 0;

	if (G_WinsockInitialized)
	{
		return TRUE;
	}

	status = WSAStartup(
		MAKEWORD(WINSOCK_VERSION_MAJOR, WINSOCK_VERSION_MINOR),
		&wsaData
	);
	if (status != 0)
	{
		return FALSE;
	}

	G_WinsockInitialized = TRUE;
	return TRUE;
}

BOOL NetworkInit(PCWSTR host, PCWSTR port, SOCKET* sock, SCHANNEL_CRED* credentialPointer, CredHandle credHandle, CtxtHandle contextHandle)
{
	ADDRINFOW hints = { 0 };
	ADDRINFOW* result = NULL;
	INT status = 0;

	ASSERT(host != NULL);
	ASSERT(port != NULL);
	ASSERT(sock != NULL);

	*sock = INVALID_SOCKET;
	if (!G_WinsockInitialized)
	{
		return FALSE;
	}

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	/* Resolve the destination before creating the TCP socket. */
	status = GetAddrInfoW(host, port, &hints, &result);
	if (status != 0)
	{
		return FALSE;
	}

	*sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (*sock == INVALID_SOCKET)
	{
		FreeAddrInfoW(result);
		return FALSE;
	}

	status = connect(*sock, result->ai_addr, (INT)result->ai_addrlen);
	FreeAddrInfoW(result);

	if (status == SOCKET_ERROR)
	{
		/* Tear down only the failed socket; Winsock stays active for polling. */
		closesocket(*sock);
		*sock = INVALID_SOCKET;
		return FALSE;
	}

	return TRUE;
}

VOID NetworkCleanup(SOCKET sock)
{
	if (sock != INVALID_SOCKET)
	{
		shutdown(sock, SD_BOTH);
		closesocket(sock);
	}
}

VOID NetworkShutdown(VOID)
{
	if (!G_WinsockInitialized)
	{
		return;
	}

	WSACleanup();
	G_WinsockInitialized = FALSE;
}