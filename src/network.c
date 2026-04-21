#include "network.h"

/*
 * network.c - TCP connect + TLS handshake for one implant poll cycle.
 *
 * NetworkInit replaces the old two-step pattern (connect socket, then
 * separately set up TLS) with a single call that returns a fully-negotiated
 * TLS_CONTEXT.  Session teardown is now owned by TlsCleanup so there is no
 * separate NetworkCleanup function.
 */

#define WINSOCK_VERSION_MAJOR 2
#define WINSOCK_VERSION_MINOR 2

static BOOL G_WinsockInitialized = FALSE;

BOOL NetworkStartup(VOID)
{
    WSADATA wsaData = { 0 };
    INT status;

    if (G_WinsockInitialized) return TRUE;

    status = WSAStartup(
        MAKEWORD(WINSOCK_VERSION_MAJOR, WINSOCK_VERSION_MINOR),
        &wsaData);
    if (status != 0) return FALSE;

    G_WinsockInitialized = TRUE;
    return TRUE;
}

BOOL NetworkInit(PCWSTR host, PCWSTR port, TLS_CONTEXT* ctx)
{
    ADDRINFOW  hints = { 0 };
    ADDRINFOW* result = NULL;
    SOCKET     sock = INVALID_SOCKET;
    INT        status;

    ASSERT(host != NULL);
    ASSERT(port != NULL);
    ASSERT(ctx != NULL);

    if (!G_WinsockInitialized) return FALSE;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    status = GetAddrInfoW(host, port, &hints, &result);
    if (status != 0) return FALSE;

    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET)
    {
        FreeAddrInfoW(result);
        return FALSE;
    }

    status = connect(sock, result->ai_addr, (INT)result->ai_addrlen);
    FreeAddrInfoW(result);

    if (status == SOCKET_ERROR)
    {
        closesocket(sock);
        return FALSE;
    }

    /* Hand the connected socket to Schannel for the TLS handshake.
     * TlsInit stores the socket in ctx->sock; if the handshake fails it
     * does NOT close the socket, so we close it here on failure. */
    if (!TlsInit(sock, host, ctx))
    {
        closesocket(sock);
        return FALSE;
    }

    return TRUE;
}

VOID NetworkShutdown(VOID)
{
    if (!G_WinsockInitialized) return;
    WSACleanup();
    G_WinsockInitialized = FALSE;
}