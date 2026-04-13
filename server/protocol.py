import struct

MSG_ERROR = 0xFFFFFFFF

MSG_AGENT_GET_TASK = 0x10000001
MSG_AGENT_POST_RESULT = 0x10000002
MSG_OPERATOR_SUBMIT_TASK = 0x10000003
MSG_OPERATOR_GET_RESULT = 0x10000004
MSG_SERVER_NO_TASK = 0x10000005
MSG_SERVER_TASK = 0x10000006
MSG_SERVER_ACK = 0x10000007
MSG_SERVER_RESULT = 0x10000008
MSG_SERVER_PENDING = 0x10000009
MSG_OPERATOR_LIST_PENDING = 0x1000000A
MSG_SERVER_TASK_LIST = 0x1000000B
MSG_OPERATOR_LIST_HISTORY = 0x1000000C
MSG_SERVER_TASK_HISTORY = 0x1000000D

DEFAULT_AGENT_ID = 1

TASK_STATE_QUEUED_CODE = 1
TASK_STATE_LEASED_CODE = 2
TASK_STATE_COMPLETED_CODE = 3

MESSAGE_NAMES = {
    MSG_ERROR: "MSG_ERROR",
    MSG_AGENT_GET_TASK: "MSG_AGENT_GET_TASK",
    MSG_AGENT_POST_RESULT: "MSG_AGENT_POST_RESULT",
    MSG_OPERATOR_SUBMIT_TASK: "MSG_OPERATOR_SUBMIT_TASK",
    MSG_OPERATOR_GET_RESULT: "MSG_OPERATOR_GET_RESULT",
    MSG_SERVER_NO_TASK: "MSG_SERVER_NO_TASK",
    MSG_SERVER_TASK: "MSG_SERVER_TASK",
    MSG_SERVER_ACK: "MSG_SERVER_ACK",
    MSG_SERVER_RESULT: "MSG_SERVER_RESULT",
    MSG_SERVER_PENDING: "MSG_SERVER_PENDING",
    MSG_OPERATOR_LIST_PENDING: "MSG_OPERATOR_LIST_PENDING",
    MSG_SERVER_TASK_LIST: "MSG_SERVER_TASK_LIST",
    MSG_OPERATOR_LIST_HISTORY: "MSG_OPERATOR_LIST_HISTORY",
    MSG_SERVER_TASK_HISTORY: "MSG_SERVER_TASK_HISTORY",
}


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def encode_tlv(message_type, payload=b""):
    return struct.pack("<II", message_type, len(payload)) + payload


def decode_tlv(sock):
    header = recv_exact(sock, 8)
    if header is None:
        return None

    message_type, length = struct.unpack("<II", header)
    payload = recv_exact(sock, length) if length else b""
    if payload is None:
        return None

    return message_type, payload
