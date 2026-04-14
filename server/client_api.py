import socket
import struct

from commands import CMD_NAMES
from protocol import (
    DEFAULT_AGENT_ID,
    MSG_OPERATOR_GET_RESULT,
    MSG_OPERATOR_LIST_HISTORY,
    MSG_OPERATOR_LIST_PENDING,
    MSG_OPERATOR_SUBMIT_TASK,
    MSG_SERVER_ACK,
    MSG_SERVER_PENDING,
    MSG_SERVER_RESULT,
    MSG_SERVER_TASK_HISTORY,
    MSG_SERVER_TASK_LIST,
    TASK_STATE_COMPLETED_CODE,
    TASK_STATE_LEASED_CODE,
    TASK_STATE_QUEUED_CODE,
    decode_tlv,
    encode_tlv,
)

C2_HOST = "127.0.0.1"
C2_PORT = 9002

TASK_STATE_NAMES = {
    TASK_STATE_QUEUED_CODE: "queued",
    TASK_STATE_LEASED_CODE: "leased",
    TASK_STATE_COMPLETED_CODE: "completed",
}

PENDING_TASK_ENTRY_SIZE = 16
TASK_HISTORY_ENTRY_SIZE = 20
RESULT_HEADER_SIZE = 16


def encode_arg_bytes(cmd_name, arg):
    """
    Convert operator input into the binary argument format expected by the
    implant.

    Students generally should not need to modify this unless the lab changes
    the request format.
    """
    if cmd_name in {"process-token", "token-privileges", "impersonate-token"}:
        return struct.pack("<I", int(arg, 10))
    if cmd_name == "enable-privilege":
        return arg.encode("utf-8")
    return b""


def send_message(message_type, payload):
    """Open a short-lived connection to the task server and send one message."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((C2_HOST, C2_PORT))
        sock.sendall(encode_tlv(message_type, payload))
        return decode_tlv(sock)
    finally:
        sock.close()


def submit_task(command_id, arg_bytes):
    """Queue a task for the default test agent."""
    payload = struct.pack(
        "<III",
        DEFAULT_AGENT_ID,
        command_id,
        len(arg_bytes),
    ) + arg_bytes
    return send_message(MSG_OPERATOR_SUBMIT_TASK, payload)


def fetch_result(task_id):
    """Query the task server for the result of a previously queued task."""
    return send_message(MSG_OPERATOR_GET_RESULT, struct.pack("<I", task_id))


def fetch_pending_tasks():
    """Request a snapshot of all queued or leased tasks from the server."""
    return send_message(MSG_OPERATOR_LIST_PENDING, b"")


def fetch_task_history():
    """Request a snapshot of all known tasks from the server."""
    return send_message(MSG_OPERATOR_LIST_HISTORY, b"")


def display_pending_tasks():
    """Display all currently queued or leased tasks without creating a task."""
    response = fetch_pending_tasks()
    if response is None:
        print("[!] Failed to query pending tasks")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_TASK_LIST or len(payload) < 4:
        print("[!] Unexpected response while querying pending tasks")
        return

    task_count = struct.unpack("<I", payload[:4])[0]
    expected_length = 4 + (task_count * PENDING_TASK_ENTRY_SIZE)
    if len(payload) < expected_length:
        print("[!] Pending task list payload is truncated")
        return

    if task_count == 0:
        print("[*] No queued or leased tasks.")
        return

    print("\nPending tasks:")
    print("  task_id  agent_id  command                state")

    offset = 4
    for _ in range(task_count):
        task_id, agent_id, command_id, state_code = struct.unpack(
            "<IIII",
            payload[offset:offset + PENDING_TASK_ENTRY_SIZE],
        )
        offset += PENDING_TASK_ENTRY_SIZE
        command_name = CMD_NAMES.get(command_id, f"0x{command_id:08X}")
        state_name = TASK_STATE_NAMES.get(state_code, f"unknown({state_code})")
        print(
            f"  {task_id:<7}  {agent_id:<8}  "
            f"{command_name:<21} {state_name}"
        )


def display_task_history():
    """Display all known tasks, including completed ones."""
    response = fetch_task_history()
    if response is None:
        print("[!] Failed to query task history")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_TASK_HISTORY or len(payload) < 4:
        print("[!] Unexpected response while querying task history")
        return

    task_count = struct.unpack("<I", payload[:4])[0]
    expected_length = 4 + (task_count * TASK_HISTORY_ENTRY_SIZE)
    if len(payload) < expected_length:
        print("[!] Task history payload is truncated")
        return

    if task_count == 0:
        print("[*] No task history available.")
        return

    print("\nTask history:")
    print("  task_id  agent_id  command                state       status")

    offset = 4
    for _ in range(task_count):
        task_id, agent_id, command_id, state_code, status = struct.unpack(
            "<IIIII",
            payload[offset:offset + TASK_HISTORY_ENTRY_SIZE],
        )
        offset += TASK_HISTORY_ENTRY_SIZE
        command_name = CMD_NAMES.get(command_id, f"0x{command_id:08X}")
        state_name = TASK_STATE_NAMES.get(state_code, f"unknown({state_code})")
        print(
            f"  {task_id:<7}  {agent_id:<8}  "
            f"{command_name:<21} {state_name:<10} 0x{status:08X}"
        )


def check_task_result(display_result, task_id):
    """Fetch and display the current state of one previously queued task."""
    result = fetch_result(task_id)
    if result is None:
        print("[!] Failed to query task result")
        return

    result_type, result_payload = result
    if result_type == MSG_SERVER_PENDING:
        print(f"[*] Task {task_id} is still pending.")
        return

    if result_type != MSG_SERVER_RESULT or len(result_payload) < RESULT_HEADER_SIZE:
        print("[!] Unexpected result response")
        return

    result_task_id, result_command_id, status, result_length = struct.unpack(
        "<IIII",
        result_payload[:RESULT_HEADER_SIZE],
    )
    result_bytes = result_payload[
        RESULT_HEADER_SIZE:RESULT_HEADER_SIZE + result_length
    ]
    print(f"[*] Task {result_task_id} completed")
    display_result(result_command_id, status, result_bytes)


def print_queue_result(response):
    """Display the server response after submitting a new task."""
    if response is None:
        print("[!] Failed to submit task")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_ACK or len(payload) < 4:
        print("[!] Unexpected response while submitting task")
        return

    task_id = struct.unpack("<I", payload[:4])[0]
    print(f"[*] Queued task {task_id} for agent {DEFAULT_AGENT_ID}")
