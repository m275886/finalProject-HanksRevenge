import struct

from generated_commands import CMD_IDS, CMD_NAMES, COMMAND_SPECS
from generated_errors import ERROR_MESSAGES

TOKEN_SUMMARY_HEADER_SIZE = 16
REFERENCE_COMMANDS = {"current-token", "killimplant"}


def display_help():
    """Print the local help menu built from the generated command specs."""
    print("\nLocal client commands:")
    print(f"  {'help':<22} Display this local help menu")
    print(f"  {'exit':<22} Close the operator client")
    print(f"  {'pending':<22} List queued or leased tasks on the server")
    print(f"  {'history':<22} List all known tasks and their latest status")
    print(f"  {'check <task_id>':<22} Query a queued task result by task id")

    print("\nReference implant commands:")
    for command_spec in COMMAND_SPECS:
        if command_spec["name"] not in REFERENCE_COMMANDS:
            continue

        print(f"  {command_spec['usage']:<22} {command_spec['description']}")

    print("\nStudent TODO implant commands:")
    for command_spec in COMMAND_SPECS:
        if command_spec["name"] in REFERENCE_COMMANDS:
            continue

        print(f"  {command_spec['usage']:<22} {command_spec['description']}")


def display_current_token(payload):
    """
    Example display handler for the current-token command.

    Response format:
    - DWORD elevated
    - DWORD impersonated
    - DWORD userNameLength
    - DWORD userSidLength
    - UTF-16LE username bytes including trailing null
    - UTF-16LE SID string bytes including trailing null

    Students can use this function as the reference implementation for how to
    parse other command responses in the lab.
    """
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


def display_process_token(payload):
    """
    TODO: Students implement this display handler.

    The implant should return a binary payload that summarizes the token for
    the requested PID. Your lab instructions should define the exact layout.

    Suggested output fields:
    - username
    - user SID
    - elevated (yes/no)
    - impersonated (yes/no)
    """
    print("[TODO] Parse and display the process-token response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")


def display_token_privileges(payload):
    """
    TODO: Students implement this display handler.

    The implant should return a binary payload containing all privileges
    associated with the requested process token.

    Your lab instructions should define how each privilege entry is encoded and
    how the privileges must be displayed.
    """
    print("[TODO] Parse and display the token-privileges response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")


def display_impersonate_token(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether impersonation succeeded or failed and, if successful, which token
    is now active.

    Your lab instructions should define the exact payload layout.
    """
    print("[TODO] Parse and display the impersonate-token response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")


def display_enable_privilege(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether the requested privilege was enabled successfully.

    Your lab instructions should define the exact payload layout.
    """
    print("[TODO] Parse and display the enable-privilege response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")


def display_killimplant(payload):
    """Display the killimplant result."""
    if payload:
        print(f"  payload_hex    : {payload.hex()}")
    else:
        print("  Implant termination requested.")




def display_disable_privilege(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether the requested privilege was enabled successfully.

    Your lab instructions should define the exact payload layout.
    """
    print("[TODO] Parse and display the enable-privilege response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")


def display_Host_Name(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether the requested privilege was enabled successfully.

    Your lab instructions should define the exact payload layout.
    """
    print("[TODO] Parse and display the enable-privilege response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")




def display_WHOAMI(payload):
    """
    TODO: Students implement this display handler.

    The implant should return enough information for the operator to tell
    whether the requested privilege was enabled successfully.

    Your lab instructions should define the exact payload layout.
    """
    print("[TODO] Parse and display the enable-privilege response.")
    print(f"  payload_length : {len(payload)}")
    if payload:
        print(f"  payload_hex    : {payload.hex()}")
        



#### UPDATE THIS FOR COMMANDS
DISPLAY_HANDLERS = {
    CMD_IDS["current-token"]: display_current_token,
    CMD_IDS["process-token"]: display_process_token,
    CMD_IDS["token-privileges"]: display_token_privileges,
    CMD_IDS["impersonate-token"]: display_impersonate_token,
    CMD_IDS["enable-privilege"]: display_enable_privilege,
    CMD_IDS["killimplant"]: display_killimplant,
    CMD_ID5["disable-privilege"] : display_disable_privilege,
    CMD_ID5["Host-Name"] : display_Host_name,
    CMD_ID5["WHOAMI"] : display_WHOAMI
}


def display_result(command_id, status, payload):
    """
    Dispatch a completed task result to the appropriate display handler.

    Students should implement the command-specific parsing logic in the
    display_* functions above rather than modifying the networking code below.
    """
    print(
        f"\n[result] type={CMD_NAMES.get(command_id, command_id)} "
        f"status=0x{status:08X}"
    )
    if status != 0:
        print(f"  error          : {ERROR_MESSAGES.get(status, 'Unknown error')}")
        return

    handler = DISPLAY_HANDLERS.get(command_id)
    if handler is None:
        print("[!] No display handler registered for this command.")
        print(f"  payload_length : {len(payload)}")
        if payload:
            print(f"  payload_hex    : {payload.hex()}")
        return

    handler(payload)
