CMD_KILLIMPLANT = 1
CMD_CURRENT_TOKEN = 2
CMD_PROCESS_TOKEN = 3
CMD_INSPECT_TOKEN = 4
CMD_IMPERSONATE_TOKEN = 5
CMD_ENABLE_PRIVILEGE = 6
CMD_DISABLE_PRIVILEGE = 7
CMD_HOST_NAME = 8
CMD_WHOAMI = 9

COMMAND_SPECS = [
    {'id': CMD_KILLIMPLANT, 'name': 'killimplant', 'usage': 'killimplant', 'description': 'Stop the implant runtime'},
    {'id': CMD_CURRENT_TOKEN, 'name': 'current-token', 'usage': 'current-token', 'description': 'Return a summary of the current process token'},
    {'id': CMD_PROCESS_TOKEN, 'name': 'process-token', 'usage': 'process-token <pid>', 'description': 'Return a summary of a target process token'},
    {'id': CMD_INSPECT_TOKEN, 'name': 'inspect-token', 'usage': 'inspect-token <pid>', 'description': 'Return all privileges present on a target process token'},
    {'id': CMD_IMPERSONATE_TOKEN, 'name': 'impersonate-token', 'usage': 'impersonate-token <pid>', 'description': 'Attempt to impersonate the token of a target process'},
    {'id': CMD_ENABLE_PRIVILEGE, 'name': 'enable-privilege', 'usage': 'enable-privilege <name>', 'description': 'Attempt to enable a privilege on the current process token'},
    {'id': CMD_DISABLE_PRIVILEGE, 'name': 'disable-privilege', 'usage': 'disable-privilege <name>', 'description': 'Attempt to disable a privilege on the current process token'},
    {'id': CMD_HOST_NAME, 'name': 'hostname', 'usage': 'hostname', 'description': 'Tells user the host name'},
    {'id': CMD_WHOAMI, 'name': 'whoami', 'usage': 'whoami', 'description': 'Retrieves username and admin status'},
]

CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}
CMD_IDS = {spec['name']: spec['id'] for spec in COMMAND_SPECS}
