# Hank's Revenge — Final Project

## Team Roles

| Area | Owner |
|------|-------|
| Protocol (DNS/HTTPS) | Evan & Daniel |
| Implant beacon callback | Shawn |
| Initial commands | Audrey |

---

## Overview

Hank's Revenge is a lab-only Windows post-compromise research platform built for the Windows Internals for Cyber Operations capstone.  It consists of three components:

| Component | Language | Description |
|-----------|----------|-------------|
| **Implant DLL** | C (MSVC) | `Hanks_Revenge.dll` — beacons over HTTPS, executes tasks, returns results |
| **C2 Server** | Python | Dual-port HTTPS task broker (implant port 9001, operator port 9002) |
| **Operator Client** | Python | Interactive CLI for issuing commands and inspecting results |

All traffic is TLS-encrypted (TLS 1.2+) and framed as HTTP/1.1 POST requests so the C2 channel appears as ordinary HTTPS at the network layer.

---

## Project Structure

```
finalProject-HanksRevenge/
├── CMakeLists.txt          # CMake build definition
├── rebuild.bat             # Clean + configure + build (opens VS solution)
├── start_project.bat       # Launch all three components in separate windows
├── setup.ps1               # One-time setup for Developer PowerShell
├── host/
│   └── HankInitialHost.c   # Test harness that loads and runs the DLL
├── include/                # C headers
│   ├── tls.h               # Schannel TLS context
│   ├── protocol.h          # TLV message types + HTTP round-trip API
│   ├── network.h           # TCP + TLS connect
│   ├── exports.h           # DLL exports (HankInitialize / HankStart / HankStop)
│   ├── command.h           # Command dispatch table
│   ├── security.h          # Token manipulation API
│   ├── process.h           # Process enumeration
│   ├── system.h            # System info
│   └── debug.h             # Heap tracking / assertions
├── src/                    # C implementation
│   ├── tls.c               # Schannel handshake, encrypt, decrypt
│   ├── protocol.c          # HTTP-over-TLS framing (HttpSendTlvRoundTrip)
│   ├── network.c           # TCP connect → TLS handshake
│   ├── exports.c           # DLL entry points + polling loop
│   ├── command.c           # Command dispatch table
│   ├── security.c          # Token inspection / privilege / impersonation
│   ├── process.c           # Process enumeration
│   ├── system.c            # Hostname / whoami
│   └── debug.c             # Heap tracking
├── server/
│   ├── server.py           # C2 task broker (HTTPS, dual-port)
│   ├── client.py           # Operator interactive CLI
│   ├── client_api.py       # HTTPS client helpers
│   ├── client_display.py   # Result display handlers
│   ├── protocol.py         # TLV + HTTP framing helpers
│   ├── commands.py         # Command ID → name mapping
│   ├── errors.py           # Error code → message mapping
│   └── gen_certs.py        # Self-signed TLS cert generator (run once)
├── shared/
│   ├── commands.csv        # Command definitions (shared C ↔ Python)
│   └── errors.csv          # Error code definitions
└── .vscode/
    ├── tasks.json          # VS Code build / launch tasks
    ├── launch.json         # Debugger configurations
    ├── c_cpp_properties.json  # IntelliSense settings
    └── settings.json       # Editor settings
```

---

## Prerequisites (install once on the VM)

| Tool | Purpose | Where to get it |
|------|---------|-----------------|
| Visual Studio 2022 (or 2019) | C compiler (`cl.exe`) | Visual Studio Installer — include the **Desktop development with C++** workload |
| CMake 3.10+ | Build system | Bundled with VS, or [cmake.org](https://cmake.org) |
| Python 3.8+ | Server + operator client | [python.org](https://python.org) — check **Add to PATH** |
| `cryptography` Python package | TLS cert generation | `pip install cryptography` |

---

## Getting Started on a New VM

### Step 0 — Transfer the project

Zip the project folder on your host machine and copy the zip to the VM:

```
Right-click finalProject-HanksRevenge → Send to → Compressed (zipped) folder
```

On the VM, extract it anywhere (e.g. `C:\Users\<you>\Desktop\finalProject-HanksRevenge`).

---

### Option A — One-command setup (Developer PowerShell) ✅ Recommended

1. Open **Developer PowerShell for VS 2022** from the Start menu.
2. Navigate to the project:
   ```powershell
   cd C:\Users\<you>\Desktop\finalProject-HanksRevenge
   ```
3. Allow the script to run for this session:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```
4. Run setup (installs deps, builds, generates cert):
   ```powershell
   .\setup.ps1
   ```
5. Launch everything:
   ```powershell
   .\start_project.bat
   ```

Three windows open automatically: C2 server, implant host, operator client.

---

### Option B — Batch scripts (Command Prompt)

1. Open a **normal Command Prompt** (or Developer Command Prompt).
2. `cd` to the project folder.
3. Build:
   ```bat
   rebuild.bat
   ```
4. Generate the TLS cert (first time only):
   ```bat
   python server\gen_certs.py
   ```
5. Launch:
   ```bat
   start_project.bat
   ```

`start_project.bat` also auto-generates the cert if it is missing.

---

### Option C — Visual Studio (full GUI)

1. Run `rebuild.bat` — it builds and opens the `.sln` automatically.
2. In **Solution Explorer**, right-click `HankInitialHost` → **Set as Startup Project**.
3. Open a separate terminal and start the Python C2 server:
   ```bat
   python server\server.py
   ```
4. Start the operator client in another terminal:
   ```bat
   python server\client.py
   ```
5. Press **F5** in Visual Studio to launch the host under the debugger.
   - Set breakpoints in `src/security.c`, `src/command.c`, etc.
   - The debugger loads DLL symbols automatically when the host calls `LoadLibraryW`.
   - If breakpoints appear hollow, confirm you are running the **Debug** build.

---

### Option D — VS Code

1. Open the project:
   ```bat
   code .
   ```
2. Install the **C/C++** and **CMake Tools** extensions when prompted.
3. Build: `Ctrl+Shift+B` → **Rebuild (clean + configure + Debug)**
4. Start the server: **Terminal → Run Task → Start C2 Server**
5. Debug: **Run and Debug** → **Debug Implant (via HankInitialHost)** → **F5**
6. Start the operator: **Terminal → Run Task → Start Operator Client**

---

## Manual startup (three separate terminals)

If the scripts do not work, start each component manually:

**Terminal 1 — C2 server:**
```bat
python server\server.py
```

**Terminal 2 — Implant host:**
```bat
build\Debug\HankInitialHost.exe build\Debug\Hanks_Revenge.dll 127.0.0.1 9001
```

**Terminal 3 — Operator client:**
```bat
python server\client.py
```

---

## Architecture

```
[Operator CLI] ──HTTPS──► [C2 Server :9002]
                                │
                          task queue (in-memory)
                                │
[Implant DLL]  ◄─HTTPS── [C2 Server :9001]
     │
 (loaded by HankInitialHost.exe)
```

**Communications flow:**
1. Implant beacons every 5 seconds: `POST /beacon` with TLV `MSG_AGENT_GET_TASK`
2. Server responds with `MSG_SERVER_TASK` (or `MSG_SERVER_NO_TASK`)
3. Implant executes command, sends `POST /beacon` with TLV `MSG_AGENT_POST_RESULT`
4. Server stores result; operator polls with `check <task_id>`

All bodies are TLV-encoded (4-byte type + 4-byte length + payload) over TLS 1.2+.

---

## Encryption Approach

Transport: **TLS 1.2 / 1.3** (HTTPS)

- **C implant:** Windows Schannel via SSPI (`src/tls.c`).  `SCH_CRED_MANUAL_CRED_VALIDATION` allows the self-signed lab cert without embedding a CA chain.
- **Python server:** `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` wrapping standard `socket`.
- **Python operator:** `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with `CERT_NONE` (self-signed cert accepted in the lab environment).
- **Cert generation:** `server/gen_certs.py` generates a 2048-bit RSA self-signed cert with SANs for `localhost` and `127.0.0.1`.  Run once; certs are excluded from the repo via `.gitignore`.

---

## Supported Commands

### Operator client built-ins (local only — not sent to implant)

| Command | Description |
|---------|-------------|
| `help` | Display the full command menu |
| `exit` | Close the operator client |
| `pending` | List all queued or leased tasks |
| `history` | Show all tasks and their final status |
| `check <task_id>` | Retrieve the result for a completed task |

### Filesystem

| Command | Description |
|---------|-------------|
| `ls <remote_path>` | List directory contents (type, size, name) |
| `cat <remote_path>` | Display a text file's contents |
| `mkdir <remote_path>` | Create a directory |
| `rm <remote_path>` | Delete a file or empty directory |
| `upload <remote_path> <local_path>` | Transfer a local file to the implant host |
| `download <remote_path>` | Transfer a file from the implant host; saves to the `server/` directory |

### System Enumeration

| Command | Description |
|---------|-------------|
| `whoami` | Current username + admin status |
| `hostname` | Host computer name |
| `getpid` | Implant process ID |
| `ps` | Enumerate running processes (PID + image name) |

### Execution

| Command | Description |
|---------|-------------|
| `exec <command>` | Run a shell command via `cmd.exe /c`; returns stdout, stderr, and exit code |
| `shellcodeexec <pid> <shellcode_file>` | Inject raw shellcode (`pid=0` → self; any other PID → remote thread injection) |

### Token Manipulation

| Command | Description |
|---------|-------------|
| `inspect-token` | Display all privileges on the current process token |
| `enable-privilege <name>` | Enable a named privilege (e.g. `SeDebugPrivilege`) |
| `disable-privilege <name>` | Disable a named privilege |
| `impersonate-token <pid>` | Impersonate the token of the target process |

### Memory and Object Inspection

| Command | Description |
|---------|-------------|
| `memread <pid> <addr_hex> <size>` | Dump `size` bytes from a process address; displays a hex+ASCII dump |
| `modulelist <pid>` | List all loaded modules with their base addresses |
| `handlelist <pid>` | Enumerate all handles for a process (value, type index, access mask) |

### Environment

| Command | Description |
|---------|-------------|
| `env` | List all environment variables of the implant process |
| `getenv <name>` | Return the value of one environment variable |
| `setenv <NAME=VALUE>` | Create or modify an environment variable |

### Implant Management

| Command | Description |
|---------|-------------|
| `sleep <ms>` | Change the beacon callback interval (milliseconds); takes effect next cycle |
| `kill` | Stop the implant gracefully after the current task result is posted |
| `persist` | Write a `HKCU\...\Run\HanksRevenge` registry value so the implant restarts on login |
| `unpersist` | Remove the Run registry value added by `persist` |
| `migrate <pid>` | Inject the implant DLL into another process via `CreateRemoteThread + LoadLibraryW` |

---

## Persistence Method

Persistence is implemented via the Windows registry Run key:

- **Key:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `HanksRevenge`
- **Value data:** `"<HankInitialHost.exe path>" "<Hanks_Revenge.dll path>" <C2 host> <C2 port>`

This causes the implant host process to relaunch automatically whenever the current user logs in.

To install: `persist`  
To remove:  `unpersist`

---

## Testing Workflow

1. **Build and start** with `.\setup.ps1` then `.\start_project.bat` (three windows open).

2. **Verify beaconing** — the server window should show periodic `MSG_AGENT_GET_TASK` lines.

3. **Submit a command** in the operator window, e.g.:
   ```
   whoami
   exec ipconfig
   ls C:\Users
   ps
   ```

4. **Retrieve the result:**
   ```
   check <task_id>
   ```
   or just wait and run `history` to see all completed tasks.

5. **File transfer smoke test:**
   ```
   upload C:\Windows\System32\drivers\etc\hosts C:\local\hosts
   download C:\Windows\System32\drivers\etc\hosts
   ```

6. **Token demo:**
   ```
   inspect-token
   enable-privilege SeDebugPrivilege
   impersonate-token <pid>
   ```

7. **Cleanup:**
   ```
   unpersist
   kill
   ```

---

## Cleanup / Uninstall

1. Close all three component windows (or press `Ctrl+C`).
2. Delete `server\server.key` and `server\server.crt` to remove generated credentials.
3. Delete the `build\` directory to remove compiled binaries.

*TODO — document persistence cleanup when implemented.*
