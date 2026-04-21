# setup.ps1 - One-time environment setup for Hank's Revenge
#
# Works from ANY PowerShell window - regular, Developer, or ISE.
# Automatically locates Visual Studio, CMake, and cl.exe via vswhere.
#
# Usage:
#   cd C:\...\finalProject-HanksRevenge
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\setup.ps1
#
# What it does:
#   1. Finds Visual Studio via vswhere.exe
#   2. Imports the VS build environment (cmake + cl.exe) into this session
#   3. Installs the cryptography Python package
#   4. Configures CMake and builds the Debug DLL + host EXE
#   5. Generates the self-signed TLS certificate
#   6. Prints next steps

$ProjectDir = $PSScriptRoot
$BuildDir   = Join-Path $ProjectDir "build"
$ServerDir  = Join-Path $ProjectDir "server"
$CertFile   = Join-Path $ServerDir  "server.crt"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Hank's Revenge - Setup"                                     -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Locate Visual Studio with vswhere and import its build environment
# ---------------------------------------------------------------------------

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $vswhere)) {
    Write-Host "[!] vswhere.exe not found at:" -ForegroundColor Red
    Write-Host "    $vswhere"
    Write-Host ""
    Write-Host "    Visual Studio does not appear to be installed."
    Write-Host "    Install VS 2022 with the 'Desktop development with C++' workload."
    exit 1
}

Write-Host "[*] Locating Visual Studio installation ..."
$vsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null

if (-not $vsInstallPath) {
    Write-Host "[!] No Visual Studio installation with C++ tools found." -ForegroundColor Red
    Write-Host "    Run the Visual Studio Installer and add the"
    Write-Host "    'Desktop development with C++' workload."
    exit 1
}

Write-Host "[+] Found VS at: $vsInstallPath" -ForegroundColor Green

# Import the x64 native build environment from vcvars64.bat into this
# PowerShell session by running it in cmd and capturing the resulting env vars.
$vcvars = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    Write-Host "[!] vcvars64.bat not found: $vcvars" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Importing VS build environment (vcvars64.bat) ..."
$envDump = cmd /c "`"$vcvars`" >nul 2>&1 && set"
foreach ($line in $envDump) {
    if ($line -match "^([^=]+)=(.*)$") {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
Write-Host "[+] VS build environment loaded." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Verify cmake and cl.exe are now reachable
# ---------------------------------------------------------------------------

function Require-Command($name, $hint) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "[!] '$name' still not found after loading VS environment." -ForegroundColor Red
        Write-Host "    $hint"
        exit 1
    }
    $ver = (& $name --version 2>&1 | Select-Object -First 1) -replace "`n",""
    Write-Host "[+] $name : $ver" -ForegroundColor Green
}

Require-Command "cmake"  "Ensure 'C++ CMake tools for Windows' is installed via the VS Installer."
Require-Command "cl"     "Ensure 'MSVC v143 - VS 2022 C++ x64/x86 build tools' is installed."

# Python check (not part of VS - must be on system PATH)
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] 'python' not found." -ForegroundColor Red
    Write-Host "    Install Python 3 from https://python.org and check 'Add to PATH'."
    exit 1
}
$pyVer = python --version 2>&1
Write-Host "[+] python : $pyVer" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 3. Install Python dependency
# ---------------------------------------------------------------------------

Write-Host "[*] Installing Python dependency: cryptography ..."
python -m pip install cryptography --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] pip install failed. Check your Python/pip setup." -ForegroundColor Red
    exit 1
}
Write-Host "[+] cryptography package ready." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 4. CMake configure + Debug build
# ---------------------------------------------------------------------------

Write-Host "[*] Configuring CMake ..."
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path $BuildDir | Out-Null
Push-Location $BuildDir

# Helper: wipe CMake cache so the next generator attempt starts clean.
# CMake writes a partial CMakeCache.txt even on failure; without this
# cleanup the next attempt aborts with "generator does not match".
function Clear-CMakeCache {
    if (Test-Path "CMakeCache.txt") { Remove-Item "CMakeCache.txt" -Force }
    if (Test-Path "CMakeFiles")     { Remove-Item "CMakeFiles" -Recurse -Force }
}

$multiConfig = $true

# --- VS 17 (2022) ---
cmake .. -G "Visual Studio 17 2022" -A x64 2>$null
if ($LASTEXITCODE -ne 0) {
    Clear-CMakeCache

    # --- VS 16 (2019) ---
    Write-Host "[*] VS 2022 not found, trying VS 2019 ..."
    cmake .. -G "Visual Studio 16 2019" -A x64 2>$null
}
if ($LASTEXITCODE -ne 0) {
    Clear-CMakeCache

    # --- Ninja Multi-Config (bundled inside VS; on PATH in Dev PS) ---
    Write-Host "[*] VS generators unavailable, trying Ninja Multi-Config ..."

    # Add ninja from the VS install tree if not already on PATH
    foreach ($ver in @(18, 17, 16)) {
        foreach ($ed in @("Enterprise","Professional","Community","BuildTools","Preview")) {
            $nj = "C:\Program Files\Microsoft Visual Studio\$ver\$ed\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
            if (Test-Path "$nj\ninja.exe") {
                $env:PATH = "$nj;$env:PATH"
                break
            }
        }
        if (Get-Command ninja -ErrorAction SilentlyContinue) { break }
    }

    cmake .. -G "Ninja Multi-Config" 2>$null
}
if ($LASTEXITCODE -ne 0) {
    Clear-CMakeCache

    # --- NMake Makefiles (always present in a Developer shell) ---
    Write-Host "[*] Ninja unavailable, trying NMake Makefiles (Debug only) ..."
    cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug
    $multiConfig = $false
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] CMake configure failed. Run from a Developer PowerShell for VS." -ForegroundColor Red
    Pop-Location; exit 1
}

Write-Host ""
Write-Host "[*] Building Debug ..."
if ($multiConfig) {
    cmake --build . --config Debug
} else {
    cmake --build .
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed. Check compiler errors above." -ForegroundColor Red
    Pop-Location; exit 1
}
Pop-Location

# Verify outputs - multi-config: build\Debug\; NMake: build\
$debugDir = Join-Path $BuildDir "Debug"
if (-not (Test-Path (Join-Path $debugDir "Hanks_Revenge.dll"))) {
    $debugDir = $BuildDir   # NMake single-config layout
}
$dll = Join-Path $debugDir "Hanks_Revenge.dll"
$exe = Join-Path $debugDir "HankInitialHost.exe"
foreach ($f in @($dll, $exe)) {
    if (Test-Path $f) {
        Write-Host "[+] $(Split-Path $f -Leaf) built successfully." -ForegroundColor Green
    } else {
        Write-Host "[!] Expected output not found: $f" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# ---------------------------------------------------------------------------
# 5. TLS certificate
# ---------------------------------------------------------------------------

if (-not (Test-Path $CertFile)) {
    Write-Host "[*] Generating self-signed TLS certificate ..."
    python (Join-Path $ServerDir "gen_certs.py")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Certificate generation failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Certificate generated." -ForegroundColor Green
} else {
    Write-Host "[+] TLS certificate already present." -ForegroundColor Green
}
Write-Host ""

# ---------------------------------------------------------------------------
# 6. Done
# ---------------------------------------------------------------------------

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Setup complete.  To start the project:"                     -ForegroundColor Cyan
Write-Host ""
Write-Host "    .\start_project.bat"
Write-Host ""
Write-Host "  Or manually in three terminals:"
Write-Host "    python server\server.py"
$binDir = if (Test-Path (Join-Path $BuildDir "Debug\HankInitialHost.exe")) { "build\Debug" } else { "build" }
Write-Host "    $binDir\HankInitialHost.exe $binDir\Hanks_Revenge.dll 127.0.0.1 9001"
Write-Host "    python server\client.py"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
