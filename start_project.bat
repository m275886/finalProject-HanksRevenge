@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------------------------------------
:: start_project.bat - Launch Hank's Revenge (C2 server, implant host, operator)
::
:: Usage:
::   start_project.bat            - Start using Debug build (default)
::   start_project.bat Debug      - Start using Debug build
::   start_project.bat Release    - Start using Release build
::
:: Opens three separate terminal windows:
::   1. C2 Server    (Python)  - listens on HTTPS 9001 (implant) and 9002 (operator)
::   2. Implant Host (C/DLL)   - loads Hanks_Revenge.dll and starts beaconing
::   3. Operator     (Python)  - interactive command shell
::
:: Prerequisites:
::   pip install cryptography   (first time only, for TLS cert generation)
:: ---------------------------------------------------------------------------

set "PROJECT_DIR=%~dp0"
set BUILD_CONFIG=Debug

if /i "%1"=="Release" set BUILD_CONFIG=Release
if /i "%1"=="release" set BUILD_CONFIG=Release
if /i "%1"=="DEBUG"   set BUILD_CONFIG=Debug

:: Multi-config generators (VS / Ninja MC) put outputs in build\<Config>\.
:: Single-config generators (NMake) put outputs directly in build\.
set "BUILD_DIR=%PROJECT_DIR%build\%BUILD_CONFIG%"
if not exist "%BUILD_DIR%\HankInitialHost.exe" (
    if exist "%PROJECT_DIR%build\HankInitialHost.exe" (
        set "BUILD_DIR=%PROJECT_DIR%build"
    )
)
set "HOST_EXE=%BUILD_DIR%\HankInitialHost.exe"
set "DLL_PATH=%BUILD_DIR%\Hanks_Revenge.dll"
set "SERVER_KEY=%PROJECT_DIR%server\server.key"
set "SERVER_CRT=%PROJECT_DIR%server\server.crt"
set "SERVER_PY=%PROJECT_DIR%server\server.py"
set "CLIENT_PY=%PROJECT_DIR%server\client.py"
set "GEN_CERTS_PY=%PROJECT_DIR%server\gen_certs.py"

echo.
echo  ============================================================
echo   Hank's Revenge - Start (%BUILD_CONFIG%)
echo  ============================================================
echo.

:: ---- Check build outputs --------------------------------------------------
if not exist "%HOST_EXE%" (
    echo [!] Host executable not found:
    echo     %HOST_EXE%
    echo.
    echo [!] Run rebuild.bat first.
    pause
    exit /b 1
)

if not exist "%DLL_PATH%" (
    echo [!] Implant DLL not found:
    echo     %DLL_PATH%
    echo.
    echo [!] Run rebuild.bat first.
    pause
    exit /b 1
)

:: ---- Generate TLS certificate if missing ---------------------------------
if not exist "%SERVER_CRT%" (
    echo [*] TLS certificate not found.  Generating self-signed cert...
    python "%GEN_CERTS_PY%"
    if %ERRORLEVEL% neq 0 (
        echo.
        echo [!] Certificate generation failed.
        echo [!] Install the dependency and retry:
        echo.
        echo       pip install cryptography
        echo.
        pause
        exit /b 1
    )
    echo.
)

echo [*] Build config : %BUILD_CONFIG%
echo [*] Host EXE     : %HOST_EXE%
echo [*] Implant DLL  : %DLL_PATH%
echo [*] Certificate  : %SERVER_CRT%
echo.

:: ---- Window 1: C2 server --------------------------------------------------
echo [*] Starting C2 server (implant port 9001 / operator port 9002)...
start "Hank's Revenge - C2 Server" cmd /k "cd /d "%PROJECT_DIR%" && python server\server.py"

:: Give the server a moment to bind its ports before the implant connects.
timeout /t 2 /nobreak >nul

:: ---- Window 2: Implant host -----------------------------------------------
echo [*] Starting implant host...
start "Hank's Revenge - Implant Host" cmd /k ""%HOST_EXE%" "%DLL_PATH%" 127.0.0.1 9001"

:: Brief pause so the host prints its startup banner before the operator opens.
timeout /t 1 /nobreak >nul

:: ---- Window 3: Operator client --------------------------------------------
echo [*] Starting operator client...
start "Hank's Revenge - Operator" cmd /k "cd /d "%PROJECT_DIR%" && python server\client.py"

echo.
echo  ============================================================
echo   All components started in separate windows.
echo.
echo   C2 Server    implant HTTPS -> port 9001
echo                operator HTTPS -> port 9002
echo   Implant      beacons to 127.0.0.1:9001 every 5 seconds
echo   Operator     type  help  for available commands
echo.
echo   To stop: close each window or press Ctrl+C inside it.
echo  ============================================================
echo.
endlocal
