@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------------------------------------
:: rebuild.bat - Clean, configure, and build Hank's Revenge
::
:: Usage:
::   rebuild.bat            - Build Debug only (fastest for development)
::   rebuild.bat Release    - Build Debug + Release
::   rebuild.bat All        - Build Debug + Release
:: ---------------------------------------------------------------------------

set "PROJECT_DIR=%~dp0"
set "BUILD_DIR=%PROJECT_DIR%build"

set BUILD_RELEASE=0
if /i "%1"=="Release" set BUILD_RELEASE=1
if /i "%1"=="All"     set BUILD_RELEASE=1

:: 1 = multi-config generator (VS / Ninja MC) supports --config flag
:: 0 = single-config generator (NMake) - build type baked in at configure time
set MULTI_CONFIG=1

echo.
echo  ============================================================
echo   Hank's Revenge - Rebuild
echo  ============================================================
echo.

:: ---- Clean ----------------------------------------------------------------
if exist "%BUILD_DIR%" (
    echo [*] Removing previous build directory...
    rmdir /s /q "%BUILD_DIR%"
)
mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

:: ---- Helper: wipe CMake cache between generator attempts ------------------
:: CMake writes a partial CMakeCache.txt even when configure fails.
:: If we do not delete it, the next generator attempt errors with
:: "Does not match the generator used previously".

if "%~2"=="" (
    echo Error: At least 2 arguments required HOST PORT .
    exit /b 1
)


echo [*] regenerating generated_commands.h and commands.py
python ..\shared\generate_shared_defs.py ../ %1 %2
:: ---- CMake configure - try generators in order ----------------------------
echo [*] Configuring with CMake...
echo.

:: --- Visual Studio 17 (2022) ---
cmake .. -G "Visual Studio 18 2026" -A x64 >nul 2>&1
if %ERRORLEVEL% equ 0 goto :cmake_ok
if exist CMakeCache.txt del /f /q CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles

:: --- Visual Studio 16 (2019) ---
echo [*] VS 2026 not found, trying VS 2019...
cmake .. -G "Visual Studio 16 2022" -A x64 >nul 2>&1
if %ERRORLEVEL% equ 0 goto :cmake_ok
if exist CMakeCache.txt del /f /q CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles


echo [*] Using default CMAKE compiler 
cmake .. -A x64 >nul 2>&1

if %ERRORLEVEL% equ 0 goto :cmake_ok


:: --- Ninja Multi-Config (ships inside every VS install) --------------------
:: In a Developer PowerShell/Command Prompt, ninja.exe is already on PATH.
:: We also search the VS install tree in case the shell was not pre-loaded.
echo [*] VS generators unavailable, trying Ninja Multi-Config...

for %%V in (18 17 16) do (
    for %%E in (Enterprise Professional Community BuildTools Preview) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%V\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" (
            set "PATH=C:\Program Files\Microsoft Visual Studio\%%V\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;!PATH!"
            goto :ninja_path_set
        )
    )
)
:ninja_path_set

cmake .. -G "Ninja Multi-Config" >nul 2>&1
if %ERRORLEVEL% equ 0 goto :cmake_ok
if exist CMakeCache.txt del /f /q CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles

:: --- NMake Makefiles (always present in a Developer shell) -----------------
echo [*] Ninja unavailable, trying NMake Makefiles (Debug only)...
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] All CMake generators failed.
    echo.
    echo     Run this script from a "Developer Command Prompt for VS"
    echo     or "Developer PowerShell for VS" so that cl.exe and
    echo     nmake.exe are on your PATH.
    echo.
    cd /d "%PROJECT_DIR%"
    pause
    exit /b 1
)
echo [*] Using NMake Makefiles - Debug only.
set MULTI_CONFIG=0

:cmake_ok
echo [+] CMake configure succeeded.
echo.




:: ---- Build Debug ----------------------------------------------------------
echo [*] Building Debug...
if %MULTI_CONFIG% equ 1 (
    cmake --build . --config Debug
) else (
    cmake --build .
)
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Debug build failed. Check compiler errors above.
    cd /d "%PROJECT_DIR%"
    pause
    exit /b 1
)
echo [+] Debug build complete.
echo.

:: ---- Build Release (multi-config only) ------------------------------------
if %BUILD_RELEASE% equ 1 (
    if %MULTI_CONFIG% equ 1 (
        echo [*] Building Release...
        cmake --build . --config Release
        if %ERRORLEVEL% neq 0 (
            echo [!] Release build failed.
        ) else (
            echo [+] Release build complete.
        )
        echo.
    ) else (
        echo [*] Skipping Release - NMake is single-config.
        echo.
    )
)

cd /d "%PROJECT_DIR%"

:: ---- Verify output --------------------------------------------------------
echo [*] Build outputs:

:: Multi-config puts binaries in build\Debug\; NMake puts them in build\
set "BIN_DIR=%BUILD_DIR%\Debug"
if not exist "%BIN_DIR%\Hanks_Revenge.dll" set "BIN_DIR=%BUILD_DIR%"

if exist "%BIN_DIR%\Hanks_Revenge.dll" (
    echo     [OK] Hanks_Revenge.dll
) else (
    echo     [!!] Hanks_Revenge.dll  NOT FOUND
)
if exist "%BIN_DIR%\FidelityUpdate.exe" (
    echo     [OK] FidelityUpdate.exe
) else (
    echo     [!!] FidelityUpdate.exe  NOT FOUND
)
echo.

:: ---- Open solution in Visual Studio (VS generators only) -----------------
for %%F in ("%BUILD_DIR%\*.sln") do (
    echo [*] Opening %%~nxF in Visual Studio...
    start "" "%%F"
    goto :opened
)
echo [*] No .sln found (Ninja/NMake build).

:opened
echo.
echo [+] Done.  Run start_project.bat to launch all components.
echo.
endlocal
