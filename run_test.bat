```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================
REM Certificate Generator Test Script
REM ============================================================

cd /d "%~dp0"

set "PYTHON=python"
set "SCRIPT=cert_gen.py"
set "CONFIG=input.json"

REM OpenSSL path
set "OPENSSL=C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

REM Test output
set "TEST_ROOT=test_output"

echo.
echo ============================================================
echo        ECDSA P-256 Certificate Generator Test
echo ============================================================
echo.

REM ============================================================
REM 1. Check Python
REM ============================================================

echo [CHECK] Python...

%PYTHON% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not available.
    pause
    exit /b 1
)

%PYTHON% --version
echo.

REM ============================================================
REM 2. Check cert_gen.py
REM ============================================================

if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% not found.
    pause
    exit /b 1
)

REM ============================================================
REM 3. Check input.json
REM ============================================================

if not exist "%CONFIG%" (
    echo [ERROR] %CONFIG% not found.
    pause
    exit /b 1
)

REM ============================================================
REM 4. Check OpenSSL
REM ============================================================

echo [CHECK] OpenSSL...

if not exist "%OPENSSL%" (
    echo [ERROR] OpenSSL not found:
    echo         %OPENSSL%
    echo.
    echo Please update OPENSSL in this BAT file.
    pause
    exit /b 1
)

"%OPENSSL%" version

if errorlevel 1 (
    echo [ERROR] OpenSSL execution failed.
    pause
    exit /b 1
)

echo.

REM ============================================================
REM 5. Clean previous test output
REM ============================================================

echo [CLEAN] Removing previous test output...

if exist "%TEST_ROOT%" (
    rmdir /s /q "%TEST_ROOT%"
)

mkdir "%TEST_ROOT%"

echo.

REM ============================================================
REM 6. CASE 1 - GENERATE
REM ============================================================

echo ============================================================
echo CASE 1: GENERATE
echo ============================================================
echo.

echo [RUN] Generate Root + IMI + Device...

%PYTHON% "%SCRIPT%" generate ^
    --config "%CONFIG%" ^
    --output "%TEST_ROOT%\generate" ^
    --openssl "%OPENSSL%"

if errorlevel 1 (
    echo.
    echo [FAILED] CASE 1 - GENERATE
    pause
    exit /b 1
)

echo.
echo [PASSED] CASE 1 - GENERATE
echo.

REM ============================================================
REM Check generated files
REM ============================================================

if not exist "%TEST_ROOT%\generate\root\root.crt" goto FILE_ERROR
if not exist "%TEST_ROOT%\generate\root\root.key" goto FILE_ERROR

if not exist "%TEST_ROOT%\generate\imi\imi.crt" goto FILE_ERROR
if not exist "%TEST_ROOT%\generate\imi\imi.key" goto FILE_ERROR

if not exist "%TEST_ROOT%\generate\device\device.crt" goto FILE_ERROR
if not exist "%TEST_ROOT%\generate\device\device.key" goto FILE_ERROR

REM ============================================================
REM 7. CASE 2 - REPLACE ALL
REM ============================================================

echo ============================================================
echo CASE 2: REPLACE-ALL
echo ============================================================
echo.

echo [RUN] Replace Root + IMI + Device...
echo.

%PYTHON% "%SCRIPT%" replace-all ^
    --config "%CONFIG%" ^
    --output "%TEST_ROOT%\replace-all" ^
    --openssl "%OPENSSL%" ^
    --old-root-cert "%TEST_ROOT%\generate\root\root.crt" ^
    --old-root-key "%TEST_ROOT%\generate\root\root.key"

if errorlevel 1 (
    echo.
    echo [FAILED] CASE 2 - REPLACE-ALL
    pause
    exit /b 1
)

echo.
echo [PASSED] CASE 2 - REPLACE-ALL
echo.

REM ============================================================
REM 8. CASE 3 - REPLACE IMI + DEVICE
REM ============================================================

echo ============================================================
echo CASE 3: REPLACE-IMI-DEVICE
echo ============================================================
echo.

echo [RUN] Replace IMI + Device...
echo.

%PYTHON% "%SCRIPT%" replace-imi-device ^
    --config "%CONFIG%" ^
    --output "%TEST_ROOT%\replace-imi-device" ^
    --openssl "%OPENSSL%" ^
    --old-root-cert "%TEST_ROOT%\generate\root\root.crt" ^
    --old-root-key "%TEST_ROOT%\generate\root\root.key"

if errorlevel 1 (
    echo.
    echo [FAILED] CASE 3 - REPLACE-IMI-DEVICE
    pause
    exit /b 1
)

echo.
echo [PASSED] CASE 3 - REPLACE-IMI-DEVICE
echo.

REM ============================================================
REM 9. CASE 4 - REPLACE DEVICE
REM ============================================================

echo ============================================================
echo CASE 4: REPLACE-DEVICE
echo ============================================================
echo.

echo [RUN] Replace Device only...
echo.

%PYTHON% "%SCRIPT%" replace-device ^
    --config "%CONFIG%" ^
    --output "%TEST_ROOT%\replace-device" ^
    --openssl "%OPENSSL%" ^
    --old-root-cert "%TEST_ROOT%\generate\root\root.crt" ^
    --old-root-key "%TEST_ROOT%\generate\root\root.key" ^
    --old-imi-cert "%TEST_ROOT%\generate\imi\imi.crt" ^
    --old-imi-key "%TEST_ROOT%\generate\imi\imi.key"

if errorlevel 1 (
    echo.
    echo [FAILED] CASE 4 - REPLACE-DEVICE
    pause
    exit /b 1
)

echo.
echo [PASSED] CASE 4 - REPLACE-DEVICE
echo.

REM ============================================================
REM 10. TEST RESULT
REM ============================================================

echo.
echo ============================================================
echo                 ALL TESTS PASSED
echo ============================================================
echo.
echo Test output:
echo.
echo %TEST_ROOT%\generate
echo %TEST_ROOT%\replace-all
echo %TEST_ROOT%\replace-imi-device
echo %TEST_ROOT%\replace-device
echo.

echo Certificate chains:
echo.
echo [GENERATE]
echo   Root
echo    |
echo   IMI
echo    |
echo   Device
echo.

echo [REPLACE-ALL]
echo   OLD Root
echo      |
echo   Root Link
echo      |
echo   NEW Root
echo      |
echo   NEW IMI
echo      |
echo   NEW Device
echo.

echo [REPLACE-IMI-DEVICE]
echo   OLD Root
echo      |
echo   NEW IMI
echo      |
echo   NEW Device
echo.

echo [REPLACE-DEVICE]
echo   OLD Root
echo      |
echo   OLD IMI
echo      |
echo   NEW Device
echo.

pause
exit /b 0


REM ============================================================
REM Error handlers
REM ============================================================

:FILE_ERROR

echo.
echo [ERROR] Expected generated certificate/key file not found.
echo.
echo Please check the output directory:
echo %TEST_ROOT%
echo.
pause
exit /b 1
```
