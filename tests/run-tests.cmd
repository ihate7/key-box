@echo off
rem Builds and runs all KeyBox tests. Exit code 0 means everything passed.
rem
rem   tests\run-tests.cmd            core tests + UI tests (windows stay off-screen)
rem   tests\run-tests.cmd core       core tests only (crypto, file format, data model)
rem   tests\run-tests.cmd visible    UI tests with windows shown on screen (for screenshots)
rem
rem Output goes to tests\out (safe to delete).
setlocal
cd /d "%~dp0.."

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo ERROR: csc.exe was not found. .NET Framework 4.x is required; it is part of Windows 10 and 11.
    exit /b 1
)

set "OUT=tests\out"
if not exist "%OUT%" mkdir "%OUT%"
set "REFS=/r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Runtime.Serialization.dll /r:System.Xml.dll"
set "FAILED=0"

echo === Core tests ===
"%CSC%" /nologo /noconfig /target:exe /platform:anycpu /optimize+ /warn:4 /codepage:65001 /utf8output %REFS% ^
    /out:%OUT%\CoreTests.exe src\L.cs /recurse:src\Crypto\*.cs /recurse:src\Vault\*.cs tests\CoreTests.cs
if errorlevel 1 exit /b 1

rem An independent implementation of the file format (Node.js, standard crypto module only)
rem writes a vault for KeyBox to open and then opens the vault written by KeyBox.
set "HAVE_NODE=0"
where node >nul 2>nul && set "HAVE_NODE=1"
if "%HAVE_NODE%"=="1" (
    node tests\interop.js write %OUT%\node.vault || set "FAILED=1"
) else (
    if exist %OUT%\node.vault del %OUT%\node.vault
    echo note: Node.js not found, the cross-implementation check is skipped
)

%OUT%\CoreTests.exe %OUT% || set "FAILED=1"

if "%HAVE_NODE%"=="1" (
    node tests\interop.js verify %OUT%\cs.vault || set "FAILED=1"
)

if /i "%~1"=="core" goto done

echo.
echo === UI tests ===
"%CSC%" /nologo /noconfig /target:exe /platform:anycpu /optimize+ /warn:4 /codepage:65001 /utf8output %REFS% ^
    /main:KeyBox.Tests.UiTests /win32manifest:res\app.manifest ^
    /resource:res\app.ico,KeyBox.app.ico /resource:res\logo.png,KeyBox.logo.png ^
    /out:%OUT%\UiTests.exe /recurse:src\*.cs tests\UiTests.cs tests\IsolatedDesktop.cs
if errorlevel 1 exit /b 1

if /i "%~1"=="visible" (
    %OUT%\UiTests.exe %OUT%\ui --visible || set "FAILED=1"
) else (
    %OUT%\UiTests.exe %OUT%\ui || set "FAILED=1"
)

:done
echo.
if "%FAILED%"=="1" (
    echo SOME TESTS FAILED
    exit /b 1
)
echo ALL TESTS PASSED
exit /b 0
