@echo off
rem Builds dist\KeyBox.exe with the C# compiler that is part of Windows (.NET Framework 4.x).
rem Nothing has to be installed and nothing is downloaded.
setlocal
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo ERROR: csc.exe was not found. .NET Framework 4.x is required; it is part of Windows 10 and 11.
    exit /b 1
)

if not exist dist mkdir dist

"%CSC%" /nologo /noconfig /target:winexe /platform:anycpu /optimize+ /debug- /warn:4 ^
    /codepage:65001 /utf8output /highentropyva+ ^
    /win32icon:res\app.ico /win32manifest:res\app.manifest ^
    /resource:res\app.ico,KeyBox.app.ico /resource:res\logo.png,KeyBox.logo.png ^
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
    /r:System.Runtime.Serialization.dll /r:System.Xml.dll ^
    /out:dist\KeyBox.exe /recurse:src\*.cs
if errorlevel 1 (
    echo.
    echo BUILD FAILED. If KeyBox is running, close it and try again.
    exit /b 1
)

echo OK: %~dp0dist\KeyBox.exe
