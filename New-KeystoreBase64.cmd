@echo off
REM Runs New-KeystoreBase64.ps1 (same folder), bypassing the Execution Policy for this run only.
REM Without arguments the script runs in guided mode. "/?" shows the parameter help.
REM Example: New-KeystoreBase64.cmd -KeystorePath D:\Keys\myapp.p12 -Alias myapp -GitHubRepo myuser/myapp
setlocal
cd /d "%~dp0"

set "PS1=%~dp0New-KeystoreBase64.ps1"
if not exist "%PS1%" if exist "%PS1%.txt" (
    echo Renaming New-KeystoreBase64.ps1.txt to New-KeystoreBase64.ps1
    ren "%PS1%.txt" "New-KeystoreBase64.ps1"
)
if not exist "%PS1%" (
    echo ERROR: New-KeystoreBase64.ps1 not found in "%~dp0"
    set "RC=1"
    goto :end
)

REM Prefer PowerShell 7, otherwise Windows PowerShell 5.1
set "PSEXE=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PSEXE=pwsh.exe"

if "%~1"=="/?" (
    "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Help
) else (
    "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
)
set "RC=%ERRORLEVEL%"

:end
REM Pause only when started by double-click, so the result can be read
echo %cmdcmdline% | find /i "%~nx0" >nul && pause
endlocal & exit /b %RC%
