@echo off
setlocal

rem --- Configuration ---
rem IMPORTANT: This URL points to the install.ps1 script on YOUR GitHub Release.
set "POWERSHELL_SCRIPT_URL=https://github.com/dipesh-m12/CICD-tool/releases/download/cicd_win_v1.0.0/install.ps1"
set "POWERSHELL_SCRIPT_NAME=install.ps1"
set "TEMP_DIR=%TEMP%"
set "DOWNLOAD_PATH=%TEMP_DIR%\%POWERSHELL_SCRIPT_NAME%"

echo.
echo ===================================================================
echo   ✨ CICD Webhook Tool Setup ✨
echo ===================================================================
echo.

rem --- Step 1: Download the PowerShell script ---
echo Downloading setup script from %POWERSHELL_SCRIPT_URL%...
bitsadmin /transfer "DownloadCICDInstaller" /download /priority HIGH %POWERSHELL_SCRIPT_URL% %DOWNLOAD_PATH%
if %errorlevel% neq 0 (
    echo Error: Failed to download %POWERSHELL_SCRIPT_NAME%.
    echo Please check your internet connection or the URL: %POWERSHELL_SCRIPT_URL%
    pause
    goto :eof
)
echo Downloaded %POWERSHELL_SCRIPT_NAME% to %DOWNLOAD_PATH%

echo.
echo --- Step 2: Running the installation script (requires Administrator privileges) ---
echo.
echo This script will now attempt to run with Administrator privileges.
echo Please click "Yes" on the User Account Control (UAC) prompt if it appears.
echo.

rem Launch PowerShell script with elevated privileges
rem -NoProfile: Prevents loading the user's PowerShell profile, for faster execution and consistency.
rem -ExecutionPolicy Bypass: Temporarily bypasses execution policy for this specific script execution.
rem -File: Specifies the script to run.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%DOWNLOAD_PATH%\"'"

if %errorlevel% neq 0 (
    echo.
    echo Error: Failed to launch PowerShell script with Administrator privileges.
    echo Please ensure you clicked 'Yes' on the UAC prompt.
    echo.
)

echo.
echo ===================================================================
echo   Setup process initiated. Please follow the instructions in the
echo   new PowerShell window that should appear.
echo ===================================================================
echo.
pause

endlocal
