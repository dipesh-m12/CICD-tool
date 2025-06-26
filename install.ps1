# install.ps1
# This script downloads the cicd.exe from a specified URL,
# moves it to C:\Program Files\GoTools, and adds that directory to the PATH.
# It can be used for both initial installation and for updating an existing cicd.exe.

# --- Configuration ---
# The direct download URL for your cicd.exe from GitHub Releases
$downloadUrl = "https://github.com/dipesh-m12/CICD-tool/releases/download/cicd/cicd.exe"
# --- CHANGED: New target directory for installation in Program Files ---
$targetDir = Join-Path ${env:ProgramFiles} "GoTools"
$appName = "cicd.exe" # The name of the executable once downloaded
$downloadedFilePath = Join-Path $env:TEMP $appName # Temporary location for download

# --- IMPORTANT: Check for Administrator Privileges ---
Write-Host "Checking for Administrator privileges..."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges to install software to 'C:\Program Files' and modify system PATH."
    Write-Error "Please right-click on the script file and select 'Run as administrator', or run PowerShell as Administrator and execute the script from there."
    Read-Host "Press Enter to exit..."
    exit 1
}
Write-Host "Running with Administrator privileges. Proceeding with installation."


# --- Step 1: Download the executable ---
Write-Host "Attempting to download '$appName' from $downloadUrl..."
try {
    # Using Invoke-WebRequest for downloading
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadedFilePath -UseBasicParsing
    Write-Host "Download successful: $downloadedFilePath"
} catch {
    Write-Error "Failed to download $appName from $downloadUrl. Please check the URL and your internet connection. Specific error: $_"
    Read-Host "Press Enter to exit..."
    exit 1
}

# --- Step 2: Create target directory if it doesn't exist ---
Write-Host "Checking for $targetDir..."
if (-not (Test-Path $targetDir)) {
    Write-Host "Creating directory: $targetDir"
    try {
        # Creating a directory in Program Files requires Administrator privileges
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    } catch {
        Write-Error "Failed to create directory '$targetDir'. This usually requires Administrator privileges. Specific error: $_"
        Read-Host "Press Enter to exit..."
        exit 1 # Exit on critical failure
    }
} else {
    Write-Host "Target directory '$targetDir' already exists."
}


# --- Step 3: Move the downloaded executable to the target directory ---
$finalTargetPath = Join-Path $targetDir $appName
Write-Host "Moving $appName to $finalTargetPath..."
try {
    # Remove existing file if it exists to ensure clean move/overwrite
    # Removing/moving files in Program Files requires Administrator privileges
    if (Test-Path $finalTargetPath) {
        Write-Host "Existing '$appName' found. Replacing it with the new version."
        Remove-Item -Path $finalTargetPath -Force | Out-Null
    }
    Move-Item -Path $downloadedFilePath -Destination $finalTargetPath -Force
    Write-Host "Successfully moved $appName to $finalTargetPath."
} catch {
    Write-Error "Failed to move $appName to '$targetDir'. This usually requires Administrator privileges or the file might be in use. Specific error: $_"
    Read-Host "Press Enter to exit..."
    exit 1 # Exit on critical failure
}


# --- Step 4: Add the target directory to system's PATH environment variable ---
# IMPORTANT: Modifying the system-wide PATH (HKEY_LOCAL_MACHINE) requires Administrator privileges.
# We will target the System PATH, not User PATH, when installing to Program Files.
Write-Host "Adding $targetDir to system's PATH environment variable..."

# Get the current system PATH. This is stored in HKEY_LOCAL_MACHINE.
# Ensure the script is run with Admin privileges to read/write this.
$registryKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
try {
    $currentPath = Get-ItemProperty -LiteralPath $registryKey -Name "Path" | Select-Object -ExpandProperty Path
} catch {
    Write-Error "Failed to read current system PATH from registry. This requires Administrator privileges. Specific error: $_"
    Read-Host "Press Enter to exit..."
    exit 1 # Exit on critical failure
}

# Check if the target directory is already in the PATH
# Use Regex.Escape to handle special characters in paths correctly
if (-not ($currentPath -like "*$([System.Text.RegularExpressions.Regex]::Escape($targetDir))*")) {
    $newPath = "$currentPath;$targetDir"
    
    try {
        # Set the system-wide PATH. This requires Administrator privileges.
        Set-ItemProperty -LiteralPath $registryKey -Name "Path" -Value $newPath -Force
        Write-Host "System PATH updated successfully."

        # Broadcast message to notify other processes about the environment change
        # This part helps new cmd/PowerShell windows pick up the change without a full reboot.
        # Fixed wParam type issue (0 -> [UIntPtr]::Zero)
        $signature = @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out IntPtr lpdwResult);
'@
        $type = Add-Type -MemberDefinition $signature -Name "Win32" -Namespace "Env" -PassThru
        $HWND_BROADCAST = [IntPtr]0xFFFF
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [IntPtr]::Zero # Changed 0 to [IntPtr]::Zero
        try {
            $type::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", $SMTO_ABORTIFHUNG, 5000, [ref]$result) # Corrected wParam
            Write-Host "Broadcasted WM_SETTINGCHANGE message to refresh environment variables."
        } catch {
            Write-Warning "Failed to broadcast WM_SETTINGCHANGE message. Environment variables might require a full restart to apply. Specific error: $_"
        }

    } catch {
        Write-Error "Failed to update system PATH. This definitely requires Administrator privileges. Specific error: $_"
        Read-Host "Press Enter to exit..."
        exit 1 # Exit on critical failure
    }
} else {
    Write-Host "$targetDir is already in the system PATH. No changes made."
}

# --- Final Instructions ---
Write-Host "`n=========================================================="
Write-Host "  ✨ CICD Webhook Tool Installation Complete! ✨"
Write-Host "=========================================================="
Write-Host "You can now run 'cicd' from any Command Prompt or PowerShell window."
Write-Host "`nIMPORTANT: Please close and reopen ALL Command Prompt or PowerShell windows"
Write-Host "for the changes to the PATH environment variable to take effect."
Write-Host "`nTo verify, open a NEW terminal and type: cicd list"
Write-Host "`nIf you encounter issues, ensure this script was run as Administrator."
Write-Host "=========================================================="

Read-Host "Press Enter to exit..."
