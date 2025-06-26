# install.ps1
# This script downloads the cicd.exe from a specified URL,
# moves it to a user's GoTools directory, and adds that directory to the PATH.
# It can be used for both initial installation and for updating an existing cicd.exe.

# --- Configuration ---
# The direct download URL for your cicd.exe from GitHub Releases
$downloadUrl = "https://github.com/dipesh-m12/CICD-tool/releases/download/cicd/cicd.exe"
$targetDir = Join-Path $env:USERPROFILE "GoTools"
$appName = "cicd.exe" # The name of the executable once downloaded
$downloadedFilePath = Join-Path $env:TEMP $appName # Temporary location for download

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
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    } catch {
        Write-Error "Failed to create directory: $_"
        Read-Host "Press Enter to exit..."
        exit 1
    }
}

# --- Step 3: Move the downloaded executable to the target directory ---
$finalTargetPath = Join-Path $targetDir $appName
Write-Host "Moving $appName to $finalTargetPath..."
try {
    # Remove existing file if it exists to ensure clean move/overwrite
    if (Test-Path $finalTargetPath) {
        Write-Host "Existing '$appName' found. Replacing it with the new version."
        Remove-Item -Path $finalTargetPath -Force | Out-Null
    }
    Move-Item -Path $downloadedFilePath -Destination $finalTargetPath -Force
    Write-Host "Successfully moved $appName to $finalTargetPath."
} catch {
    Write-Error "Failed to move $appName to $targetDir. Check permissions or if the file is in use. Specific error: $_"
    Read-Host "Press Enter to exit..."
    exit 1
}

# --- Step 4: Add the target directory to user's PATH environment variable ---
Write-Host "Adding $targetDir to user's PATH environment variable..."
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

# Check if the target directory is already in the PATH
# Use Regex.Escape to handle special characters in paths correctly
if (-not ($currentPath -like "*$([System.Text.RegularExpressions.Regex]::Escape($targetDir))*")) {
    $newPath = "$currentPath;$targetDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Path updated successfully."
} else {
    Write-Host "$targetDir is already in the user's PATH. No changes made."
}

# --- Final Instructions ---
Write-Host "`n=========================================================="
Write-Host "  ✨ CICD Webhook Tool Installation Complete! ✨"
Write-Host "=========================================================="
Write-Host "You can now run 'cicd' from any Command Prompt or PowerShell window."
Write-Host "`nIMPORTANT: Please close and reopen ALL Command Prompt or PowerShell windows"
Write-Host "for the changes to the PATH environment variable to take effect."
Write-Host "`nTo verify, open a NEW terminal and type: cicd list"
Write-Host "`nIf you encounter issues, ensure PowerShell has execution policy set:"
Write-Host "  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
Write-Host "=========================================================="

Read-Host "Press Enter to exit..."
