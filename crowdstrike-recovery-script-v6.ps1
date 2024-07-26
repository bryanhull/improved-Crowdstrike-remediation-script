#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CrowdStrike Recovery Tool V5
.DESCRIPTION
    This script automates the creation of a bootable USB recovery key or ISO image
    to resolve issues caused by CrowdStrike deleting a critical kernel file.
.NOTES
    File Name      : CrowdStrikeRecoveryV5.ps1
    Author         : Improved by AI Assistant
    Prerequisite   : PowerShell 5.1 or later, Windows 10 or later
    Copyright 2024 - Licensed under MIT License
#>

# Strict mode and error preferences
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import required modules
Import-Module BitsTransfer, Dism -ErrorAction Stop

# Script Variables
$script:ADKInstallLocation = "${env:ProgramFiles(x86)}\Windows Kits\10"
$script:ADKInstaller = "$env:TEMP\ADKSetup.exe"
$script:ADKWinPEAddOnInstaller = "$env:TEMP\adkwinpesetup.exe"
$script:WinPEMountLocation = "$env:TEMP\WinPEMountLocation"
$script:RecoveryImageLocation = "$env:TEMP\MsftRecoveryToolForCS.iso"
$script:LogFile = "$env:TEMP\CrowdStrikeRecoveryTool.log"

# Function to log messages
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $script:LogFile
    Write-Host $Message
}

# Function to handle errors
function Handle-Error {
    param ([string]$ErrorMessage)
    Write-Log "ERROR: $ErrorMessage"
    Write-Host "An error occurred. Please check the log file at $script:LogFile for details." -ForegroundColor Red
    if (Test-Path $script:WinPEMountLocation) {
        Dismount-WindowsImage -Path $script:WinPEMountLocation -Discard -ErrorAction SilentlyContinue
    }
    Exit 1
}

# Function to download file with progress
function Download-FileWithProgress {
    param (
        [string]$Url,
        [string]$OutFile
    )
    Write-Log "Downloading $Url to $OutFile"
    try {
        $job = Start-BitsTransfer -Source $Url -Destination $OutFile -DisplayName "Downloading $(Split-Path $OutFile -Leaf)" -Asynchronous

        while (($job.JobState -eq "Transferring") -or ($job.JobState -eq "Connecting")) {
            $progress = [Math]::Round(($job.BytesTransferred / $job.BytesTotal) * 100, 2)
            Write-Progress -Activity $job.DisplayName -Status "$progress% Complete" -PercentComplete $progress
            Start-Sleep -Seconds 1
        }

        switch($job.JobState) {
            "Transferred" {
                Complete-BitsTransfer -BitsJob $job
                Write-Log "Download completed successfully"
            }
            "Error" {
                $job | Format-List
                throw "An error occurred during download"
            }
        }
    }
    catch {
        Write-Log "Error occurred during download: $_"
        throw
    }
    finally {
        Remove-BitsTransfer -BitsJob $job -ErrorAction SilentlyContinue
    }
}

# Updated Function to verify file hash
function Verify-FileHash {
    param (
        [string]$FilePath,
        [string]$ExpectedHash
    )
    Write-Host "Verifying file hash for $FilePath..." -ForegroundColor Yellow
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    Write-Host "Expected hash: $ExpectedHash" -ForegroundColor Cyan
    Write-Host "Actual hash:   $actualHash" -ForegroundColor Cyan
    
    if ($actualHash -ne $ExpectedHash) {
        Write-Host "WARNING: File hash mismatch detected!" -ForegroundColor Red
        Write-Log "WARNING: File hash mismatch for $FilePath"
        Write-Log "Expected: $ExpectedHash"
        Write-Log "Actual: $actualHash"
        return $false
    }
    Write-Host "Hash verification successful." -ForegroundColor Green
    return $true
}

# Updated Function to install ADK
function Install-ADK {
    Write-Log "Checking if ADK is installed..."
    $ADKInstalled = Test-Path -Path "$script:ADKInstallLocation\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"
    if ($ADKInstalled) {
        Write-Log "ADK is already installed."
        Write-Host "ADK is already installed." -ForegroundColor Green
        return
    }
    
    Write-Log "Downloading and installing ADK..."
    Write-Host "Downloading ADK installer..." -ForegroundColor Yellow
    Download-FileWithProgress -Url "https://go.microsoft.com/fwlink/?linkid=2196127" -OutFile $script:ADKInstaller
    
    $hashVerified = Verify-FileHash -FilePath $script:ADKInstaller -ExpectedHash "35B10F5B01F4D0CF724BEFD9F7D0F89F6E6A66CE10872C8999F95BADCB8084C9"
    if (-not $hashVerified) {
        $continue = Read-Host "File hash verification failed. Do you want to continue anyway? (Y/N)"
        if ($continue.ToUpper() -ne "Y") {
            throw "Installation aborted due to hash mismatch."
        }
        Write-Host "Continuing installation despite hash mismatch." -ForegroundColor Yellow
        Write-Log "Continuing installation despite hash mismatch."
    }
    
    $ceip = Read-Host "Allow Microsoft to collect insights for Windows Kits? (Y/N)"
    $ceipArg = if ($ceip.ToUpperInvariant() -eq 'Y') { "/ceip on" } else { "/ceip off" }
    
    Write-Host "Installing ADK..." -ForegroundColor Yellow
    Start-Process -FilePath $script:ADKInstaller -ArgumentList "/features", "+", "OptionId.DeploymentTools", "/quiet", $ceipArg -Wait -NoNewWindow
    Write-Host "ADK installed successfully." -ForegroundColor Green
    Write-Log "ADK installed successfully."
}

# Function to install ADK WinPE Add-on
function Install-ADKWinPEAddOn {
    Write-Log "Checking if ADK WinPE add-on is installed..."
    $ADKWinPEInstalled = Test-Path -Path "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment"
    if ($ADKWinPEInstalled) {
        Write-Log "ADK WinPE add-on is already installed."
        return
    }
    
    Write-Log "Downloading and installing ADK WinPE add-on..."
    Download-FileWithProgress -Url "https://go.microsoft.com/fwlink/?linkid=2196224" -OutFile $script:ADKWinPEAddOnInstaller
    
    Verify-FileHash -FilePath $script:ADKWinPEAddOnInstaller -ExpectedHash "D2E2CAA52C0F6F015A16131BD03FAC5116FB62CF74A9E94FDA5C2A39DFAE8CC8"
    
    Start-Process -FilePath $script:ADKWinPEAddOnInstaller -ArgumentList "/features", "+", "OptionId.WindowsPreinstallationEnvironment", "/quiet" -Wait -NoNewWindow
    Write-Log "ADK WinPE add-on installed successfully."
}

# Function to create and mount WinPE image
function Create-AndMountWinPEImage {
    Write-Log "Creating and mounting WinPE image..."
    $winpeRoot = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment"
    $winpeWim = "$winpeRoot\amd64\en-us\winpe.wim"

    if (-not (Test-Path $script:WinPEMountLocation)) {
        New-Item -Path $script:WinPEMountLocation -ItemType Directory -Force | Out-Null
    }

    Mount-WindowsImage -ImagePath $winpeWim -Index 1 -Path $script:WinPEMountLocation
    Write-Log "WinPE image mounted successfully."
}

# Function to create recovery scripts
function Create-RecoveryScripts {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet(1, 2)]
        [int]$Option
    )

    $CSRemediationScriptPath = "$script:WinPEMountLocation\CSRemediationScript.bat"
    $RepairCmdFile = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\Media\repair.cmd"

    Remove-Item -Path $CSRemediationScriptPath, $RepairCmdFile -ErrorAction SilentlyContinue

    if ($Option -eq 2) {
        # Safe mode boot option
        @"
@echo off
echo Configuring system to boot in safe mode...
bcdedit /set {default} safeboot network
if %errorlevel% equ 0 (
    echo System configured to boot in Safe Mode.
    echo IMPORTANT: Restore original boot order if changed and remove USB/bootable device to prevent BitLocker recovery.
) else (
    echo Failed to configure safe mode.
)
pause
exit
"@ | Out-File -FilePath $CSRemediationScriptPath -Encoding ascii

        @"
@echo off
echo Removing impacted files and restoring normal boot...
del /f /q %SystemRoot%\System32\drivers\CrowdStrike\C-00000291*.sys
bcdedit /deletevalue {current} safeboot
echo System will reboot now.
pause
shutdown /r /t 0
"@ | Out-File -FilePath $RepairCmdFile -Encoding ascii
    } else {
        # Direct remediation option
        @"
@echo off
set drive=C:
echo Attempting remediation on %drive%
echo For BitLocker recovery key, visit: https://aka.ms/aadrecoverykey
manage-bde -protectors %drive% -get
set /p reckey="Enter BitLocker recovery key if prompted: "
if not "%reckey%"=="" manage-bde -unlock %drive% -recoverypassword %reckey%
del /f /q %drive%\Windows\System32\drivers\CrowdStrike\C-00000291*.sys
echo Remediation complete.
pause
"@ | Out-File -FilePath $CSRemediationScriptPath -Encoding ascii
    }

    @"
[LaunchApps]
%SYSTEMDRIVE%\Windows\system32\cmd.exe /k %SYSTEMDRIVE%\CSRemediationScript.bat
"@ | Out-File -FilePath "$script:WinPEMountLocation\Windows\system32\winpeshl.ini" -Encoding ascii

    Write-Log "Recovery scripts created successfully."
}

# Function to add necessary packages to WinPE
function Add-WinPEPackages {
    Write-Log "Checking and adding packages to WinPE..."
    $packages = @("WinPE-WMI", "WinPE-SecureStartup", "WinPE-Scripting", "WinPE-PowerShell")
    
    # Get list of installed packages
    $installedPackages = Get-WindowsPackage -Path $script:WinPEMountLocation | Select-Object -ExpandProperty PackageName
    
    foreach ($package in $packages) {
        $packagePath = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\$package.cab"
        $packageLangPath = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\en-us\$package`_en-us.cab"
        
        if ($installedPackages -notcontains $package) {
            try {
                Add-WindowsPackage -Path $script:WinPEMountLocation -PackagePath $packagePath -ErrorAction Stop
                Write-Log "Successfully added package: $package"
            }
            catch {
                Write-Log "Failed to add package $package. Error: $_"
            }
        }
        else {
            Write-Log "Package $package is already installed. Skipping."
        }
        
        # Check and add language package
        if ($installedPackages -notcontains "$package`_en-us") {
            try {
                Add-WindowsPackage -Path $script:WinPEMountLocation -PackagePath $packageLangPath -ErrorAction Stop
                Write-Log "Successfully added language package: $package`_en-us"
            }
            catch {
                Write-Log "Failed to add language package $package`_en-us. Error: $_"
            }
        }
        else {
            Write-Log "Language package $package`_en-us is already installed. Skipping."
        }
    }
    Write-Log "WinPE packages processing completed."
}

# Function to add drivers to WinPE
function Add-WinPEDrivers {
    $addDrivers = Read-Host "Add drivers to WinPE? (Y/N)"
    if ($addDrivers.ToUpperInvariant() -eq 'Y') {
        $driverPath = Read-Host "Enter path to driver folder"
        if (Test-Path $driverPath) {
            Write-Log "Adding drivers from $driverPath..."
            try {
                Add-WindowsDriver -Path $script:WinPEMountLocation -Driver $driverPath -Recurse
                Write-Log "Drivers added successfully."
            }
            catch {
                Write-Log "Failed to add drivers. Error: $_"
            }
        } else {
            Write-Log "Invalid driver path. Skipping driver addition."
        }
    }
}

# Function to unmount WinPE image
function Unmount-WinPEImage {
    Write-Log "Unmounting WinPE image..."
    try {
        Dismount-WindowsImage -Path $script:WinPEMountLocation -Save
        Write-Log "WinPE image unmounted successfully."
    }
    catch {
        Write-Log "Failed to unmount WinPE image. Error: $_"
        throw
    }
}

# Function to create recovery media
function Create-RecoveryMedia {
    $mediaType = Read-Host "Create ISO [1] or USB [2]?"
    
    if ($mediaType -eq '2') {
        $usbDrive = Read-Host "Enter USB drive letter (e.g., E:)"
        if (-not (Test-Path $usbDrive)) {
            throw "Invalid drive letter or drive not found."
        }

        $usbVolume = Get-Volume -DriveLetter $usbDrive[0]
        if ($usbVolume.Size -gt 32GB) {
            throw "USB drives larger than 32GB are not supported."
        }

        Write-Log "Formatting USB drive..."
        Format-Volume -DriveLetter $usbDrive[0] -FileSystem FAT32 -Force

        Write-Log "Creating bootable USB..."
        $winPERoot = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment"
        & "$winPERoot\amd64\MakeWinPEMedia.cmd" /UFD /F $script:WinPEMountLocation $usbDrive
    } else {
        Write-Log "Creating ISO..."
        $winPERoot = "$script:ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment"
        & "$winPERoot\amd64\MakeWinPEMedia.cmd" /ISO /F $script:WinPEMountLocation $script:RecoveryImageLocation
    }
    Write-Log "Recovery media created successfully."
}

    # Function to clean up temporary files
function Cleanup-TempFiles {
    Write-Log "Cleaning up temporary files..."
    Remove-Item -Path $script:WinPEMountLocation -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path $script:ADKInstaller, $script:ADKWinPEAddOnInstaller -Force -ErrorAction SilentlyContinue
}

# Main execution
try {
    Write-Log "Starting CrowdStrike Recovery Tool V5..."

    Install-ADK
    Install-ADKWinPEAddOn

    Create-AndMountWinPEImage

    do {
        $recoveryOption = Read-Host "Choose recovery option: [1] Direct remediation or [2] Safe mode boot"
    } while ($recoveryOption -notin '1','2')

    Create-RecoveryScripts -Option ([int]$recoveryOption)

    Add-WinPEPackages
    Add-WinPEDrivers

    Unmount-WinPEImage

    Create-RecoveryMedia

    Cleanup-TempFiles

    Write-Log "CrowdStrike Recovery Tool V5 completed successfully."
    Write-Host "Recovery media creation complete. Please check the log file at $script:LogFile for details." -ForegroundColor Green
}
catch {
    Handle-Error "An unexpected error occurred: $_"
}
finally {
    if (Test-Path $script:WinPEMountLocation) {
        Write-Log "Attempting to dismount WinPE image in cleanup..."
        try {
            Dismount-WindowsImage -Path $script:WinPEMountLocation -Discard -ErrorAction Stop
            Write-Log "WinPE image dismounted successfully during cleanup."
        }
        catch {
            Write-Log "Failed to dismount WinPE image during cleanup. Error: $_"
        }
    }
    Write-Host "Script execution complete. For detailed information, please check the log file at $script:LogFile" -ForegroundColor Cyan
}

# SIG # Begin signature block
# (Optional) Add a script signature here for added security
# SIG # End signature block