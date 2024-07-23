# Function to check if the script is running as an administrator
function Check-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "This must be ran as an administrator" -ForegroundColor Red
        exit
    } else {
        Write-Host "Administrative privileges confirmed." -ForegroundColor Green
    }
}

# Function to create a timestamp
function Get-Timestamp {
    return (Get-Date).ToString("yyMMddHHmmss")
}

# Function to check if a service exists
function Test-ServiceExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Function to stop and remove the ImmyBot Agent service
function Test-Stop-And-Remove-Service {
    $serviceName = "ImmyBot Agent"

    if (Test-ServiceExists -ServiceName $serviceName) {
        Write-Host "Service '$serviceName' exists."
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        Write-Host "Checking if the service $serviceName is running."
        if ($null -ne $service) {
            if ($service.Status -eq "Running") {
                try {
                    Write-Host "Stopping the ImmyBot Agent Service"
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                } catch {
                    Write-Host "Failed to stop the service $serviceName, killing process" -ForegroundColor Orange
                    Stop-Process -Name "Immybot.Agent" -Force -ErrorAction Stop
                    if ($service.Status -eq "Running") {
                        Write-Host "Failed to stop the service $serviceName" -ForegroundColor Red
                        exit
                    }
                }
            }
            Write-Host "Deleting the ImmyBot Agent Service"
            sc.exe delete $serviceName
            if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                Write-Host "Failed to remove the service $serviceName" -ForegroundColor Red
                exit
            }
        }
    } else {
        Write-Host "Service '$serviceName' does not exist."
    }
}

# Function to check and kill ImmyBot processes
function Check-And-Kill-Processes {
    $processes = @("Immybot.Agent", "Immybot.Agent.Ephemeral")
    foreach ($process in $processes) {
        $runningProcess = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($runningProcess) {
            Write-Host "$process is running."
            Stop-Process -Name $process -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            if (Get-Process -Name $process -ErrorAction SilentlyContinue) {
                Write-Host "Failed to kill the process $process" -ForegroundColor Red
                exit
            }
        } else {
            Write-Host "$process is not running."
        }
    }
}

# Function to backup or delete the ImmyBot folders
function Backup-Or-Delete-Folders {
    param ($shouldBackup, $backupFolder)

    $folders = @(
        "$env:SystemDrive\ProgramData\ImmyBot",
        "$env:SystemDrive\ProgramData\ImmyBotAgentService"
    )
    $foldersProgramFiles = @(
        "$env:SystemDrive\program files (x86)\ImmyBot"
    )
    $removeFolders = @(
        "$env:SystemRoot\Temp\.net\Immybot.Agent",
        "$env:SystemRoot\Temp\.net\Immybot.Agent.Ephemeral"
    )

    foreach ($folder in $folders) {
        if (Test-Path $folder) {
            if ($shouldBackup) {
                $destination = "$env:SystemDrive\immybackup.$backupFolder"
                try {
                    New-Item -Path $destination -ItemType Directory -Force
                    Move-Item -Path $folder -Destination $destination -Force
                    Write-Host "Backed up $folder to $destination"
                } catch {
                    Write-Host "Failed to backup $folder" -ForegroundColor Red
                }
            } else {
                try {
                    Remove-Item -Path $folder -Recurse -Force
                    Write-Host "Deleted $folder"
                } catch {
                    Write-Host "Failed to delete $folder" -ForegroundColor Red
                }
            }
        }
    }

    foreach ($folder in $foldersProgramFiles) {
        if (Test-Path $folder) {
            if ($shouldBackup) {
                $destination = "$env:SystemDrive\immybackup.$backupFolder\programfiles"
                try {
                    New-Item -Path $destination -ItemType Directory -Force
                    Move-Item -Path $folder -Destination $destination -Force
                    Write-Host "Backed up $folder to $destination"
                } catch {
                    Write-Host "Failed to backup $folder" -ForegroundColor Red
                }
            } else {
                try {
                    Remove-Item -Path $folder -Recurse -Force
                    Write-Host "Deleted $folder"
                } catch {
                    Write-Host "Failed to delete $folder" -ForegroundColor Red
                }
            }
        }
    }

    foreach ($removeFolder in $removeFolders) {
        if (Test-Path $removeFolder) {
            try {
                Remove-Item -Path $removeFolder -Recurse -Force
                Write-Host "Deleted $removeFolder"
            } catch {
                Write-Host "Failed to delete $removeFolder" -ForegroundColor Red
            }
        }
    }

    # Additional files to delete
    $additionalFiles = @(
        "C:\Program Files (x86)\ImmyBot\Immybot.Agent.exe",
        "C:\ProgramData\ImmyBotAgentService\config.json",
        "C:\Windows\Installer\{AEAE9A9B-5BA9-4F30-945B-02255C3A08B4}\app_icon.ico"
    )

    foreach ($file in $additionalFiles) {
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force
                Write-Host "FILE DELETED! $file"
            } catch {
                Write-Host "Failed to delete $file" -ForegroundColor Red
            }
        }
    }

    # Additional directories to delete
    $additionalDirs = @(
        "C:\Program Files (x86)\ImmyBot",
        "C:\Windows\Installer\{AEAE9A9B-5BA9-4F30-945B-02255C3A08B4}",
        "C:\Windows\Installer\SourceHash{AEAE9A9B-5BA9-4F30-945B-02255C3A08B4}"
    )

    foreach ($dir in $additionalDirs) {
        if (Test-Path $dir) {
            try {
                Remove-Item -Path $dir -Recurse -Force
                Write-Host "FILE DELETED! $dir"
            } catch {
                Write-Host "Failed to delete $dir" -ForegroundColor Red
            }
        }
    }
}

# Function to remove ImmyBot from Add & Remove Programs
function Remove-ImmyBot-From-Programs {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $uninstallPaths) {
        Get-ChildItem -Path $path | ForEach-Object {
            $displayName = (Get-ItemProperty -Path $_.PSPath).DisplayName
            if ($displayName -like "*ImmyBot*") {
                try {
                    Remove-Item -Path $_.PSPath -Recurse -Force
                    Write-Host "Removed $displayName from Add & Remove Programs"
                } catch {
                    Write-Host "Failed to remove $displayName from Add & Remove Programs" -ForegroundColor Red
                }
            }
        }
    }

    # Registry keys to delete
    $registryKeys = @(
        "HKLM:\SOFTWARE\Classes\Installer\Features\B9A9EAEA9AB503F449B52052C5A3804B",
        "HKLM:\SOFTWARE\Classes\Installer\Products\B9A9EAEA9AB503F449B52052C5A3804B",
        "HKLM:\SOFTWARE\Classes\Installer\Products\B9A9EAEA9AB503F449B52052C5A3804B\SourceList",
        "HKLM:\SOFTWARE\Classes\Installer\Products\B9A9EAEA9AB503F449B52052C5A3804B\SourceList\Media",
        "HKLM:\SOFTWARE\Classes\Installer\Products\B9A9EAEA9AB503F449B52052C5A3804B\SourceList\Net",
        "HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\838BD7B5CEB1FD34F9822188ACFCDFA7",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AEAE9A9B-5BA9-4F30-945B-02255C3A08B4}",
        "HKLM:\SYSTEM\ControlSet001\Services\ImmyBot Agent",
        "HKLM:\SYSTEM\CurrentControlSet\Services\ImmyBot Agent"
    )

    foreach ($regKey in $registryKeys) {
        if (Test-Path $regKey) {
            try {
                Remove-Item -Path $regKey -Recurse -Force
                Write-Host "REG DELETED! $regKey"
            } catch {
                Write-Host "Failed to delete $regKey" -ForegroundColor Red
            }
        }
    }
}

# Main script execution
Check-Admin

$backupDecision = Read-Host "Do you want to backup data? (y/n)"
$shouldBackup = $false
$timestamp = ""
if ($backupDecision -eq "y") {
    $shouldBackup = $true
    $timestamp = Get-Timestamp
}

Test-Stop-And-Remove-Service
Check-And-Kill-Processes
Backup-Or-Delete-Folders -shouldBackup $shouldBackup -backupFolder $timestamp
Remove-ImmyBot-From-Programs

Write-Host "Script completed successfully."