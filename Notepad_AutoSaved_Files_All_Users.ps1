<#
.SYNOPSIS
Extracts and outputs information about Windows 11 Notepad autosave items for all users on the system.

.DESCRIPTION
This script identifies and processes Notepad autosave data (`.bin` files) stored in the TabState directory for all user profiles on Windows 11. 
It gathers metadata, alternate data streams (ADS), zone identifiers, digital signature details, and file hashes. The results are output to a CSV file for analysis.

**Important:** Prior to execution, the script forcibly terminates all instances of Notepad.exe to ensure file access, so unsaved Notepad content should be saved beforehand. 
This script is designed exclusively for Windows 11 as Notepad autosave files are not present in Windows 10.

.NOTES
Author: soc-otter
Compatible with: PowerShell v5+
Designed for: Windows 11

.LINK
https://github.com/soc-otter/Blue/blob/main/Notepad_AutoSaved_Files_All_Users.ps1

.EXAMPLE
./Notepad_AutoSaved_Files_All_Users.ps1
#>

# Check if the operating system is Windows 11
$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
if ($osVersion -lt "10.0.22000") {
    Write-Host "This script is only compatible with Windows 11. Exiting..." -ForegroundColor Red
    sleep 3
    exit
}

# Warning: This script will close all running instances of Notepad.exe before execution.
#Write-Host "Closing all instances of Notepad.exe..." -ForegroundColor Yellow
Get-Process -Name "Notepad" -ErrorAction SilentlyContinue | Stop-Process -Force

# Define output path for the CSV
$outputFolder = "C:\BlueTeam"
$outputFile = "$outputFolder\Notepad_AutoSaved_Files_All_Users.csv"

# Create output folder if it does not exist
if (!(Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory | Out-Null
}

# Helper function to format byte sizes
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Function to get Zone Identifier data
function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=3') {
            $zoneId = "3"
            switch -Regex ($adsContent) {
                '^ReferrerUrl=(.+)' { $referrerUrl = $matches[1] }
                '^HostUrl=(.+)' { $hostUrl = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Function to retrieve digital signature details
function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $signature) {
            return [PSCustomObject]@{
                IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
                SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsOSBinary = "-"
        SignerCertificate = "-"
        TimeStamperCertificate = "-"
    }
}

# Helper function to calculate file hash
function Get-FileHash {
    param ([string]$FilePath)
    try {
        (Microsoft.PowerShell.Utility\Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { "-" }
}

# Helper function to retrieve file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath -ErrorAction Stop).Owner
    } catch { "-" }
}

# Function to get ADS information
function Get-ADSInfo {
    param ([string]$filePath)
    $adsInfo = @()

    try {
        $streams = Get-Item -Path $filePath -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        foreach ($stream in $streams) {
            $adsContent = Get-Content -Path $filePath -Stream $stream.Stream -Raw -ErrorAction SilentlyContinue
            $adsInfo += [PSCustomObject]@{
                StreamName = $stream.Stream
                StreamSize = Get-FormattedByteSize -ByteSize $stream.Length
                StreamContent = $adsContent
            }
        }
    } catch {}

    if ($adsInfo.Count -eq 0) {
        $adsInfo = "-"
    }

    return $adsInfo
}

# Initialize an array to store file details
$fileDetails = @()

# Loop through all user profiles
$userProfiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Default", "Public", "All Users") }
foreach ($userProfile in $userProfiles) {
    $packagesPath = Join-Path -Path $userProfile.FullName -ChildPath "AppData\Local\Packages"
    $notepadPaths = Get-ChildItem -Path $packagesPath -Directory -Filter "Microsoft.WindowsNotepad_*" -ErrorAction SilentlyContinue | ForEach-Object {
        Join-Path -Path $_.FullName -ChildPath "LocalState\TabState"
    }

    foreach ($tabStateDirectory in $notepadPaths) {
        if (Test-Path -Path $tabStateDirectory) {
            Write-Host "Searching $tabStateDirectory for Notepad autosave .bin files..." -ForegroundColor Cyan
            $binFiles = Get-ChildItem -Path $tabStateDirectory -File -Filter "*.bin" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt 0 -and $_.Name -notmatch "\.\d+\.bin$" }

            if ($binFiles.Count -gt 0) {
                foreach ($file in $binFiles) {
                    try {
                        # Read the .bin file content
                        $rawContent = Get-Content -Path $file.FullName -Raw -Encoding UTF8
                        $zoneInfo = Get-ZoneIdentifierInfo -FilePath $file.FullName
                        $adsInfo = Get-ADSInfo -FilePath $file.FullName
                        $signatureDetails = Get-AuthenticodeSignatureDetails -FilePath $file.FullName

                        $fileDetails += [PSCustomObject]@{
                            UserProfile           = $userProfile.Name
                            Location              = "TabState Directory"
                            FileName              = $file.Name
                            FilePath              = $file.FullName
                            Size                  = Get-FormattedByteSize -ByteSize $file.Length
                            CreationTime          = $file.CreationTime
                            LastWriteTime         = $file.LastWriteTime
                            LastAccessTime        = $file.LastAccessTime
                            FileHash              = Get-FileHash -FilePath $file.FullName
                            FileOwner             = Get-FileOwner -FilePath $file.FullName
                            ZoneId                = $zoneInfo.ZoneId
                            ReferrerUrl           = $zoneInfo.ReferrerUrl
                            HostUrl               = $zoneInfo.HostUrl
                            IsOSBinary            = $signatureDetails.IsOSBinary
                            SignerCertificate     = $signatureDetails.SignerCertificate
                            TimeStamperCertificate = $signatureDetails.TimeStamperCertificate
                            ADSInfo               = $adsInfo
                            RawContent            = $rawContent
                        }
                    } catch {
                        Write-Host "Failed to read file $($file.FullName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "No valid .bin files found in $tabStateDirectory." -ForegroundColor Yellow
            }
        } else {
            Write-Host "TabState directory not found: $tabStateDirectory" -ForegroundColor Yellow
        }
    }
}

# Output results to CSV if any data was found
if ($fileDetails.Count -gt 0) {
    $fileDetails | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Host "Autosave file details exported to: $outputFile" -ForegroundColor Green
} else {
    Write-Host "No Notepad autosave data found." -ForegroundColor Red
}
