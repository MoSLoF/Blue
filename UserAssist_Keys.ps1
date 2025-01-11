<#
.SYNOPSIS
Parses UserAssist registry keys to identify program usage details.

.DESCRIPTION
This script retrieves and decodes UserAssist registry keys from all user profiles on a Windows system. UserAssist keys are registry entries maintained by Windows Explorer to track the usage of applications and files accessed by users. These keys are primarily used to populate the "Most Frequently Used Programs" section of the Start menu which prioritizes programs based on user activity and frequency of execution. Each entry is encoded (by the OS) using ROT13 to obfuscate the program names and the script decodes them for readability.

From a forensic perspective, UserAssist keys are an essential artifact for understanding user behavior and activity on a system. They can provide:
- Timelines               : Evidence of when specific applications were run and how often.
- User actions            : Correlation of user behavior with system events or incidents.
- Indicators of compromise: Execution of unauthorized or suspicious programs.

Adversaries may target UserAssist keys to cover their tracks as clearing these entries will reset the data and remove evidence of prior application usage. However, investigators can use this script to retrieve and analyze the keys providing information into program execution history.

The script also collects metadata such as file size, owner, hash, zone identifier, referrer URL, host URL, and digital signature details for enriched forensic analysis. Results are exported to a CSV file.

.NOTES
Requires PowerShell v5+ and administrative privileges to access registry hives and user profile directories.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/UserAssist_Keys.ps1  
https://blog.didierstevens.com/2006/07/24/rot13-is-used-in-windows-you%E2%80%99re-joking/

.EXAMPLE
PS> .\UserAssist_Keys.ps1
#>


# Function to decode ROT13 encoded program names
function Decode-Rot13 {
    param([Parameter(Mandatory = $true)][string]$EncodedString)
    $decoded = [char[]]$EncodedString | ForEach-Object {
        if ($_ -match '[a-zA-Z]') {
            $ascii = [int]$_
            $baseAscii = if ($ascii -ge 97) { 97 } else { 65 }
            [char](($ascii - $baseAscii + 13) % 26 + $baseAscii)
        } else { $_ }
    }
    return ($decoded -join '')
}

# Function to translate SID to Username
function Get-UsernameFromSid {
    param([string]$SID)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    }
    catch {
        switch ($SID) {
            "S-1-5-18" { return "SYSTEM" }
            "S-1-5-19" { return "LOCAL SERVICE" }
            "S-1-5-20" { return "NETWORK SERVICE" }
            default { return "Unknown User" }
        }
    }
}

# Function to translate KnownFolder GUIDs to paths
function Expand-GUID {
    param(
        [string]$Path,
        [string]$UserProfilePath
    )

    # https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
    $knownFolders = @{
        '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B8FA8E}' = '%SystemDrive%\Program Files'
        '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' = '%ProgramFiles%\Common Files'
        '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' = '%ProgramFiles%\Common Files'
        '{DFDF76A2-C82A-4D63-906A-5644AC457385}' = '%SystemDrive%\Users\Public'
        '{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}' = '%PUBLIC%\Desktop'
        '{ED4824AF-DCE4-45A8-81E2-FC7965083634}' = '%PUBLIC%\Documents'
        '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = '%windir%\system32'
        '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = '%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs'
        '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = '%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned'
        '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = '%APPDATA%\Microsoft\Windows\Start Menu\Programs'
        '{6D809377-6AF0-444B-8957-A3773F02200E}' = '%SystemDrive%\Program Files'
        '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = '%windir%'
        '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = '%windir%\system32'
    }

    foreach ($guid in $knownFolders.Keys) {
        if ($Path -match $guid) {
            $Path = $Path -replace [regex]::Escape($guid), $knownFolders[$guid]
            break
        }
    }
    return $Path
}

# Function to expand environment variables dynamically
function Expand-EnvironmentVariables {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$UserProfilePath
    )

    # https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
    $variables = @{
        '%SystemRoot%' = [Environment]::GetEnvironmentVariable('SystemRoot')
        '%windir%' = [Environment]::GetEnvironmentVariable('windir')
        '%ProgramFiles%' = [Environment]::GetEnvironmentVariable('ProgramFiles')
        '%ProgramFiles(x86)%' = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
        '%SystemDrive%' = [Environment]::GetEnvironmentVariable('SystemDrive')
        '%UserProfile%' = $UserProfilePath
        '%AppData%' = Join-Path -Path $UserProfilePath -ChildPath 'AppData\Roaming'
        '%LocalAppData%' = Join-Path -Path $UserProfilePath -ChildPath 'AppData\Local'
        '%ALLUSERSPROFILE%' = [Environment]::GetEnvironmentVariable('ProgramData')
    }

    foreach ($key in $variables.Keys) {
        if ($Path -like "*$key*") {
            $Path = $Path -replace [regex]::Escape($key), $variables[$key]
        }
    }
    return $Path
}

# Function to get file size in human-readable format
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

# Function to get file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Function to get Zone Identifier data
function Get-ZoneIdentifierInfo {
    param ([string]$FilePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=(\d)') {
            $zoneId = $matches[1]
        }
        if ($adsContent -match '^ReferrerUrl=(.+)') {
            $referrerUrl = $matches[1]
        }
        if ($adsContent -match '^HostUrl=(.+)') {
            $hostUrl = $matches[1]
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Function to get digital signature details
function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
            SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
            TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
        }
    } catch {
        [PSCustomObject]@{
            IsOSBinary = "-"
            SignerCertificate = "-"
            TimeStamperCertificate = "-"
        }
    }
}

# Function to get file hash
function Get-FileHash256 {
    param ([string]$FilePath)
    try {
        (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    } catch {
        "-"
    }
}

# Function to determine execution type from GuidKey
function Get-ExecutionType {
    param ([string]$GuidKey)
    switch ($GuidKey) {
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}" { "Direct" }
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" { "Shortcut" }
        default { "-" }
    }
}

# Setup output location
$outputFile = Join-Path 'C:\BlueTeam' 'UserAssist_Keys.csv'
New-Item -ItemType Directory -Path (Split-Path $outputFile) -Force -ErrorAction SilentlyContinue | Out-Null

$results = @()
Get-ChildItem "Registry::HKU" | ForEach-Object {
    $sid = $_
    $userProfilePath = (Get-WmiObject Win32_UserProfile | Where-Object { $_.SID -eq $sid.PSChildName }).LocalPath
    if (-not $userProfilePath) { return }

    $userAssistPath = "Registry::HKU\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (-not (Test-Path $userAssistPath)) { return }

    Get-ChildItem -Path $userAssistPath | ForEach-Object {
        $guidFolder = $_
        $countPath = Join-Path $_.PSPath "Count"
        if (-not (Test-Path $countPath)) { return }

        $values = Get-ItemProperty -Path $countPath
        foreach ($valueName in $values.PSObject.Properties.Name) {
            if ($valueName -eq "(default)") { continue }

            $binaryData = $values.$valueName
            $runCount = "-"
            $lastRunTime = "-"

            if ($binaryData -and $binaryData.Length -ge 16) {
                try {
                    $runCount = [BitConverter]::ToInt32($binaryData, 4)
                    $fileTime = [BitConverter]::ToInt64($binaryData, 60)
                    $lastRunTime = if ($fileTime -gt 0) { [datetime]::FromFileTime($fileTime) } else { "-" }
                } catch {
                    $runCount = "-"
                    $lastRunTime = "-"
                }
            }

            $decodedName = Decode-Rot13 -EncodedString $valueName
            $guidTranslated = Expand-GUID -Path $decodedName -UserProfilePath $userProfilePath
            $finalPath = Expand-EnvironmentVariables -Path $guidTranslated -UserProfilePath $userProfilePath

            # Additional File Metadata
            $fileSize = "-"
            $fileOwner = "-"
            $fileHash = "-"
            $zoneData = Get-ZoneIdentifierInfo -FilePath $finalPath
            $signatureDetails = Get-AuthenticodeSignatureDetails -FilePath $finalPath

            if (Test-Path $finalPath) {
                $fileInfo = Get-Item -Path $finalPath -ErrorAction SilentlyContinue
                if ($fileInfo) {
                    $fileSize = Get-FormattedByteSize -ByteSize $fileInfo.Length
                    $fileOwner = Get-FileOwner -FilePath $finalPath
                    $fileHash = Get-FileHash256 -FilePath $finalPath
                }
            }

            $results += [PSCustomObject]@{
                Username = Get-UsernameFromSid -SID $sid.PSChildName
                UserSID = $sid.PSChildName
                ProgramName = $finalPath
                RunCount = $runCount
                LastRunTime = $lastRunTime
                ExecutionType = Get-ExecutionType -GuidKey $guidFolder.PSChildName
                GuidKey = $guidFolder.PSChildName
                FileSize = $fileSize
                FileOwner = $fileOwner
                SHA256 = $fileHash
                ZoneId = $zoneData.ZoneId
                ReferrerUrl = $zoneData.ReferrerUrl
                HostUrl = $zoneData.HostUrl
                IsOSBinary = $signatureDetails.IsOSBinary
                SignerCertificate = $signatureDetails.SignerCertificate
                TimeStamperCertificate = $signatureDetails.TimeStamperCertificate
            }
        }
    }
}

# Export Results
if ($results.Count -gt 0) {
    $results |
    Sort-Object { 
        if ($_.LastRunTime -eq "-") { [datetime]::MinValue } 
        else { $_.LastRunTime } 
    } -Descending |
    Export-Csv -Path $outputFile -NoTypeInformation -Force
}
