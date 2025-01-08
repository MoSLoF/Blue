<#
.SYNOPSIS
Exports Windows event logs and archives each into separate zip files.

.DESCRIPTION
This script collects event logs (e.g., Security, Sysmon) from the local machine if they exist. Each log is exported as an `.evtx` file and compressed into a `.zip` archive named after the host and log type. By default, the script exports logs from the past 30 days, but a custom date range can be specified using the `-DaysBack` parameter or by simply changing the hardcoded value of `30` to something else.

.NOTES
- Requires administrative privileges to access and export some event log types.
- Compatible with PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Zip_Event_Logs.ps1

.EXAMPLE
PS> .\Zip_Event_Logs.ps1
PS> .\Zip_Event_Logs.ps1 -DaysBack 7
#>

param (
    [int]$DaysBack = 30  # Default to the past 30 days
)

# Define the output directory
$outputDirectory = 'C:\BlueTeam'
$hostname = $env:COMPUTERNAME

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Define event logs
$eventLogs = @(
    "Security", 
    "Microsoft-Windows-Sysmon/Operational", 
    "System", 
    "Microsoft-Windows-Windows Firewall with Advanced Security/Firewall", 
    "Microsoft-Windows-PowerShell/Operational", 
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 
    "Microsoft-Windows-WMI-Activity/Operational", 
    "Application", 
    "Microsoft-Windows-TaskScheduler/Operational", 
    "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", 
    "Microsoft-Windows-DNS-Client/Operational", 
    "Microsoft-Windows-DeviceGuard/Operational", 
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 
    "Microsoft-Windows-SMBServer/Operational", 
    "Microsoft-Windows-GroupPolicy/Operational"
)

# Calculate the start time based on the DaysBack parameter
$startTime = (Get-Date).AddDays(-$DaysBack)

foreach ($log in $eventLogs) {
    try {

        # Check if the event log exists by querying for the first event
        $logExists = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($logExists) {

            # Create a friendly name for the log file
            $friendlyLogName = ($log -replace 'Microsoft-Windows-', '').Replace('/', '_').Replace(' ', '_')
            $exportPath = Join-Path $outputDirectory "$hostname`_$friendlyLogName.evtx"

            # Export the event log with a time range
            wevtutil epl $log $exportPath /q:"*[System[TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))']]]"

            # Zip the exported log with underscores in the name
            $zipPath = "$exportPath".Replace(' ', '_') + ".zip"
            if (Test-Path $zipPath) { Remove-Item $zipPath }
            Compress-Archive -Path $exportPath -DestinationPath $zipPath -Force

            # Clean up the exported log file
            Remove-Item $exportPath -Force
        } else {
            Write-Warning "Log $log does not exist or cannot be accessed."
        }
    } catch {
        Write-Warning "An error occurred with log ${log}: $($_.Exception.Message)"
    }
}
