<#
.SYNOPSIS
Enumerates WMI event subscriptions.

.DESCRIPTION
This script retrieves WMI event subscription details from the `root\Subscription` namespace including event filters, consumers, and bindings. WMI event subscriptions are used for system management tasks but are also a common persistence method for attackers. The script resolves creator SIDs to usernames, extracts filter queries and consumer actions, and organizes the data into a CSV.

These subscriptions are great in forensic investigations to detect signs of malicious persistence or misconfiguration.

.NOTES
Requires administrative privileges and PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/WMI_Event_Subscriptions.ps1  
https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event#event-consumers

.EXAMPLE
PS> .\WMI_Event_Subscriptions.ps1
#>

$outputDirectory = 'C:\BlueTeam'

function Convert-ByteToString {
    param (
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes
    )

    [System.Text.Encoding]::Unicode.GetString($Bytes)
}

function Convert-SidToString {
    param (
        [Parameter(Mandatory = $true)]
        [byte[]] $SidBytes
    )

    (New-Object Security.Principal.SecurityIdentifier($SidBytes, 0)).Value
}

function Convert-SIDToUsername {
    param (
        [Parameter(Mandatory = $true)]
        [string] $SIDString
    )

    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SIDString)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        Write-Warning "Could not translate SID: $_"
        return "-"
    }
}

function Get-ConsumerAction {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.ManagementObject] $Consumer
    )

    switch ($Consumer.ClassPath.ClassName) {
        'CommandLineEventConsumer' { $Consumer.CommandLineTemplate }
        'ActiveScriptEventConsumer' { $Consumer.ScriptText }
        'LogFileEventConsumer' { $Consumer.FileName }
        'SMTPEventConsumer' { $Consumer.SMTPServer }
        Default { '-' }
    }
}

$outputCsvFilePath = Join-Path -Path $outputDirectory -ChildPath "WMI_Event_Subscriptions.csv"

if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force
}

$eventFilters = Get-WmiObject -Namespace root\Subscription -Class __EventFilter
$eventConsumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer
$filterToConsumerBindings = Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding

$subscriptionsData = @()

foreach ($binding in $filterToConsumerBindings) {
    $filter = $eventFilters | Where-Object { $_.__RELPATH -eq $binding.Filter }
    $consumer = $eventConsumers | Where-Object { $_.__RELPATH -eq $binding.Consumer }

    $creatorSidString = if ($consumer.CreatorSID) { Convert-SidToString $consumer.CreatorSID } else { '-' }
    $username = if ($creatorSidString -ne '-') { Convert-SIDToUsername $creatorSidString } else { '-' }
    $consumerAction = Get-ConsumerAction -Consumer $consumer

    $subscription = [PSCustomObject]@{
        CreatorSID            = $creatorSidString
        NameOfUserSIDProperty = $username
        FilterName            = $filter.Name
        FilterQuery           = $filter.Query
        ConsumerName          = $consumer.Name
        ConsumerType          = $consumer.__CLASS
        ConsumerAction        = $consumerAction
    }

    $subscriptionsData += $subscription
}

$subscriptionsData | Export-Csv -Path $outputCsvFilePath -NoTypeInformation -Force
