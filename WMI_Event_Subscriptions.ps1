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

    $creatorSidString = if ($consumer.CreatorSID) { (New-Object Security.Principal.SecurityIdentifier($consumer.CreatorSID, 0)).Value } else { '-' }
    $username = if ($creatorSidString -ne '-') { Convert-SIDToUsername $creatorSidString } else { '-' }
    $consumerAction = Get-ConsumerAction -Consumer $consumer

    $removeCommand = if ($filter -and $consumer) {
        "Remove-WmiObject -Namespace root\Subscription -Filter '__RELPATH=$($binding.Filter)'"
    } else {
        "-"
    }

    $subscription = [PSCustomObject]@{
        CreatorSID            = $creatorSidString
        NameOfUserSIDProperty = $username
        FilterName            = $filter.Name
        FilterQuery           = $filter.Query
        ConsumerName          = $consumer.Name
        ConsumerType          = $consumer.__CLASS
        ConsumerAction        = $consumerAction
        RemoveCommand         = $removeCommand
    }

    $subscriptionsData += $subscription
}

if ($subscriptionsData.Count -gt 0) {
    $subscriptionsData | Export-Csv -Path $outputCsvFilePath -NoTypeInformation -Force
}
