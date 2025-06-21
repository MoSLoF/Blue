<#

.SYNOPSIS
Parses DLL export tables to map ordinals to function names.

.DESCRIPTION
This script checks both 32-bit and 64-bit DLLs to extract export information directly from PE headers. It maps ordinal numbers to their corresponding function names, including forwarded exports. It can optionally save the results for each DLL to a unique CSV file. Accepts file paths via parameter or pipeline.

.NOTES
Requires PowerShell v3+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Map_DLL_Ordinals_to_Function_Names.ps1

.PARAMETER DllPath
The full path to the DLL file(s) to analyze. If omitted, the script defaults to `C:\Windows\System32\comsvcs.dll`. This parameter accepts pipeline input.

.PARAMETER OutCsvFolder
Optional. The path to a directory where CSV output files will be saved. If the directory does not exist, it will be created. Do not specify a file name.

.EXAMPLE
.\Map_DLL_Ordinals_to_Function_Names.ps1
Analyzes the default DLL (C:\Windows\System32\comsvcs.dll) and prints the results to the console.

.EXAMPLE
.\Map_DLL_Ordinals_to_Function_Names.ps1 -DllPath "C:\Windows\System32\kernel32.dll"
Analyzes kernel32.dll and prints the results to the console without creating a CSV file.

.EXAMPLE
"C:\Windows\System32\kernel32.dll", "C:\Windows\System32\user32.dll" | .\Map_DLL_Ordinals_to_Function_Names.ps1
Analyzes both kernel32.dll and user32.dll from the pipeline and displays their results sequentially in the console.

.EXAMPLE
.\Map_DLL_Ordinals_to_Function_Names.ps1 -DllPath "C:\Windows\System32\user32.dll" -OutCsvFolder "C:\BlueTeam"
Analyzes user32.dll, prints the results to the console, and also saves the results to a uniquely named CSV file (e.g., user32_ordinal_function_mappings_....csv) in the directory.

.EXAMPLE
Get-ChildItem "C:\Windows\System32\d*.dll" | .\Map_DLL_Ordinals_to_Function_Names.ps1 -OutCsvFolder "C:\BlueTeam"
Finds all DLLs starting with 'd' in System32, analyzes each one, prints the results to the console, and saves a separate CSV report for each in the folder.

.EXAMPLE
.\Map_DLL_Ordinals_to_Function_Names.ps1 -DllPath "C:\Windows\System32\kernel32.dll", "C:\Windows\System32\user32.dll" -OutCsvFolder C:\BlueTeam
Analyzes both kernel32.dll and user32.dll, prints the results to the console, and also saves the results to a uniquely named CSV file (e.g., user32_ordinal_function_mappings_....csv) in the directory.

#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
    [Alias("FullName")]
    [string[]]$DllPath,

    [Parameter(Mandatory=$false)]
    [string]$OutCsvFolder
)

begin {
    $isInputProvided = $false

    function Translate-MemoryAddressToFileOffset {
        param([uint32]$Rva, [array]$SectionHeaders)
        $section = $SectionHeaders | Where-Object { $Rva -ge $_.VirtualAddress -and $Rva -lt ($_.VirtualAddress + $_.VirtualSize) } | Select-Object -First 1
        if ($section) {
            return $section.PointerToRawData + ($Rva - $section.VirtualAddress)
        }
        return 0
    }

    function Read-NullTerminatedString {
        param([byte[]]$ByteArray, [long]$Offset)
        $length = 0
        while ($Offset + $length -lt $ByteArray.Length -and $ByteArray[$Offset + $length] -ne 0) {
            $length++
        }
        return [System.Text.Encoding]::ASCII.GetString($ByteArray, $Offset, $length)
    }

    function Discover-DllExportedFunctions {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$DllFilePath
        )

        try {
            if (-not (Test-Path -Path $DllFilePath -PathType Leaf)) {
                Write-Error "File not found: '$DllFilePath'"
                return
            }

            $fileBytes = [System.IO.File]::ReadAllBytes($DllFilePath)
            
            $peHeaderOffset = [System.BitConverter]::ToUInt32($fileBytes, 0x3C)
            $coffHeaderOffset = $peHeaderOffset + 4
            $optionalHeaderOffset = $coffHeaderOffset + 20
            $magic = [System.BitConverter]::ToUInt16($fileBytes, $optionalHeaderOffset)
            
            $exportDirRvaOffset = switch ($magic) {
                0x10b { $optionalHeaderOffset + 96 }
                0x20b { $optionalHeaderOffset + 112 }
                default { Write-Error "Unsupported PE format in '$DllFilePath'."; return }
            }
            $exportDirRva = [System.BitConverter]::ToUInt32($fileBytes, $exportDirRvaOffset)
            if ($exportDirRva -eq 0) { Write-Warning "No export table found in '$DllFilePath'"; return }

            $numberOfSections = [System.BitConverter]::ToUInt16($fileBytes, $coffHeaderOffset + 2)
            $sizeOfOptionalHeader = [System.BitConverter]::ToUInt16($fileBytes, $coffHeaderOffset + 16)
            $sectionHeadersOffset = $optionalHeaderOffset + $sizeOfOptionalHeader
            $sectionHeaders = for ($i = 0; $i -lt $numberOfSections; $i++) {
                $offset = $sectionHeadersOffset + ($i * 40)
                [PSCustomObject]@{
                    VirtualSize      = [System.BitConverter]::ToUInt32($fileBytes, $offset + 8)
                    VirtualAddress   = [System.BitConverter]::ToUInt32($fileBytes, $offset + 12)
                    PointerToRawData = [System.BitConverter]::ToUInt32($fileBytes, $offset + 20)
                }
            }

            $exportDirOffset = Translate-MemoryAddressToFileOffset -Rva $exportDirRva -SectionHeaders $sectionHeaders
            $ordinalBase = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 16)
            $numberOfFunctions = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 20)
            $numberOfNames = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 24)
            $functionsAddrRva = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 28)
            $namesAddrRva = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 32)
            $ordinalsAddrRva = [System.BitConverter]::ToUInt32($fileBytes, $exportDirOffset + 36)

            $functionsTableFileOffset = Translate-MemoryAddressToFileOffset -Rva $functionsAddrRva -SectionHeaders $sectionHeaders
            $functionList = for ($i = 0; $i -lt $numberOfFunctions; $i++) {
                [PSCustomObject]@{
                    Rva          = [System.BitConverter]::ToUInt32($fileBytes, $functionsTableFileOffset + ($i * 4))
                    Ordinal      = $ordinalBase + $i
                    FunctionName = '[Ordinal Only]'
                }
            }

            $namesTableFileOffset = Translate-MemoryAddressToFileOffset -Rva $namesAddrRva -SectionHeaders $sectionHeaders
            $ordinalsTableFileOffset = Translate-MemoryAddressToFileOffset -Rva $ordinalsAddrRva -SectionHeaders $sectionHeaders
            for ($i = 0; $i -lt $numberOfNames; $i++) {
                $nameRva = [System.BitConverter]::ToUInt32($fileBytes, $namesTableFileOffset + ($i * 4))
                $nameFileOffset = Translate-MemoryAddressToFileOffset -Rva $nameRva -SectionHeaders $sectionHeaders
                $functionName = Read-NullTerminatedString -ByteArray $fileBytes -Offset $nameFileOffset
                $functionIndex = [System.BitConverter]::ToUInt16($fileBytes, $ordinalsTableFileOffset + ($i * 2))
                if ($functionIndex -lt $functionList.Count) {
                    $functionList[$functionIndex].FunctionName = $functionName
                }
            }

            $exportSection = $sectionHeaders | Where-Object { $exportDirRva -ge $_.VirtualAddress -and $exportDirRva -lt ($_.VirtualAddress + $_.VirtualSize) } | Select-Object -First 1
            foreach ($func in $functionList) {
                if ($func.Rva -eq 0) { continue }
                $forwarder = "-"
                if ($exportSection -and $func.Rva -ge $exportSection.VirtualAddress -and $func.Rva -lt ($exportSection.VirtualAddress + $exportSection.VirtualSize)) {
                    $forwarderOffset = Translate-MemoryAddressToFileOffset -Rva $func.Rva -SectionHeaders $sectionHeaders
                    $potentialForwarder = Read-NullTerminatedString -ByteArray $fileBytes -Offset $forwarderOffset
                    if (($potentialForwarder -like '*.*') -and ($potentialForwarder -notmatch '[^\x20-\x7E]')) {
                        $forwarder = $potentialForwarder
                    }
                }
                [PSCustomObject]@{
                    DllPath      = $DllFilePath
                    Ordinal      = $func.Ordinal
                    FunctionName = $func.FunctionName
                    Forwarder    = $forwarder
                }
            }
        }
        catch { Write-Error "Failed to parse '$DllFilePath': $_" }
    }

    function Write-ExportResults {
        param ($Results)
        if ($Results) {
            $maxNameLength = ($Results.FunctionName | Measure-Object -Maximum -Property Length).Maximum
            $functionNameColumnWidth = [Math]::Max(12, $maxNameLength)

            $headerFormat = "{0,-45} {1,7} {2,-$functionNameColumnWidth} {3}"
            $header = $headerFormat -f "DllPath", "Ordinal", "FunctionName", "Forwarder"
            
            Write-Host $header -ForegroundColor Cyan
            Write-Host ("-" * ($header.Length + 4)) -ForegroundColor Cyan
            
            foreach ($entry in $Results) {
                $dllPart = "  {0,-45}" -f $entry.DllPath
                $ordinalPart = "{0,7}" -f $entry.Ordinal
                $functionPart = "  {0,-$functionNameColumnWidth}" -f $entry.FunctionName
                $forwarderPart = $entry.Forwarder

                Write-Host -Object ($dllPart + $ordinalPart) -NoNewline
                if ($entry.FunctionName -eq "[Ordinal Only]") {
                    Write-Host -Object $functionPart -ForegroundColor Magenta -NoNewline
                } else {
                    Write-Host -Object $functionPart -NoNewline
                }
                Write-Host -Object " " -NoNewline
                Write-Host -Object $forwarderPart
            }
            Write-Host ""
        }
    }
    
    $helpTextColor = "Gray"
    Write-Host ""
    Write-Host ""
    Write-Host "--- Map DLL Ordinals to Function Names ---" -ForegroundColor Green
    Write-Host "Parses PE Export Address Table (EAT) to resolve ordinals and forwarded exports." -ForegroundColor $helpTextColor
    Write-Host ("-" * 80) -ForegroundColor $helpTextColor
    Write-Host "Interpreting the 'Forwarder' Column:" -ForegroundColor $helpTextColor
    Write-Host "  - A dash ('-') indicates the function is implemented within the analyzed module." -ForegroundColor $helpTextColor
    Write-Host "  - A string (e.g., 'NTDLL.RtlAcquireSRWLockExclusive') specifies a forwarded export." -ForegroundColor $helpTextColor
    Write-Host "" -ForegroundColor $helpTextColor
    Write-Host "    A forwarded export is a mechanism where a DLL's export table acts as a redirect." -ForegroundColor $helpTextColor
    Write-Host "    It instructs the Windows operating system that the actual code for the function" -ForegroundColor $helpTextColor
    Write-Host "    resides in a different module. When a program calls the function, the OS" -ForegroundColor $helpTextColor
    Write-Host "    intercepts the request and retrieves the real function from the target DLL specified." -ForegroundColor $helpTextColor
    Write-Host "" -ForegroundColor $helpTextColor
    Write-Host "Sample Output:" -ForegroundColor $helpTextColor
    Write-Host "  DllPath                           Ordinal FunctionName               Forwarder" -ForegroundColor $helpTextColor
    Write-Host "  -------                           ------- ------------               ---------" -ForegroundColor $helpTextColor
    Write-Host "  C:\Windows\System32\kernel32.dll        5 AddAtomA                   -" -ForegroundColor $helpTextColor
    Write-Host "  C:\Windows\System32\kernel32.dll        6 [Ordinal Only]             -" -ForegroundColor $helpTextColor
    Write-Host "  C:\Windows\System32\kernel32.dll        1 AcquireSRWLockExclusive    NTDLL.RtlAcquireSRWLockExclusive" -ForegroundColor $helpTextColor
    Write-Host ("-" * 80) -ForegroundColor $helpTextColor
    Write-Host ""
}

process {
    # Process each file path provided via parameter or pipeline.
    if ($DllPath) {
        $isInputProvided = $true
        foreach ($path in $DllPath) {
            $exportResults = Discover-DllExportedFunctions -DllFilePath $path
            
            Write-ExportResults -Results $exportResults
            
            if ($PSBoundParameters.ContainsKey('OutCsvFolder')) {
                if (-not (Test-Path -Path $OutCsvFolder -PathType Container)) {
                    Write-Host "Creating output directory: $OutCsvFolder" -ForegroundColor Yellow
                    New-Item -Path $OutCsvFolder -ItemType Directory -Force | Out-Null
                }
                
                $dllBaseName = [System.IO.Path]::GetFileNameWithoutExtension($path)
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmssfff'
                $csvFileName = "{0}_ordinal_function_mappings_{1}.csv" -f $dllBaseName, $timestamp
                $fullCsvPath = [System.IO.Path]::Combine($OutCsvFolder, $csvFileName)
                
                $exportResults | Export-Csv -Path $fullCsvPath -NoTypeInformation -Encoding UTF8
                Write-Host "Results also saved to: $fullCsvPath" -ForegroundColor Green
                Write-Host ""
            }
        }
    }
}

end {
    # After processing all input, run the default case if no files were provided.
    if (-not $isInputProvided) {
        $defaultPath = "C:\Windows\System32\comsvcs.dll"
        Write-Host "No DLL path provided. Analyzing default: $defaultPath" -ForegroundColor Yellow
        Write-Host ""
        $exportResults = Discover-DllExportedFunctions -DllFilePath $defaultPath
        Write-ExportResults -Results $exportResults

        if ($PSBoundParameters.ContainsKey('OutCsvFolder')) {
            if (-not (Test-Path -Path $OutCsvFolder -PathType Container)) {
                Write-Host "Creating output directory: $OutCsvFolder" -ForegroundColor Yellow
                New-Item -Path $OutCsvFolder -ItemType Directory -Force | Out-Null
            }
            $dllBaseName = [System.IO.Path]::GetFileNameWithoutExtension($defaultPath)
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmssfff'
            $csvFileName = "{0}_ordinal_function_mappings_{1}.csv" -f $dllBaseName, $timestamp
            $fullCsvPath = [System.IO.Path]::Combine($OutCsvFolder, $csvFileName)
            
            $exportResults | Export-Csv -Path $fullCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Results also saved to: $fullCsvPath" -ForegroundColor Green
            Write-Host ""
        }
    }
    Write-Host "--- Analysis Complete ---" -ForegroundColor Green
}
