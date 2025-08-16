<#
.SYNOPSIS
    Profile Script. Last Modified 10/06/2025

.DESCRIPTION
    something borrowed, something blue, something old

.FUNCTION LIST
    .Get-MachineInfo
    .ha
    .Clear-Clipboard
    .df
    .get-drivespace
    .aduser-info
    .go-365admin
    .get-loggedonuser
    .prompt
    .ioc-search

.FUNCTION Go-365admin
    Connects to EXO with SSO credentials

.FUNCTION Get-LoggedOnUser
    checked logged on user for remote machines. use it to see what examiners i am logged in to.
    can feed it 1 computer or multiple
    .example 1 Get-LoggedOnUser localhost
    .example 2 Get-LoggedOnUser localhost,remotecomputer
    .example 3 Get-LoggedOnUser (get-content .\computers.txt/csv)

.FUNCTION prompt
    marks prompt with admin if logged in as admin
    uses split path to shorten prompt while showing path in the powershell window title
#>

$datecon = Get-Date -UFormat "%A, %b %d %Y %I:%M %p"
$date = Get-Date -UFormat "%Y-%m-%d"
$host.UI.RawUI.WindowTitle = " Started $datecon "
Write-Host "loading, please wait..." -ForegroundColor Green

if (-Not (Test-Path -Path "$Env:userprofile\scripts")) {
    New-Item -ItemType Directory -Path "$Env:userprofile\scripts"
}

Start-Sleep -Seconds 1
Clear-Host
Write-Host $datecon

function Get-MachineInfo {
    param (
        $ServerName = "localhost"
    )
    Get-WmiObject Win32_ComputerSystem -ComputerName $ServerName |
        Select-Object DNSHostName, Manufacturer, Model, SystemType,
            @{Name="TotalPhysicalMemoryInMB";Expression={"{0:n2}" -f ($_.TotalPhysicalMemory/1mb)}},
            NumberOfLogicalProcessors, NumberOfProcessors, CurrentTimeZone, DaylightInEffect
}

function ha {
    Get-History -Count $MaximumHistoryCount
}

function Clear-Clipboard {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Clipboard]::Clear()
    Write-Output "Clipboard cleared."
}
Set-Alias -Name cc -Value Clear-Clipboard

function df {
    $colItems = Get-WmiObject -Class "Win32_LogicalDisk" -Namespace "root\CIMV2" -ComputerName localhost
    foreach ($objItem in $colItems) {
        Write-Output "$($objItem.DeviceID) $($objItem.Description) $($objItem.FileSystem) $([math]::Round($objItem.Size / 1GB, 3)) $([math]::Round($objItem.FreeSpace / 1GB, 3))"
    }
}

function get-drivespace {
    param (
        [Parameter(Mandatory = $true)]
        $Computer
    )
    if ($Computer -like "*.com") {
        $cred = Get-Credential
        $qry = Get-WmiObject Win32_LogicalDisk -Filter "drivetype=3" -ComputerName $Computer -Credential $cred
    }
    else {
        $qry = Get-WmiObject Win32_LogicalDisk -Filter "drivetype=3" -ComputerName $Computer
    }
    $qry | Select-Object `
        @{n="drive"; e={$_.DeviceID}}, `
        @{n="GB Free"; e={"{0:N2}" -f ($_.FreeSpace / 1GB)}}, `
        @{n="TotalGB"; e={"{0:N0}" -f ($_.Size / 1GB)}}, `
        @{n="FreePct"; e={"{0:P0}" -f ($_.FreeSpace / $_.Size)}}, `
        @{n="name"; e={$_.VolumeName}} |
    Format-Table -AutoSize
}

function aduser-info {
    param (
        $who
    )
    Get-ADUser -Server spsc $who -Properties * | Select-Object displayname,
        Organization,
        samaccountname,
        created,
        passwordlastset,
        whenchanged,
        lastlogondate,
        passwordneverexpires,
        lastbadpasswordattempt,
        emailaddress,
        HomeDirectory,
        state,
        comment,
        employeeid,
        extensionAttribute11,
        extensionAttribute12,
        extensionAttribute13,
        msExchHomeServerName,
        SID
}

function ioc-search {
    param (
        $badstr,
        $badpath,
        $badext
    )

    $searchresults = Get-ChildItem $badpath "*.$badext" -Recurse |
        Select-String -Pattern "$badstr" |
        Select-Object -Unique Path

    if ($null -eq $searchresults) {
        Write-Host "No matches found" -ForegroundColor Green
    }
    else {
        Write-Host "! possible IOC found in the following files !" -ForegroundColor Red
        $searchresults | ForEach-Object { $_.Path }
    }
}

# just need to edit with your account below
function Go-365admin {
    Connect-ExchangeOnline -UserPrincipalName
}

function Get-LoggedOnUser {
    #Requires -Version 2.0
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]$ComputerName
    )
    begin {
        Write-Host "`n Checking Users . . . "
    }
    process {
        $ComputerName | ForEach-Object {
            $Computer = $_
            try {
                $processinfo = @(Get-WmiObject -Class Win32_Process -ComputerName $Computer -ErrorAction Stop)
                if ($processinfo) {
                    $processinfo | ForEach-Object { $_.GetOwner().User } |
                        Where-Object { $_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM" } |
                        Sort-Object -Unique |
                        ForEach-Object { New-Object psobject -Property @{ Computer = $Computer; LoggedOn = $_ } } |
                        Select-Object Computer, LoggedOn
                }
            }
            catch {
                "Cannot find any processes running on $Computer" | Out-Host
            }
        }
    }
    end { }
}

function prompt {
    # New nice WindowTitle
    $Host.UI.RawUI.WindowTitle = "PowerShell v$((Get-Host).Version.Major).$((Get-Host).Version.Minor) ($($pwd.Provider.Name)) $($pwd.Path)"

    # Admin?
    if (
        (New-Object Security.Principal.WindowsPrincipal (
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ) {
        # Admin-mark in WindowTitle
        $Host.UI.RawUI.WindowTitle = "[Admin] " + $Host.UI.RawUI.WindowTitle

        # Admin-mark on prompt
        $path = Split-Path -Leaf -Path (Get-Location)
        Write-Host "[" -NoNewline -ForegroundColor DarkGray
        Write-Host "Admin" -NoNewline -ForegroundColor Red
        Write-Host "] $path" -NoNewline -ForegroundColor DarkGray
        Write-Host "`:\>" -NoNewline -ForegroundColor Cyan
    }
    else {
        $path = Split-Path -Leaf -Path (Get-Location)
        Write-Host "[" -NoNewline -ForegroundColor DarkGray
        Write-Host "Non-Admin" -NoNewline -ForegroundColor Yellow
        Write-Host "] $path" -NoNewline -ForegroundColor DarkGray
        Write-Host "`:\>" -NoNewline -ForegroundColor Cyan
    }

    # Show providername if you are outside FileSystem
    if ($pwd.Provider.Name -ne "FileSystem") {
        Write-Host "[" -NoNewline -ForegroundColor DarkGray
        Write-Host $pwd.Provider.Name -NoNewline -ForegroundColor Gray
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
    }

    return " "
}

# Old functions I can't toss

<#
function Get-FolderSizes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Path,
        [Parameter(Mandatory = $false)]$SizeMB,
        [Parameter(Mandatory = $false)]$ExcludeFolder
    )
    $pathCheck = Test-Path $Path
    if (!$pathCheck) { "Invalid path. Wants gci's -path parameter."; break }
    $fso = New-Object -ComObject Scripting.FileSystemObject
    $parents = Get-ChildItem $Path -Force | Where-Object { $_.PSIsContainer -and $_.Name -ne $ExcludeFolder }
    $folders = foreach ($folder in $parents) {
        $getFolder = $fso.GetFolder($folder.FullName.ToString())
        if (!$getFolder.Size) {
            $lengthSum = Get-ChildItem $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Sum Length -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Sum
            $sizeMBs = "{0:N0}" -f ($lengthSum / 1MB)
        }
        else {
            $sizeMBs = "{0:N0}" -f ($getFolder.Size / 1MB)
        }
        New-Object -TypeName PSObject -Property @{
            Name   = $getFolder.Path
            SizeMB = $sizeMBs
        }
    }
    $folders | Sort-Object @{E = { [decimal]$_.SizeMB }} -Descending | Where-Object { [decimal]$_.SizeMB -gt $SizeMB } | Format-Table -AutoSize
    $sum = $folders | Select-Object -ExpandProperty SizeMB | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $sum += (Get-ChildItem -File $Path | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum) / 1MB
    $sumString = "{0:n2}" -f ($sum / 1KB)
    $sumString + " GB total"
}
Set-Alias gfs Get-FolderSizes
#>

<#
function title-rename {
    param($newtitle)
    $host.UI.RawUI.WindowTitle = " [ $newtitle ] "
}
#>
