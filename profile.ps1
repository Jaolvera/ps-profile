<# 

.SYNOPSIS 
    Profile Script. Last Modified 10/06/2021

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

$datecon = get-date -UFormat "%A, %b %d %Y %I:%M %p"
$date = Get-Date -UFormat "%Y-%m-%d"
$host.ui.RawUI.WindowTitle = " Started $datecon "
Write-Host "loading, please wait..." -foregroundcolor green
if( -Not (Test-Path -Path $Env:userprofile\'OneDrive - SPS Commerce, Inc\Documents\ps-scripts' ) )
{
    New-Item -ItemType directory -Path $Env:userprofile\'OneDrive - SPS Commerce, Inc\Documents\ps-scripts'
	}
Start-Sleep -s 1
cls
write-host $datecon

function Get-MachineInfo($ServerName="localhost")             
{            
get-wmiobject win32_computersystem -ComputerName $ServerName |            
select DNSHostName, Manufacturer, Model, SystemType ,             
        @{Name="TotalPhysicalMemoryInMB";Expression={"{0:n2}" -f($_.TotalPhysicalMemory/1mb)}},             
        NumberOfLogicalProcessors, NumberOfProcessors, CurrentTimeZone, DaylightInEffect            
}# End Get-MachineInfo


function ha {
    Get-History -count $MaximumHistoryCount
}

function Clear-Clipboard {
   Add-Type -AssemblyName System.Windows.Forms
   [System.Windows.Forms.Clipboard]::Clear()
   Write-Output "Clipboard cleared."
}
 
Set-Alias -Name cc -Value Clear-Clipboard

function df {
    $colItems = Get-wmiObject -class "Win32_LogicalDisk" -namespace "root\CIMV2" `
    -computername localhost

    foreach ($objItem in $colItems) {
        write $objItem.DeviceID $objItem.Description $objItem.FileSystem `
            ($objItem.Size / 1GB).ToString("f3") ($objItem.FreeSpace / 1GB).ToString("f3")

    }
}

function get-drivespace {
  param( [parameter(mandatory=$true)]$Computer)
  if ($computer -like "*.com") {$cred = get-credential; $qry = Get-WmiObject Win32_LogicalDisk -filter drivetype=3 -comp $computer -credential $cred }
  else { $qry = Get-WmiObject Win32_LogicalDisk -filter drivetype=3 -comp $computer }  
  $qry | select `
    @{n="drive"; e={$_.deviceID}}, `
    @{n="GB Free"; e={"{0:N2}" -f ($_.freespace / 1gb)}}, `
    @{n="TotalGB"; e={"{0:N0}" -f ($_.size / 1gb)}}, `
    @{n="FreePct"; e={"{0:P0}" -f ($_.FreeSpace / $_.size)}}, `
    @{n="name"; e={$_.volumeName}} |
  format-table -autosize
} #close drivespace

function aduser-info {

param (
    $who
)
 get-aduser -server spsc $who -properties * | select-object displayname, `
                                                Organization, `
                                                samaccountname, `
												created, `
                                                passwordlastset, `
												whenchanged, `
												lastlogondate, `
												passwordneverexpires, `
												lastbadpasswordattempt, `
                                                emailaddress, `
                                                HomeDirectory, `
                                                state, `
                                                comment, `
                                                employeeid, `
                                                extensionAttribute11, `
                                                extensionAttribute12, `
                                                extensionAttribute13, `
                                                msExchHomeServerName, `
                                                SID
}


function ioc-search {
    param ( $badstr,$badpath,$badext )


$searchresults = Get-ChildItem $badpath "*.$badext" -Recurse | `
                 Select-String -Pattern "$badstr" | `
                 Select-Object -Unique Path
if ($searchresults -eq $null) { 
    Write-host "No matches found" -ForegroundColor green
    } else { 
    write-host "! possible IOC found in the following files !" -ForegroundColor Red
    $searchresults | foreach { $_.Path}
    }
}

### just need to edit with your account below###

Function Go-365admin {
Connect-ExchangeOnline -UserPrincipalName jaolvera.admin@spscommerce.onmicrosoft.com
}	

function Get-LoggedOnUser {
#Requires -Version 2.0            
[CmdletBinding()]            
 Param             
   (                       
    [Parameter(Mandatory=$true,
               Position=0,                          
               ValueFromPipeline=$true,            
               ValueFromPipelineByPropertyName=$true)]            
    [String[]]$ComputerName
   )#End Param

Begin            
{            
 Write-Host "`n Checking Users . . . "
 $i = 0            
}#Begin          
Process            
{
    $ComputerName | Foreach-object {
    $Computer = $_
    try
        {
            $processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop")
                if ($processinfo)
                {    
                    $processinfo | Foreach-Object {$_.GetOwner().User} | 
                    Where-Object {$_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM"} |
                    Sort-Object -Unique |
                    ForEach-Object { New-Object psobject -Property @{Computer=$Computer;LoggedOn=$_} } | 
                    Select-Object Computer,LoggedOn
                }#If
        }
    catch
        {
            "Cannot find any processes running on $computer" | Out-Host
        }
     }#Forech-object(ComputerName)       
            
}#Process
End
{

}#End

}#Get-LoggedOnUser

function prompt
{

    # New nice WindowTitle
    $Host.UI.RawUI.WindowTitle = "PowerShell v" + (get-host).Version.Major + "." + (get-host).Version.Minor + " (" + $pwd.Provider.Name + ") " + $pwd.Path
 
    # Admin ?
    if( (
        New-Object Security.Principal.WindowsPrincipal (
            [Security.Principal.WindowsIdentity]::GetCurrent())
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        # Admin-mark in WindowTitle
        $Host.UI.RawUI.WindowTitle = "[Admin] " + $Host.UI.RawUI.WindowTitle
 
        # Admin-mark on prompt
		$path = Split-Path -leaf -path (Get-Location)
        Write-Host "[" -nonewline -foregroundcolor DarkGray
        Write-Host "Admin" -nonewline -foregroundcolor Red
        Write-Host "] $path" -nonewline -foregroundcolor DarkGray
        Write-Host "`:\>" -nonewline -foregroundcolor Cyan	
    }
    else {
        $path = Split-Path -leaf -path (Get-Location)
        Write-Host "[" -nonewline -foregroundcolor DarkGray
        Write-Host "Non-Admin" -nonewline -foregroundcolor Yellow
        Write-Host "] $path" -nonewline -foregroundcolor DarkGray
        Write-Host "`:\>" -nonewline -foregroundcolor cyan	
    }
 
    # Show providername if you are outside FileSystem
    if ($pwd.Provider.Name -ne "FileSystem") {
        Write-Host "[" -nonewline -foregroundcolor DarkGray
        Write-Host $pwd.Provider.Name -nonewline -foregroundcolor Gray
        Write-Host "] " -nonewline -foregroundcolor DarkGray
    }
 
    # Backspace last \ and write >
    #Write-Host "`b> test" -nonewline -foregroundcolor Gray

    return " "
}

### old functions i can't toss

<#
function Get-FolderSizes {
  [cmdletBinding()]
  param(
    [parameter(mandatory=$true)]$Path,
    [parameter(mandatory=$false)]$SizeMB,
    [parameter(mandatory=$false)]$ExcludeFolder
  ) #close param
  $pathCheck = test-path $path
  if (!$pathcheck) {"Invalid path. Wants gci's -path parameter."; break}
  $fso = New-Object -ComObject scripting.filesystemobject
  $parents = Get-ChildItem $path -Force | where { $_.PSisContainer -and $_.name -ne $ExcludeFolder }
  $folders = Foreach ($folder in $parents) {
    $getFolder = $fso.getFolder( $folder.fullname.tostring() )
    if (!$getFolder.Size) { #for "special folders" like appdata
      $lengthSum = gci $folder.FullName -recurse -force -ea silentlyContinue | `
        measure -sum length -ea SilentlyContinue | select -expand sum
      $sizeMBs = "{0:N0}" -f ($lengthSum /1mb)      
    } #close if size property is null
      else { $sizeMBs = "{0:N0}" -f ($getFolder.size /1mb) }
      #else {$sizeMBs = [int]($getFolder.size /1mb) }
    New-Object -TypeName psobject -Property @{
       name = $getFolder.path;
      sizeMB = $sizeMBs
    } #close new obj property
  } #close foreach folder
  #here's the output
  $folders | sort @{E={[decimal]$_.sizeMB}} -Descending | ? {[decimal]$_.sizeMB -gt $SizeMB} | ft -auto
  #calculate the total including contents
  $sum = $folders | select -expand sizeMB | measure -sum | select -expand sum
  $sum += ( gci -file $path | measure -property length -sum | select -expand sum ) / 1mb
  $sumString = "{0:n2}" -f ($sum /1kb)
  $sumString + " GB total" 
} #end function
set-alias gfs Get-FolderSizes
#>

<#
function title-rename {
	param( $newtitle
	 )
	$host.ui.RawUI.WindowTitle = " [ $newtitle ] "
	}
#>
