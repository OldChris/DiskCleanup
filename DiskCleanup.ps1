#
#
#  This script is inspired by a script found at https://gallery.technet.microsoft.com/scriptcenter/Clean-up-your-C-Drive-bc7bb3ed
#  I removed a lot and added some of my own functions.
#
#  Any suggestion via github are welcome : OldChris/DiskCleanup
#
#
#  if this scripts fails to run because of UnauthorizedAcces messages:
#  1) start PowerShell_Ise in administrator mode
#  2) run this command : Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
#  3) then start this script again.
#  4) this script will switch to administrator mode (see menu option)
#
#
Function Cleanup {
    
    cleanFolder "C:\Users\*\AppData\Local\Temp\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\*" @(".etl", ".db") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Internet Explorer\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" @("*") $global:RetentionDays $True

    cleanFolder "$Env:windir\SoftwareDistribution\DataStore\Logs\**" @(".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\Performance\WinSAT\DataStore\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\system32\catroot2\*" @(".jrs", ".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\system32\wdi\LogFiles\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\debug\*" @(".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\Temp\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\Prefetch\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\ProgramData\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True

    cleanFolder "$Env:windir\logs\CBS\*" @(".log") 0 $True
    cleanFolder "C:\inetpub\logs\LogFiles\*" @("*") 0 $True

    removeFolder "C:\PerfLogs" 
    removeFolder "C:\Config.Msi" 
    removeFolder "c:\Intel"

    removeFile "$Env:windir\memory.dmp" $global:RetentionDays
    removeFile "C:\ProgramData\Microsoft\Windows\Power Efficiency Diagnostics\energy-report-*-*-*.xml" $global:RetentionDays

    headerItem "Cleaning WinSxS folder" 
    dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
    footerItem

    headerItem "Empty Recycle Bin."
    # -ErrorAction SilentlyContinue needed to suppress error , this is fixed in PS 7
    Clear-RecycleBin -DriveLetter C -Force -Verbose -ErrorAction SilentlyContinue
    
    footerItem
    headerItem "Run Windows Disk Cleaner"
    WindowsDiskCleaner
    footerItem
    headerItem "Clean Events logs" 
    clearEventlogs
    footerItem
    headerItem "Clean Software Distribution folder" 
    cleanSoftwareDistribution
    footerItem
}

#
#  functions that clean files, folders, etcetera
#
Function cleanFolder
{
    Param
    (
      [string] $folder,
      [string[]] $extensions,
      [int32]  $retentionDays,
      [bool]   $recursive
    )
    if ($recursive -eq $True)
    {
        $recurse= @{'Recurse' = $True}
    }
    else
    {
        $recurse=""
    }
    headerItem "Clean folder $folder any $extensions files older then $retentionDays days." -ForegroundColor Green
    if (Test-Path "$folder")
    {
        Get-ChildItem "$folder" @recurse -Force -ErrorAction SilentlyContinue |
            #  Where-Object { $extensions -contains $_.Extension}| 
              Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$retentionDays)) } | 
        % { 
            if ($extensions -contains $_.Extension)
            { 
                Remove-Item $_.FullName -Force -Verbose -ErrorAction SilentlyContinue
            } 
            else 
            { 
              if ($extensions -contains "*")
              {
                Remove-Item $_.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
              }
            }  
          }    
    }
    else
    {
        Write-Host "$folder does not exist." -ForegroundColor DarkGray
    }
    footerItem
}
Function removeFolder
{
    Param
    (
      [string] $folder
    ) 
    headerItem "Removes folder $folder"
    if (Test-path "$folder")
    {
        Remove-Item "$folder" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Host "Folder $folder does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
}

Function removeFile
{
    Param
    (
      [string] $file,
      [int32] $retentionDays
    ) 
    headerItem "Removes file $file"
    Get-ChildItem -Path $file -ErrorAction SilentlyContinue | 
    Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$retentionDays)) }|
     Remove-Item -ErrorAction SilentlyContinue 
    footerItem
}

Function OldLogTempFiles
{
    Param
    (
      [bool] $deleteItem
    )

    $ScanPath="C:\"
    $Extensions=".log", ".tmp", ".bak", ".old"
    $totalBytes=0
    $totalFiles=0
    $totalBytesDeleted=0
    $totalFilesDeleted=0
    $totalBytesNotDeleted=0
    $totalFilesNotDeleted=0
    if ($deleteItem -eq $TRUE)
	{ 
        headerItem "Deleting from $ScanPath any $Extensions files older then $global:RetentionDays days." -ForegroundColor Green
    }
    else
    {
        headerItem "Scanning $ScanPath for any $Extensions files older then $global:RetentionDays days." -ForegroundColor Green
    }
    Get-ChildItem -Path $ScanPath -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $Extensions -contains $_.Extension}| 
    Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$global:RetentionDays)) }|
    % { Write-Host $_.Fullname $(formatBytes $_.Length);
        $totalFiles+=1;$totalBytes+=$_.Length;
        if ($deleteItem -eq $TRUE)
		{ 
           Remove-Item $_.Fullname -ErrorAction SilentlyContinue ;
           $FileExists = Test-Path $_.Fullname;
            If ($FileExists -eq $True) 
            {
                Write-Host "File could not be deleted" -ForegroundColor Red
                $totalFilesNotDeleted+=1;$totalBytesNotDeleted+=$_.Length;
            }
            Else
            {
                Write-Host "deleted" -ForegroundColor Green
                $totalFilesDeleted+=1;$totalBytesDeleted+=$_.Length;
			}
		#	;
        }
      }
    if ($deleteItem -eq $TRUE)
	{ 
        Write-Host " total $(formatBytes $totalBytes) scanned in $totalFiles files, "
        Write-Host " total $(formatBytes $totalBytesDeleted) deleted in $totalFilesDeleted files,"
        Write-Host " total $(formatBytes $totalBytesNotDeleted) not deleted in $totalFilesNotDeleted files"
    }
    else
    {
        Write-Host " total $(formatBytes $totalBytes) in $totalFiles files"
    }
    footerItem
}
Function ShowLargeFiles
{
    $ScanPath="C:\"
    Write-Host "Scanning $ScanPath for any large files." -ForegroundColor Green
    Write-Host ( Get-ChildItem $ScanPath -Recurse -ErrorAction SilentlyContinue | 
  #  Where-Object { $Extensions -contains $_.Extension}| 
    Where-Object { $_.Length -gt 1GB}| 
    Sort-Object Length -Descending | Select-Object Name, Directory,
                    @{Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) }} | Format-Table  -AutoSize |
        Out-String )
}


Function clearEventlogs 
{
    wevtutil el | Foreach-Object {Write-Progress  -Activity "Clearing events" -Status " $_" ;try { wevtutil cl "$_" 2> $null} catch {}}
    Write-Progress -Activity  "Done" -Status "Done" -Completed
}


Function WindowsDiskCleaner
{
    # when changing StateFlags number please check run command for cleanmgr
    $SageSet = "StateFlags0099"
    $Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
    $Locations= @(
        "Active Setup Temp Folders"
        "BranchCache"
        "Content Index Cleaner"
        "D3D Shader Cache"
        "Delivery Optimization Files"
        "Device Driver Packages"
        "Diagnostic Data Viewer database files"
        "Downloaded Program Files"
        "Download Program Files"
        "DownloadsFolder"
        "GameNewsFiles"
        "GameStatisticsFiles"
        "GameUpdateFiles"
        "Internet Cache Files"
        "Language Pack"
        "Memory Dump Files"
        "Offline Pages Files"
        "Old ChkDsk Files"
        "Previous Installations"
        "Recycle Bin"
        "RetailDemo Offline Content"
        "Service Pack Cleanup"
        "Setup Log Files"
        "System error memory dump files"
        "System error minidump files"
        "Temporary Files"
        "Temporary Setup Files"
      #  "Temporary Sync Files"
        "Thumbnail Cache"
        "Update Cleanup"
        "Upgrade Discarded Files"
        "User file versions"
        "Windows Defender"
        "Windows Error Reporting Files"
      #  "Windows Error Reporting Archive Files"
      #  "Windows Error Reporting Queue Files"
      #  "Windows Error Reporting System Archive Files"
      #  "Windows Error Reporting System Queue Files"
        "Windows ESD installation files"
        "Windows Upgrade Log Files"
    )
    # value 2 means 'include' in cleanmgr run, 0 means 'do not run'
    ForEach($Location in $Locations) {
        Set-ItemProperty -Path $($Base+$Location) -Name $SageSet -Type DWORD -Value 2 -ErrorAction SilentlyContinue | Out-Null
    }

    # do the cleanup . have to convert the SageSet number
    $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length-4)))"
   # Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args #-WindowStyle Hidden
    Start-Process -Wait -FilePath "$Env:ComSpec" -ArgumentList "/c title running Cleanmgr, please wait to complete&&echo Cleanmgr is running, please wait...&&cleanmgr /sagerun:99&&pause"

    # Remove the Stateflags
    ForEach($Location in $Locations)
    {
        Remove-ItemProperty -Path $($Base+$Location) -Name $SageSet -Force -ErrorAction SilentlyContinue | Out-Null
    }
} 

Function cleanSoftwareDistribution
{
    ## Stops the windows update service so that c:\windows\softwaredistribution can be cleaned up
    Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
    Get-Service -Name bits | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
    ## Deletes the contents of windows software distribution.
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue -Verbose
    ## Restarts wuauserv and bits services
    Get-Service -Name wuauserv | Start-Service -ErrorAction SilentlyContinue -Verbose
    Get-Service -Name bits | Start-Service -ErrorAction SilentlyContinue -Verbose
}
#
# Check Disk and Filesystem functions
#
Function runSFC
{
    headerItem "Run SFC utility"
    Write-Host " a seperate Dos box will open, this can take a while (30 minutes)"
    $numBefore=(Get-Content C:\windows\Logs\CBS\CBS.log | Select-String -Pattern ', Warning', ', Error' ).length
    Start-Process -Wait -FilePath "$Env:ComSpec" -ArgumentList "/c title running SFC, please wait to complete&&sfc /scannow&&pause"
    $numAfter=(Get-Content C:\windows\Logs\CBS\CBS.log | Select-String -Pattern ', Warning', ', Error' ).length
    $numNew=$numAfter-$numBefore
    Write-Host "CBS.log has $numNew new Warnings/ Errors"
    footerItem
}

Function runRepairVolune
{
    headerItem "Scan volume drive C"
    Repair-Volume -DriveLetter C -Scan
    footerItem
}

#
#  other functions (formatting, user interaction etc)
#
Function formatBytes
{
    param
    (
        [long] $theBytes
    )
    if ($theBytes -lt 0)
    {
        $theBytes*=-1
        $sign="-"
    }
    else
    {
        $sign=""
    }
    Switch ($theBytes )
    {
        {$_ -gt 1tb} {$bytesText="$([math]::round(($theBytes/1tb),2)) teraBytes";Break}
        {$_ -gt 1gb} {$bytesText="$([math]::round(($theBytes/1gb),2)) gigaBytes";Break}
        {$_ -gt 1mb} {$bytesText="$([math]::round(($theBytes/1mb),2)) megaBytes";Break}
        {$_ -gt 1kb} {$bytesText="$([math]::round(($theBytes/1kb),2)) kiloBytes";Break}
        {$_ -eq 1tb} {$bytesText="1 teraByte";Break}
        {$_ -eq 1gb} {$bytesText="1 gigaByte";Break}
        {$_ -eq 1mb} {$bytesText="1 megaByte";Break}
        {$_ -eq 1kb} {$bytesText="1 kiloByte";Break}
        {$_ -eq 1} {$bytesText="1 Byte";Break}
        Default { $bytesText="$theBytes Bytes"}
    }
    return "$sign$bytesText"
} 


Function diskFreeBytes
{
    $DevInfo=Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  
    Return $DevInfo.FreeSpace
}

Function DiskSpaceStatus
{
 $result=Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
    @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
    @{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f ( $_.Size / 1gb)}},
    @{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f ( $_.Freespace / 1gb ) } },
    @{ Name = "PercentFree" ; Expression = {"{0:P1}" -f ( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize |
        Out-String
    Return $result
}

Function LogWriteLine
{
    Param
    (
        [string] $logtext
    )
    $logRecord = (Get-Date -Format "yyyyMMddTHH:mm:ss.ffff") + " " + $logtext
    Add-content $global:Logfile -value $logRecord
}

Function headerItem
{
    Param
    (
      [string] $headerText
    )
    Write-Host $headerText
    $global:startFreeBytesItem=diskFreeBytes 
    LogWriteLine "$headerText"
}
Function footerItem
{
    $freedUpBytesItem=($(diskFreeBytes) - $global:startFreeBytesItem)
    $freedUpBytesTotal=($(diskFreeBytes) - $global:startFreeBytesScript)
    $freeTextItem=formatBytes $freedUpBytesItem 
    $freeTextTotal=formatBytes $freedUpBytesTotal
    $logText="Done (cleaned up  $freeTextItem, total $freeTextTotal  )" 
    Write-Host "$logText`n"  -ForegroundColor Green -BackgroundColor Black
    LogWriteLine "$logText"
}
Function enterNumber()
{
    Param
    (
        [string] $prompt,
        [int32] $current,
        [int32] $default,
        [int32] $min,
        [int32] $max
    )
    Do
    {
        $menuIndex=0
        if ($warning -ne "")
        {
            Write-Host $warning
        }
        Write-Host $prompt
        $result = Read-Host "Enter number between $min and $max, current = $current, Press enter to accept the default [$($default)]"
        if ($result -eq "")
        {
            $result = $default
        }
 
    } Until (([int]$result -ge $min) -and ([int]$result -le $max))
    return [int]$result
 
}
Function selectMenuOption()
{
    Param
    (
        $prompt,
        $options,
        $default,
        $numeric
    )
    $seperator="|"
    $option_list = $options.Split($seperator)
    $defaultValue = $default
    $warning=""
    $answerList=""
    Do
    {
        $menuIndex=0
        if ($warning -ne "")
        {
            Write-Host $warning
        }
        Write-Host $prompt
        ForEach ( $option in $option_list)
        {
            $menuIndex+=1
            $answerList+=",$menuIndex"
            if ($option -eq $defaultValue)
            {
                Write-Host ' ', $menuIndex, ':', $option, '(default)'
                $defaultIndex = $menuIndex
            }
            else
            {
                Write-Host ' ', $menuIndex, ':', $option
            }
        }
        $result = Read-Host "Press enter to accept the default [$($defaultIndex)]"
        if ($result -eq "")
        {
            $result = $defaultIndex
        }
        else
        {
            if (-Not ($answerList.contains($result)))
            {
                $warning="Input invalid, try again"
            }
        }
 
    } Until ($answerList.contains($result))
    if ($numeric -eq $TRUE)
    {
        return $result
    }
    else
    {
        return $list.Split($seperator)[$result-1]
    }
}

Function RunsAsAdministrator
{
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        return $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
    } catch {
        throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
        return $FALSE
    }
}

Function runCleanup
{
    Write-Host "Start script at " (Get-Date | Select-Object -ExpandProperty DateTime)
    $Starters = (Get-Date)
    $diskStatusBefore=DiskSpaceStatus
    $freeBytesBefore=diskFreeBytes
    Cleanup
    Write-Host "Before " $diskStatusBefore
    Write-Host "After " $(DiskSpaceStatus)
    Write-Host "==> Cleaned up $(formatBytes ($freeBytesBefore-(diskFreeBytes)))"
    Write-Host "    since first run $(formatBytes ($Global:startScriptFreeBytes-(diskFreeBytes)))"

    $Finished = (Get-Date)

    $minutes=[math]::floor(($Finished - $Starters).totalminutes)
    $seconds=($Finished - $Starters).totalseconds - 60 * $minutes
    Write-Host "Elapsed Time: $minutes minutes,  $seconds seconds"
    Write-Host "Elapsed Time: $(($Finished - $Starters).totalseconds) seconds"
    Write-Host "Script done"


}

Function menuCheckDiskFS
{
# check disk and filesystem
    While (1 -eq 1)
    {
        $list="Run DiskCheck"
        $list+="|Run System File Checker (SFC) utility"
        $list+="|Return to main menu"
        Write-Host ""
        $answer=selectMenuOption "$thisAppName : Enter your choise:"  $list 'Quit' $TRUE
        Switch ($answer)
        {
            {$_ -eq 1} {runRepairVolune;Break}
            {$_ -eq 2} {runSFC;Break}
            {$_ -eq 3} {Return;Break}
            Default { Return }
        }
    }
}

Clear-Host 
if ($PSVersionTable.PSVersion.Major -lt 5)
{
  Write-Host "Powershell Version : " $PSVersionTable.PSVersion  " should be at least version 5, please upgrade Powershell"
  exit
}
$thisPath=Split-Path $PSCommandPath -Parent
Set-Location $thisPath
$thisAppName=(Get-Item $PSCommandPath).Basename

$global:Logfile=$thisPath+"\"+ $thisAppName+ "_" + $(Hostname) + "_" + $(Get-Date -Format "yyyyMMddTHHmmss") + ".log"
$global:RetentionDays = 7
$Global:startFreeBytesScript=diskFreeBytes
Write-Host "$thisAppName, clean disk C:\"
Write-Host "$(Hostname): PS Version :$($PSVersionTable.PSVersion) : Script  $PSCommandPath : Logfile $global:Logfile" 
if (-Not(RunsAsAdministrator))
{
    Write-Host "Please run script as an administrator"
    $list="Run as Administrator"
    $list+="|Quit"
    Write-Host ""
    $answer=selectMenuOption "Enter your choise:" $list 'Quit' $TRUE
    Switch ($answer)
    {
        {$_ -eq 1} {Start-Process "$psHome\powershell_ise.exe" -Verb Runas -ArgumentList "-file ""$PSCommandPath""";Break}
        {$_ -eq 2} {exit;Break}
        Default { exit }
    }
} 
else
{
    While (1 -eq 1)
    {
        $list="Run DiskCleanup script"
        $list+="|List temp files older then $global:RetentionDays days"
        $list+="|Delete temp files older then $global:RetentionDays days"
        $list+="|Scan for large files"
        $list+="|Change Retention days"
        $list+="|Check Disk and Filesystem menu"
        $list+="|Quit"
        Write-Host ""
        $answer=selectMenuOption "$thisAppName : Enter your choise:"  $list 'Quit' $TRUE
        Switch ($answer)
        {
            {$_ -eq 1} {runCleanup;Break}
            {$_ -eq 2} {OldLogTempFiles $FALSE;Break}
            {$_ -eq 3} {OldLogTempFiles $TRUE;Break}
            {$_ -eq 4} {ShowLargeFiles;Break}
            {$_ -eq 5} {$global:RetentionDays=$(enterNumber "Change retention days" $global:RetentionDays 7 1 30);Break}
            {$_ -eq 6} {menuCheckDiskFS;Break}
            {$_ -eq 7} {exit;Break}
            Default { exit }
        }
    }
}