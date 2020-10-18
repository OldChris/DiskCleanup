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
    
    headerItem "Delete the contents of the Windows Temp folder."
    Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays( - $global:RetentionDays)) } | Remove-Item -force -recurse -ErrorAction SilentlyContinue -Verbose
    footerItem


    headerItem "Deletes all files and folders in user's Temp folder older then $global:RetentionDays days"
    Get-ChildItem "C:\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays( - $global:RetentionDays))} |
        Remove-Item -force -recurse -ErrorAction SilentlyContinue -Verbose
    footerItem

    headerItem "Removes all files and folders in user's Temporary Internet Files older then $global:RetentionDays days"
    Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" `
        -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object {($_.CreationTime -lt $(Get-Date).AddDays( - $global:RetentionDays))} |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    footerItem

    headerItem "Removes *.log from C:\windows\CBS"
    if(Test-Path C:\Windows\logs\CBS\){
    Get-ChildItem "C:\Windows\logs\CBS\*.log" -Recurse -Force -ErrorAction SilentlyContinue |
        remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
    } else {
        Write-Host "C:\inetpub\logs\LogFiles\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans IIS Logs older then $global:RetentionDays days"
    if (Test-Path C:\inetpub\logs\LogFiles\) {
        Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-60)) } | Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "C:\Windows\logs\CBS\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Removes C:\Config.Msi"
    if (test-path C:\Config.Msi){
        remove-item -Path C:\Config.Msi -force -recurse -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\Config.Msi does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem

    headerItem "Removes c:\Intel"
    if (test-path c:\Intel){
        remove-item -Path c:\Intel -force -recurse -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "c:\Intel does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Removes c:\PerfLogs"
    if (test-path c:\PerfLogs){
        remove-item -Path c:\PerfLogs -force -recurse -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "c:\PerfLogs does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Removes $env:windir\memory.dmp"
    if (test-path $env:windir\memory.dmp){
        remove-item $env:windir\memory.dmp -force -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\Windows\memory.dmp does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem

    headerItem "Cleaning WinSxS folder" 
    dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
    footerItem


    headerItem "Remove Windows Error Reporting files"
    if (test-path C:\ProgramData\Microsoft\Windows\WER){
        Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | Remove-Item -force -recurse -Verbose -ErrorAction SilentlyContinue
         } else {
            Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup."  -ForegroundColor DarkGray
    }
    footerItem
    ## Removes System and User Temp Files - lots of access denied will occur.
    headerItem "Cleans up c:\windows\temp"
    if (Test-Path $env:windir\Temp\) {
        Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Windows\Temp does not exist, there is nothing to cleanup. " -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up minidump"
    if (Test-Path $env:windir\minidump\) {
        Write-host "Deleting minidump files                    " -ForegroundColor Green
        Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "$env:windir\minidump\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up prefetch"
    if (Test-Path $env:windir\Prefetch\) {
        Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "$env:windir\Prefetch\ does not exist, there is nothing to cleanup."  -ForegroundColor DarkGray
    }
    footerItem

    headerItem "Cleans up all users windows error reporting" 
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up users temporary internet files" 
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up Internet Explorer"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up Internet Explorer cache"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up Internet Explorer download history"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up Internet Cache"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up Internet Cookies"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Cleans up terminal server cache"
    if (Test-Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } else {
            Write-Host "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\ does not exist." -ForegroundColor DarkGray
    }
    footerItem
 
    headerItem "Removes the hidden recycling bin."
    if (Test-path 'C:\$Recycle.Bin'){
        Remove-Item 'C:\$Recycle.Bin' -Recurse -Force -Verbose -ErrorAction SilentlyContinue
    } else {
        Write-Host "C:\`$Recycle.Bin does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
    }
    footerItem
    headerItem "Empty Recycle Bin."
    ## Turns errors back on
    $ErrorActionPreference = "Continue"

    ## Checks the version of PowerShell
    ## If PowerShell version 4 or below is installed the following will process
    if ($PSVersionTable.PSVersion.Major -le 4)
    {

        ## Empties the recycling bin, the desktop recyling bin
        $Recycler = (New-Object -ComObject Shell.Application).NameSpace(0xa)
        $Recycler.items() | ForEach-Object { 
            ## If PowerShell version 4 or bewlow is installed the following will process
            Remove-Item -Include $_.path -Force -Recurse -Verbose
        }
    }
    elseif ($PSVersionTable.PSVersion.Major -ge 5)
    {
        # -ErrorAction SilentlyContinue needed to suppress error , this is fixed in PS 7
        Clear-RecycleBin -DriveLetter C -Force -Verbose -ErrorAction SilentlyContinue
    }
    footerItem
    headerItem "Run Windows Disk Cleaner"
    WindowsDiskCleaner
    footerItem
    headerItem "Clean Events logs" 
    Clear-Eventlogs
    footerItem
    headerItem "Clean Software Distribution folder" 
    cleanSoftwareDistribution
    footerItem
}

function ShowLargeFiles
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

function OldLogTempFiles
{
    Param
    (
      [bool] $deleteItem
    )

    $ScanPath="C:\"
    $Extensions=".log", ".tmp", ".bak", ".old"
    $totalBytes=0
    $totalFiles=0
    if ($deleteItem -eq $TRUE)
	{ 
        Write-Host "Deleting from $ScanPath any $Extensions files older then $global:RetentionDays days." -ForegroundColor Green
    }
    else
    {
        Write-Host "Scanning $ScanPath for any $Extensions files older then $global:RetentionDays days." -ForegroundColor Green
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
            }
            Else
            {
                Write-Host "deleted" -ForegroundColor Green
			}
		#	;
        }
      }
    Write-Host " total bytes $(formatBytes $totalBytes) in $totalFiles files"
}
function formatBytes
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
        {$_ -gt 1tb} {$bytesText="$([math]::round(($theBytes/1tb),2)) teraByte";Break}
        {$_ -gt 1gb} {$bytesText="$([math]::round(($theBytes/1gb),2)) gigaByte";Break}
        {$_ -gt 1mb} {$bytesText="$([math]::round(($theBytes/1mb),2)) megaByte";Break}
        {$_ -gt 1kb} {$bytesText="$([math]::round(($theBytes/1kb),2)) kiloByte";Break}
        Default { $bytesText="$theBytes Bytes"}
    }
    return "$sign$bytesText"
} 
function Clear-Eventlogs 
{
    Write-Host "Clearing event logs"
    wevtutil el | Foreach-Object {Write-Progress  -Activity "Clearing events" -Status " $_" ;try { wevtutil cl "$_" 2> $null} catch {}}
}

Function WindowsDiskCleaner
{
    $SageSet = "StateFlags0099"
    $Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
    $Locations= @(
        "Active Setup Temp Folders"
        "BranchCache"
        "Downloaded Program Files"
        "GameNewsFiles"
        "GameStatisticsFiles"
        "GameUpdateFiles"
        "Internet Cache Files"
        "Memory Dump Files"
        "Offline Pages Files"
        "Old ChkDsk Files"
        "Previous Installations"
        "Recycle Bin"
        "Service Pack Cleanup"
        "Setup Log Files"
        "System error memory dump files"
        "System error minidump files"
        "Temporary Files"
        "Temporary Setup Files"
        "Temporary Sync Files"
        "Thumbnail Cache"
        "Update Cleanup"
        "Upgrade Discarded Files"
        "User file versions"
        "Windows Defender"
        "Windows Error Reporting Archive Files"
        "Windows Error Reporting Queue Files"
        "Windows Error Reporting System Archive Files"
        "Windows Error Reporting System Queue Files"
        "Windows ESD installation files"
        "Windows Upgrade Log Files"
    )

    ForEach($Location in $Locations) {
        Set-ItemProperty -Path $($Base+$Location) -Name $SageSet -Type DWORD -Value 2 -ea silentlycontinue | Out-Null
    }

    # do the cleanup . have to convert the SageSet number
    $Args = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length-4)))"
    Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $Args #-WindowStyle Hidden

    # Remove the Stateflags
    ForEach($Location in $Locations)
    {
        Remove-ItemProperty -Path $($Base+$Location) -Name $SageSet -Force -ea silentlycontinue | Out-Null
    }
} 

function RunsAsAdministrator
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

function cleanSoftwareDistribution
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

function cleanSCOM
{
    exit  # do not run
    # Sets the SCCM cache size to 1 GB if it exists.
    Try
    {
        if ((Get-WmiObject -namespace root\ccm\SoftMgmtAgent -class CacheConfig) -ne "$null")
        {
            # if data is returned and sccm cache is configured it will shrink the size to 1024MB.
            $cache = Get-WmiObject -namespace root\ccm\SoftMgmtAgent -class CacheConfig
            $Cache.size = 1024 | Out-Null
            $Cache.Put() | Out-Null
            Restart-Service ccmexec -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
    }
    Catch [System.Exception]{
        Write-host "SCOM  is not installed!" -ForegroundColor Red 
        Write-host "[ERROR]" -ForegroundColor Red -BackgroundColor black
    }


}
function diskFreeBytes
{
    $DevInfo=Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  
    Return $DevInfo.FreeSpace
}

function DiskSpaceStatus
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
function headerItem
{
    Param
    (
      [string] $headerText
    )
    Write-Host $headerText
    $global:startFreeBytes=diskFreeBytes 
}
function footerItem
{
    $freedUpBytes=($(diskFreeBytes) - $global:startFreeBytes)
    $freeText=formatBytes $freedUpBytes
 Write-Host "Done (saved  $freeText  )`n"  -ForegroundColor Green -BackgroundColor Black
}
function selectMenuOption()
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

function runCleanup
{
    Write-Host "Start script at " (Get-Date | Select-Object -ExpandProperty DateTime)
    $Starters = (Get-Date)
    $diskStatusBefore=DiskSpaceStatus
    $freeBytesBefore=diskFreeBytes
    Cleanup
    Write-Host "Before " $diskStatusBefore
    Write-Host "After " $(DiskSpaceStatus)
    Write-Host "==> Cleaned up $(formatBytes ($freeBytesBefore-(diskFreeBytes)))"
    $Finished = (Get-Date)

    $minutes=[math]::floor(($Finished - $Starters).totalminutes)
    $seconds=($Finished - $Starters).totalseconds - 60 * $minutes
    Write-Host "Elapsed Time: $minutes minutes,  $seconds seconds"
    Write-Host "Elapsed Time: $(($Finished - $Starters).totalseconds) seconds"
    Write-Host "Script done"


}

Clear-Host 
$thisAppName=(Get-Item $PSCommandPath).Basename
Write-Host "$thisAppName, clean disk C:\"
Write-Host "$(Hostname): PS Version :"$PSVersionTable.PSVersion : "Script " $PSCommandPath 
$thisPath=Split-Path $PSCommandPath -Parent
Set-Location $thisPath
$global:RetentionDays = 7
if (-Not(RunsAsAdministrator))
{
    Write-Host "Please run script as an administrator"
    $list='Run as Administrator|Quit'
    Write-Host ""
    $answer=selectMenuOption "Enter your choise:" $list 'Quit' $TRUE
    Switch ($answer)
    {
        {$_ -eq 1} {Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList "-file ""$PSCommandPath""";Break}
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
        $list+="|Quit"
        Write-Host ""
        $answer=selectMenuOption "$thisAppName : Enter your choise:"  $list 'Quit' $TRUE
        Switch ($answer)
        {
            {$_ -eq 1} {runCleanup;Break}
            {$_ -eq 2} {OldLogTempFiles $FALSE;Break}
            {$_ -eq 3} {OldLogTempFiles $TRUE;Break}
            {$_ -eq 4} {ShowLargeFiles;Break}
            {$_ -eq 5} {exit;Break}
            Default { exit }
        }
    }
}