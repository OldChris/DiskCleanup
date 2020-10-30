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
Function cleanTempFolderBrowsersEventLog
{
    
    cleanFolder "C:\Users\*\AppData\Local\Temp\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\*" @(".etl", ".db") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Internet Explorer\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" @("*") $global:RetentionDays $True

    cleanFolder "$Env:windir\SoftwareDistribution\DataStore\Logs\*" @(".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\Performance\WinSAT\DataStore\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\system32\catroot2\*" @(".jrs", ".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\system32\wdi\LogFiles\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\debug\*" @(".log") $global:RetentionDays $True
    cleanFolder "$Env:windir\Temp\*" @("*") $global:RetentionDays $True
    cleanFolder "$Env:windir\Prefetch\*" @("*") $global:RetentionDays $True
    cleanFolder "C:\ProgramData\Microsoft\Windows\WER\*" @("*") $global:RetentionDays $True

    cleanFolder "$Env:windir\logs\CBS\*" @(".log") 0 $True
    cleanFolder "C:\inetpub\logs\LogFiles\*" @("*") 0 $True

 

    removeFile "$Env:windir\memory.dmp" $global:RetentionDays
    removeFile "C:\ProgramData\Microsoft\Windows\Power Efficiency Diagnostics\energy-report-*-*-*.xml" $global:RetentionDays


	cleanIE_Chrome

    headerItem "Clean Events logs" 
    clearEventlogs
    footerItem

    headerItem "Empty Recycle Bin."
    # -ErrorAction SilentlyContinue needed to suppress error , this is fixed in PS 7
    Clear-RecycleBin -DriveLetter C -Force -Verbose -ErrorAction SilentlyContinue
    footerItem
    headerItem "Cleaning WinSxS folder" 
    dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
    footerItem
    headerItem "Run Windows Disk Cleaner"
    WindowsDiskCleaner
    footerItem
}


Function cleanSoftwareDistribution
{
    headerItem "Clean Software Distribution folder" 
    cleanSoftwareDistribution
    footerItem
}

Function checkRestorePointsRootfoldersHibernationFile
{
	checkRestorePoints
	checkRootFolders
    checkHibernationFile
}

Function testNewStuff
{

}
Function checkRootFolders
{
    headerItem "Check root folder drive C:"
    $expectedRootFolders=@(
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",
    "C:\Users",
    "C:\Windows",
    "C:\Documents and Settings",
    "C:\System Volume Information",
    "C:\Boot",
    'C:\$RECYCLE.BIN'

    )
    $hint0="this folder is not known to the script, please check for yourself"
    $hint1="this folder indicates an previous version of Windows exist, please use cleanmgr utility to remove"
    $hint1+=" Press Windows+R,`nType cleanmgr, then press Enter"
    $hint2="this folder can be deleted"
    Get-ChildItem -Path C:\ -Directory -Force -ErrorAction SilentlyContinue |
    %{ 
        #Write-Host "$($_.FullName)"
        if (-Not ($expectedRootFolders -contains "$($_.FullName)") )
        {
            $folder="$($_.FullName)"
            Write-Host "$folder : " -NoNewline
            Switch ($folder)
            {
                'C:\Windows.Old' {Write-Host $hint1 -ForegroundColor Green -BackgroundColor Black ;Break}
                'C:\$Windows.~WS' {Write-Host $hint1 -ForegroundColor Green -BackgroundColor Black;Break}
                'C:\Config.Ms'  {Write-Host $hint2;Break}
                'C:\ESD' {Write-Host $hint2;Break}
                'C:\Intel' {Write-Host $hint2;Break}
                'C:\PerfLogs'  {Write-Host $hint2;Break} 
                Default { Write-Host $hint0}
            }
        }
    }
    footerItemNoBytes
}


	# TODO
	# clear Edge browser'....
	
	# clear location history ???
	
	# ipconfig /flushdns ???
	
    # check for unused AppData folders (left behind, or apps no longer used/uninstalled poorly)
	
    # thumbnails, icon cache, fontcache cleanup

    # check Downloads folder > 500 Mb , then give warning




#
#  functions that clean files, folders, etcetera
#

Function checkHibernationFile
{
    headerItem "check Hibernation file"
    $hiberfile=$FALSE
    try
    { 
    # 
        $regVal =(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled -ErrorAction Stop)
        if ($regVal.HibernateEnabled -eq 1)
        {
            $hiberfile=$TRUE
        }
        else
        {
            $hiberfile=$FALSE
        }
    }
    catch
    {
      Write-Host "Can not find the registry key, this can happen if you never switched on Hibernation" -ForegroundColor Red -BackgroundColor Black
      $hiberfile=$FALSE
    }

#   if (Test-Path "C:\hiberfil.sys")  # this doesn't work. 
    if ($hiberfile -eq $TRUE)
    {
        Write-Host "Hibernate is swithced on, to save space you can switch it off" 
        Write-Host "in a Administrator Mode command box type 'powercfg.exe /HIBERNATE OFF' "
    }
    else
    {
        Write-Host "Hibernate is swithced off"
    }
    footerItemNoBytes
}


Function checkUnusedApps
{
  # C:\ProgramData 
  # C:\Users\Chris\AppData\Local\Temp
    Get-ChildItem -Path C:\ProgramData -Directory -Force -ErrorAction SilentlyContinue |
    %{ 
        #$_.FullName;
        if (checkFolderRecentlyUsed "$($_.FullName)" 180)
        {
         #  Write-Host "$_ recently used" 
        }
        else
        {
           Write-Host "$($_.FullName) NOT recently used" 
        }
    }
}
Function checkFolderRecentlyUsed
{
    Param
    (
      [string] $folder,
      [int32]  $ageLimit
    )
    $recentlyUsed=$False
    if (Test-Path "$folder")
    {
        # first test folder itself, then all items in it
        try
        {   #-ErrorAction Stop to make Try Catch work
            if ((Get-Item $folder -ErrorAction Stop  ).CreationTime -gt $(Get-Date).AddDays(-$ageLimit))
            {
               $recentlyUsed=$True
               return $recentlyUsed
            }
        }
        catch [System.Exception]
        {
           Write-Host "Folder $folder not accesible" -ForegroundColor DarkGray
           $recentlyUsed=$True
           return $recentlyUsed
        }
        Get-ChildItem "$folder" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -gt $(Get-Date).AddDays(-$ageLimit)) } | 
        % { $recentlyUsed=$True }    
    }
    else
    {
        Write-Host "$folder does not exist." -ForegroundColor DarkGray
    }
    Return $recentlyUsed
}

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
    Where-Object { $_.Length -gt 1GB}| 
    Sort-Object Length -Descending | Select-Object Name, Directory,
                    @{Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) }} | Format-Table  -AutoSize |
        Out-String )
}


Function cleanIE_Chrome
{
	headerItem "cleanup Internet Explorer and Chrome"

	Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    $DaysToDelete = 1

	$temporaryIEDir = "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" ## Remove all files and folders in user's Temporary Internet Files. 
	$cachesDir = "C:\Users\*\AppData\Local\Microsoft\Windows\Caches"  ## Remove all IE caches. 
	$cookiesDir = "C:\Documents and Settings\*\Cookies\*" ## Delets all cookies. 
	$locSetDir = "C:\Documents and Settings\*\Local Settings\Temp\*"  ## Delets all local settings temp 
	$locSetIEDir = "C:\Documents and Settings\*\Local Settings\Temporary Internet Files\*"   ## Delets all local settings IE temp 
	$locSetHisDir = "C:\Documents and Settings\*\Local Settings\History\*"  ## Delets all local settings history

	Get-ChildItem $temporaryIEDir, $cachesDir, $cookiesDir, $locSetDir, $locSetIEDir, $locSetHisDir -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } | remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue

	$DaysToDelete = 7

	$crLauncherDir = "C:\Documents and Settings\%USERNAME%\Local Settings\Application Data\Chromium\User Data\Default"
	$chromeDir = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default"
	$chromeSetDir = "C:\Users\*\Local Settings\Application Data\Google\Chrome\User Data\Default"

	$Items = @("*Archived History*", "*Cache*", "*Cookies*", "*History*", "*Login Data*", "*Top Sites*", "*Visited Links*", "*Web Data*")

	$items | ForEach-Object {
	$item = $_ 
	Get-ChildItem $crLauncherDir, $chromeDir, $chromeSetDir -Recurse -Force -ErrorAction SilentlyContinue | 
		Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) -and $_ -like $item} | ForEach-Object -Process { Remove-Item $_ -force -Verbose -recurse -ErrorAction SilentlyContinue }
	}
	footerItem
}

Function cleanWindowsStore
{
	headerItem "cleanup Windows Store"
	wsreset
	footerItem
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
    headerItem "clean Software Distribution"
    ## Stops the windows update service so that c:\windows\softwaredistribution can be cleaned up
    Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
    Get-Service -Name bits | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose
    ## Deletes the contents of windows software distribution.
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -recurse -ErrorAction SilentlyContinue -Verbose
    ## Restarts wuauserv and bits services
    Get-Service -Name wuauserv | Start-Service -ErrorAction SilentlyContinue -Verbose
    Get-Service -Name bits | Start-Service -ErrorAction SilentlyContinue -Verbose
    footerItem
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
    footerItemNoBytes
}

Function checkRestorePoints
{
    Write-Host "Check on Restore Points"
    $days=60
    $max=5
    $count=(Get-ComputerRestorePoint |measure).count
    if ($count -gt $max)
    {
        Write-Host "There are $count System Restore points, please take action" -ForegroundColor Red -BackgroundColor Black
        Get-ComputerRestorePoint
    }
    else
    {
        Write-Host "There are $count (less then $max) Restore Points, no action required" -ForegroundColor Green -BackgroundColor Black
    }
    $list=""
    $date = @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}
    Get-ComputerRestorePoint |Select-Object -Property SequenceNumber, $date, Description |
        Where-Object { $_.Date -lt $(Get-Date).AddDays(-$days) }|
        %{ $list+= "$($_.Date) $($_.SequenceNumber) $($_.Description)`n"}

    if ($list -ne "")
    {
        Write-Host "`nRestore points older then $days days" -ForegroundColor Red -BackgroundColor Black
        Write-Host $list
        Write-Host "To delete a Restore Point : Press Windows+R,`nType System Restore, then press Enter"
	}
    else
    {
        Write-Host "No Rstore points found older then $days days" -ForegroundColor Green -BackgroundColor Black
    }
    footerItemNoBytes
}

Function runRepairVolune
{
    headerItem "Scan volume drive C"
    Repair-Volume -DriveLetter C -Scan
    footerItemNoBytes
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
    $freedUpBytesTotal=($(diskFreeBytes) - $global:startScriptFreeBytes)
    $freeTextItem=formatBytes $freedUpBytesItem 
    $freeTextTotal=formatBytes $freedUpBytesTotal
    $logText="Done (cleaned up  $freeTextItem, total $freeTextTotal  )" 
    Write-Host "$logText`n"  -ForegroundColor Green -BackgroundColor Black
    LogWriteLine "$logText"
}
Function footerItemNoBytes
{
    $logText="Done" 
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

Function checkForUpdate
{ 
    $repo = "OldChris/DiskCleanup"
    $githubReleases ="https://api.github.com/repos/$repo/releases"
    $githubDownload="https://github.com/$repo"
    Write-Host "Check for update...." -NoNewline
    $tag = (Invoke-WebRequest $githubReleases | ConvertFrom-Json)[0].tag_name
    if ($tag -eq $null)
    {
        Write-Host " can not determine latest release from Github" -ForegroundColor Red
    }
    else
    {
        if ($tag -eq $appVersion )
        {
	        Write-Host "you have the latest version ( $tag )" -ForegroundColor Green
        }
        else
        {
	        Write-Host "you do not have the latest version" -ForegroundColor Red
            Write-Host "  this version :  $appVersion , Version on GitHub :  $tag"  -ForegroundColor Red
	        Write-Host "  download script from Github at $githubDownload. "  -ForegroundColor Red
        }
    }

}


Function cleanupStats
{
    Write-Host ""

    Write-Host "Before " $diskStatusBefore
    Write-Host "After " $(DiskSpaceStatus)
    Write-Host "==> Cleaned up $(formatBytes ($freeBytesBefore-(diskFreeBytes)))"
    Write-Host "    since first run $(formatBytes ($global:startScriptFreeBytes-(diskFreeBytes)))"

   # $Finished = (Get-Date)

 #   $minutes=[math]::floor(($Finished - $Starters).totalminutes)
 #   $seconds=($Finished - $Starters).totalseconds - 60 * $minutes
 #   Write-Host "Elapsed Time: $minutes minutes,  $seconds seconds"
 #   Write-Host "Elapsed Time: $(($Finished - $Starters).totalseconds) seconds"
}

Function menuCheckDiskCheckFS
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
Function menuTempLargeFilesWholeDisk
{
    While (1 -eq 1)
    {
        $list="List temp files older then $global:RetentionDays days"
        $list+="|Delete temp files older then $global:RetentionDays days"
        $list+="|Scan for large files"
        $list+="|Return to main menu"
        Write-Host ""
        $answer=selectMenuOption "$thisAppName : Enter your choise:"  $list 'Quit' $TRUE
        Switch ($answer)
        {
            {$_ -eq 1} {OldLogTempFiles $FALSE;Break}
            {$_ -eq 2} {OldLogTempFiles $TRUE;Break}
            {$_ -eq 3} {ShowLargeFiles;Break}
            {$_ -eq 4} {Return;Break}
            Default { Return }
        }
    }
}

Clear-Host 
New-Variable -Name appVersion -Value "v1.0" -Option ReadOnly -Force
checkForUpdate

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
$global:startScriptFreeBytes=diskFreeBytes
Write-Host "$thisAppName, clean disk C:\ Version $appVersion" 
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
    $first=$TRUE
    While (1 -eq 1)
    {
        if ($first -eq $TRUE)
        {
            $diskStatusBefore=DiskSpaceStatus
            $freeBytesBefore=diskFreeBytes
            $first=$FALSE
        }
        else
        {
            cleanupStats
        }
        $list="Change Retention days, is now set at $global:RetentionDays days"
        $list+="|Clean specific Temp folders, Internet browsers, Recycle Bin and Eventlogs"
        $list+="|sub-menu: Scan large files and temporary files across the disk"
        $list+="|Check RestorePoints, Rootfolders and Hibernation File"
        $list+="|Clean Software Distribution"
        $list+="|sub-menu: Check Disk and Filesystem"
        $list+="|Clean Windows Store"
        $list+="|Test"
        $list+="|Quit"
        Write-Host ""
        $answer=selectMenuOption "$thisAppName, Select an option:"  $list 'Quit' $TRUE
        Switch ($answer)
        {
            {$_ -eq 1} {$global:RetentionDays=$(enterNumber "Change retention days" $global:RetentionDays 7 1 30);Break}
            {$_ -eq 2} {cleanTempFolderBrowsersEventLog;Break}
            {$_ -eq 3} {menuTempLargeFilesWholeDisk;Break}
            {$_ -eq 4} {checkRestorePointsRootfoldersHibernationFile;Break}
            {$_ -eq 5} {cleanSoftwareDistribution;Break}
            {$_ -eq 6} {menuCheckDiskCheckFS;Break}
            {$_ -eq 7} {cleanWindowsStore;Break}
            {$_ -eq 8} {testNewStuff;Break}
            {$_ -eq 9} {exit;Break}
            Default { exit }
        }
    }
}