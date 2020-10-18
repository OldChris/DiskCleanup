# DiskCleanup

## What is DiskCleanup?
A Powershell script to clean up you Windows C: drive.
It adds some extra cleanup options compared to Windows Disk Cleanup tool.

## How does it work?
DiskCleanup runs a series of standard Windows utilities and removes files from temp folders.
Here is a summary of it actions:
### runs the Windows Disk Cleanup utility,
### cleans eventlogs,
### remove memory dumps,
### cleans windows/temp folder,
### cleans windows/minidump folder,
### cleans windows/prefetch folder,
### cleans Windows Software Distribution folder using the dism utility, 
### removes old files in user's temporary folders,
### shows all temporary files older then given number of days, and and option to delete these files,
### shows large files (> 1 gigabyte).
## Who will use it?
Anybody who owns a Windows 10 PC, if you are not sure ask a friend to assist you.

## Goals, next steps
Improve code and add functionality, any suggestions are welcome.