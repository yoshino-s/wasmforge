$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument '/c sc.exe config wlms start=disabled & taskkill /F /IM wlms.exe > C:\Users\localuser\wlms-guard.log 2>&1'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "WfWlmsGuard" -Force -Trigger $trigger -Action $action -Principal $principal
Write-Host "TASK_REGISTERED"
