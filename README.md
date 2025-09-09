# windows-fix-default-profile
This powershell script fix problems with Default profile on Windows Server 2019

## For run this powershell script, execute, on Powershell console with administrative privileges, the follow command:
```powershell
PowerShell -ExecutionPolicy Bypass -File "C:\Users\usertest\Desktop\Fix-DefaultProfile.ps1"
```
### For including a test user creation step:
```powershell
PowerShell -ExecutionPolicy Bypass -File "C:\Users\usertest\Desktop\Fix-DefaultProfile.ps1" -CreateTestUser
```

### To search for events related to user profile failures:
```powershell
$ids = 1508,1509,1511,1515,1530
Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=$ids } -MaxEvents 30 |
  Select TimeCreated,Id,Message | Format-Table -Wrap
```
