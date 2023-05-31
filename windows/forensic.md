Windows artifacts  

Directory `C:\Windows\System32\config`:  
- SAM  
- SOFTWARE  
- SYSTEM

Directory `C:\Users\%username%`: 
- NTUSER.DAT  
- \AppData\Local\Microsoft\Windows\USRCLASS.DAT

Event logs `\Windows\System32\winevt\Logs`:  
- `Security.evtx`  
 Security-related events specified in the system audit policy  
- `System.evtx`  
Events of the operating system and its components
- `Windows PowerShell.evtx`  
Events related to the use of PowerShell  
- `Microsoft-Windows-TaskScheduler-Operational.evtx`  
Files storing data of mail clients and other user applications  
- `Microsoft-Windows-TerminalServices-LocalSessionManager-Operational.evtx`  
Session Manager Events  

Shortcuts (LNK)  
`C:\Users\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\`

Open/Save MRU:  
`NTUSER.DAT|Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`

Logon scripts:  
`NTUSER.DAT|Environment\UserInitMprLogonScript`  

Run & RunOnce keys (NTUSER.DAT, SOFTWARE):  
- `Microsoft\Windows\CurrentVersion\Run`  
- `Microsoft\Windows\CurrentVersion\RunOnce`   

RDP connections:  
- `Security.evtx` (Events 4624, 4625)  
- `Microsoft-Windows-TerminalServices-Local SessionManager%4Operational.evtx` (Events 21, 22, 25)  

Tasks:  
- `C:\Windows\System32\Tasks\Task_Name`  
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` (Events 106, 140, 141)

Services:
- `System.evtx` (Events 7030, 7045)

Shared data (USRCLASS.DAT):  
- `Local Settings\Software\Microsoft\Windows\Shell\Bags`  
- `Local Settings\Software\Microsoft\Windows\Shell\BagsMRU`

PowerShell events:
- 600 (`Provider "Variable" is Started`)
- 4103 (`Command Invocation`)
- 4104 (`Creating Scriptblock text`)

Actions on objectives (RDP):  
- NTUSER.DAT (`Software\Microsoft\Terminal Server Client\Servers`)
- Microsoft-WindowsTerminalServicesRDPClient%4Operational.evtx (Events 1024, 1102)