# Overview

Playbook Name: Suspicious PowerShell Execution (Encoded Command)

MITRE ATT&CK ID: T1059.001 – PowerShell

Purpose: Provide a structured response workflow for detecting and responding to suspicious PowerShell execution attempts.

# Indicators of Compromise (IOCs)
1. Process Creation (Sysmon Event ID 1, Win Event ID 4688)

- cmd.exe, wscript.exe, or Office apps spawning powershell.exe

- PowerShell execution with flags:

    -ExecutionPolicy Bypass

    -EncodedCommand

    -File <script.ps1>

- Suspicious command-line usage:

    -Invoke-WebRequest (IWR)


2. Network Connections (Sysmon Event ID 3)

- Outbound connections to external IPs/domains not in baseline - 192.168.1.105:8080

- Traffic to rare domains (e.g., dynamic DNS, free hosting)

- Use of non-standard ports for HTTP/HTTPS (e.g., 8080, 8443)


3. Script Contents (PowerShell ScriptBlock Logging, Event ID 4104)

- Base64-encoded commands or large obfuscated strings


- Downloader behavior:
    -Invoke-WebRequest fetching remote files

4. File Creation (Sysmon Event ID 11)

- Dropped scripts/executables in Desktop

- Random or suspicious filenames (e.g., script.ps1)

- File extensions:

    -.ps1, .vbs, .bat outside trusted repos

# Detection

## Log Sources:

    Windows Event Logs (4688, 4104, 4103)
    Sysmon Event ID 1 Process Creation
    Sysmon Event ID 3 Network Connection
    EDR/SIEM alerts


## Detection Query (Lab Demo):
### Detecting Process Creation - Use of EncodedCommand argument
`index="sysmon" EventID=1 Image="*\\powershell.exe" CommandLine=*-EncodedCommand* | table _time Computer, User, CommandLine`
Screenshot:<img width="1025" height="655" alt="image" src="https://github.com/user-attachments/assets/5039da20-47e0-4520-974f-cf3486123d17" />

This shows us all commands executed by any users on the system that have the encodedcommand argument as part of their command line input


### Detecting Network Connections
This demonstrates how an attacker could gather information on network connections being made by powershell and display the results so they can correlate the time of the process creation with the network connection and see what hosts were contacted.
`index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort`
<img width="1103" height="796" alt="image" src="https://github.com/user-attachments/assets/e6c4356c-5bd0-40fd-8dfe-5aedb974c6b1" />

### Detecting File Creation

Now that we know that the attackerlab user has been used to launch a powershell attack and that we know the decoded command saved a file to disk we can check for any file creations with Sysmon Event ID 11 and filter 
for all created by powershell by the attackerlab account
`index="sysmon" EventID=11 Image="*\\powershell.exe" User="DESKTOP-IO6MLSF\\attackerLab" | table _time User, TargetFilename`
<img width="1002" height="684" alt="image" src="https://github.com/user-attachments/assets/3e323be3-69f4-42b2-bc5d-5fed86e03069" />

## Detection Query (Realistic Soc Use)
### Detecting Process Creation
In our lab demo we knew the ParentImage would be cmd but in a real environment there is various options an attacker can use, rather than focus on the parent image we know the image being run is powershell, we can instead focus on any events where the flags responsible for Encoded Commands are present.
`(index=sysmon OR index=win-event)
(
    (EventID=1 Image="*\\powershell.exe") 
    OR 
    (EventCode=4688 New_Process_Name="*\\powershell.exe")
)
CommandLine="*-EncodedCommand*"
| table _time, Computer, User, ParentImage, CommandLine
| sort _time`

Screenshot:<img width="1024" height="761" alt="image" src="https://github.com/user-attachments/assets/38a4ac06-fb88-4ea4-9162-b8d4a368a955" />


The command can then be decoded to determine what the attacker was trying to do, with knowledge that the attacker ran a script to invoke a web request for a malicious script to be saved to disk we should see a network connection too
<img width="1912" height="937" alt="image" src="https://github.com/user-attachments/assets/9f1c1739-5c49-4679-b1ad-dd8fdcc98386" />

### Detecting Network Creation
We can use the query provided in the lab demo as a reliable query to detect network connections made from any powershell instances
index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort

This is useful when determining the ip and port connected to at the time of the network connection, the URL can be obtained from the decoded command and will likely be a domain controlled by the attacker


### Detecting File Creations 
`index=sysmon EventID=11
(
    TargetFilename="*\\AppData\\Roaming\\*.exe" OR
    TargetFilename="*\\AppData\\Roaming\\*.ps1" OR
    TargetFilename="*\\AppData\\Local\\Temp\\*.exe" OR
    TargetFilename="*\\AppData\\Local\\Temp\\*.dll" OR
    TargetFilename="*\\Windows\\Temp\\*.exe" OR
    TargetFilename="*\\ProgramData\\*.exe" OR
    TargetFilename="*\\Startup\\*.lnk" OR
    TargetFilename="*\\Startup\\*.vbs"
)
NOT (Image="*\\Installer\\msiexec.exe")   /* filter known legit installers */
| table _time, Computer, User, Image, TargetFilename, ProcessId`

In a realistic soc environment we want to monitor all known user-writable directories for any executable files being dropped to detect any possible scripts an attacker could be adding to a computer.

This looks for any PE files, powershell scripts, Windows Shortcuts and VBscript files. This can detect both executables to be used in the execution phase of the attack chain and also detects persistence techniques.

1. Investigation

- Steps for an analyst to confirm malicious activity:

    - Review parent process (e.g., was it spawned from cmd.exe, wscript.exe, or winword.exe?).

    - Check user context — was it an admin or a normal user?

    - Review the full command line (especially if -EncodedCommand or suspicious IEX/Invoke expressions were used).

    - Search for downloaded payloads or connections to external IPs.

- Correlate with other logs (failed logins, scheduled tasks, lateral movement).

2. Containment

- Actions to stop the attack quickly:

    - Kill the PowerShell process.

    - Isolate the host from the network.

    - Disable the compromised account if applicable.

    -Block malicious IP/domain if identified.

3. Eradication

- Ensure persistence and payloads are removed:

    - Delete malicious scripts or scheduled tasks.

    - Remove unauthorized registry modifications.

    -Scan for malware with EDR/AV.

    -Verify no new local admin users were created.

4. Recovery

- Return system to a safe state:

    - Reset passwords of affected accounts.

    - Restore from backups if integrity is questionable.

    - Re-enable logging and monitoring if tampered with.

    - Reconnect host to the network after validation.

5. Lessons Learned

- To prevent recurrence:

    - Enable and forward PowerShell ScriptBlock Logging.

    - Use Constrained Language Mode or WDAC/AppLocker.

    - Require code signing for scripts in production.

    - Train SOC analysts to look for suspicious command-line usage.
