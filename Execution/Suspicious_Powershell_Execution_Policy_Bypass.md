# Overview

Playbook Name: Suspicious PowerShell Execution (ExecutionPolicy Bypass)

MITRE ATT&CK ID: T1059.001 – PowerShell

Purpose: Provide a structured response workflow for detecting and responding to suspicious PowerShell execution attempts.

# Detection

## Log Sources:

    Windows Event Logs (4688, 4104, 4103)
    Sysmon Event ID 1 Process Creation
    Sysmon Event ID 3 Network Connection
    EDR/SIEM alerts

## Detection Query (Lab Demo):
### Detecting Process Creation
`index="sysmon" EventID=1 ParentImage="C:\\Windows\\System32\\cmd.exe" CommandLine="powershell  -ExecutionPolicy Bypass -File .\\script.ps1"| table _time, Computer, User, ParentImage, CommandLine`
Screenshot:<img width="1033" height="808" alt="image" src="https://github.com/user-attachments/assets/72628a0f-8c73-4716-a1ad-ae6c69063186" />

This demonstrates how an analyst may begin investigating the use of suspicious powershell commands using specific queries based on prior investigation steps.
### Detecting Network Connections
This demonstrates how an attacker could gather information on network connections being made by powershell and display the results so they can correlate the time of the process creation with the network connection and see what hosts were contacted and 
`index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort`
<img width="1103" height="796" alt="image" src="https://github.com/user-attachments/assets/e6c4356c-5bd0-40fd-8dfe-5aedb974c6b1" />

## Detection Query (Realistic Soc Use)
### Detecting Process Creation
`index="sysmon" EventID=1 Image="*\\powershell.exe"
(
    CommandLine="*-ExecutionPolicy Bypass*" OR 
    CommandLine="*-File *"
)
| table _time, Computer, User, ParentImage, CommandLine`

Screenshot:<img width="1025" height="765" alt="image" src="https://github.com/user-attachments/assets/625eb721-c2f8-4b11-a351-f1ae68d450a8" />

### Detecting Network Creation
We can use the query provided in the lab demo as a reliable query

3. Investigation

Steps for an analyst to confirm malicious activity:

Review parent process (e.g., was it spawned from cmd.exe, wscript.exe, or winword.exe?).

Check user context — was it an admin or a normal user?

Review the full command line (especially if -EncodedCommand or suspicious IEX/Invoke expressions were used).

Search for downloaded payloads or connections to external IPs.

Correlate with other logs (failed logins, scheduled tasks, lateral movement).

4. Containment

Actions to stop the attack quickly:

Kill the PowerShell process.

Isolate the host from the network.

Disable the compromised account if applicable.

Block malicious IP/domain if identified.

5. Eradication

Ensure persistence and payloads are removed:

Delete malicious scripts or scheduled tasks.

Remove unauthorized registry modifications.

Scan for malware with EDR/AV.

Verify no new local admin users were created.

6. Recovery

Return system to a safe state:

Reset passwords of affected accounts.

Restore from backups if integrity is questionable.

Re-enable logging and monitoring if tampered with.

Reconnect host to the network after validation.

7. Lessons Learned

To prevent recurrence:

Enable and forward PowerShell ScriptBlock Logging.

Use Constrained Language Mode or WDAC/AppLocker.

Require code signing for scripts in production.

Train SOC analysts to look for suspicious command-line usage.
