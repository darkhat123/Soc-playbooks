# Overview

Playbook Name: Mimikatz Credential Dump (LSASS Memory)


Tactic: Initial Access / Execution / Defense Evasion (depends on delivery method)
MITRE ATT&CK ID: T1105 – Ingress Tool Transfer

This covers the transfer or download of tools (like Mimikatz) to a compromised host.

- Example: downloading Mimikatz via Invoke-WebRequest, certutil, or WebClient.

Tactic: Credential Access

MITRE ATT&CK ID: T1003 – Credential Dumping

Specifically, Mimikatz accesses LSASS memory to retrieve:

- Plaintext passwords

- NTLM hashes

- Kerberos tickets

Sub-techniques depending on method:

- T1003.001 – LSASS Memory (most common with Mimikatz)

- T1003.002 – Security Account Manager (SAM)

- T1003.003 – NTDS (Active Directory) if domain controller

Purpose: Provide a structured response workflow for detecting and responding to downloading and executing mimikatz for Credential Access.

# Indicators of Compromise (IOCs)
1. Process Creation (Sysmon Event ID 1, Win Event ID 4688)

- cmd.exe, wscript.exe, or Office apps spawning powershell.exe

- PowerShell execution with flags:

    -EncodedCommand

    -File <script.ps1>

- Suspicious command-line usage:

    -Invoke-WebRequest (IWR)
    -Invoke-Expression (IEX)


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


# Detection

## Log Sources:

    Windows Event Logs (4688, 4104, 4103)
    Sysmon Event ID 1 Process Creation
    Sysmon Event ID 3 Network Connection
    Sysmon Event ID 11 File Creation
    EDR/SIEM alerts


## Detection Query (Lab Demo):
### Detecting Process Creation (CMD to powershell - Use of Certutil.exe
`index=sysmon EventID=1 Image="*\\certutil.exe"
| table _time, Computer, User, ParentImage, CommandLine
| sort _time`
Screenshot:<img width="1012" height="715" alt="image" src="https://github.com/user-attachments/assets/b1009df6-0195-47fc-b5e8-cb93ece257bd" />
This will return any events detecting the use of Certutil to download files from the internet and can be useful in indentifying the staging of payloads such as downloading Mimikatz.exe before executing it

The command detected shows certutil being used to download mimikatz from an external source and saving it to disk. This Will likely lead to Network Conections (Event ID 3) being made to the external resource.

### Detecting Process Creation (CMD to powershell) - Use of Invoke-WebRequest
`index="sysmon" EventID=1 Image="*\\powershell.exe*" 
(
    CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr*"
)
| table _time, Computer, User, CommandLine, ParentImage
| sort _time`
Screenshot:<img width="1059" height="783" alt="image" src="https://github.com/user-attachments/assets/a89903e1-3dba-4b26-8b8f-3ca62b7d2cc5" />

This will return any events detecting the use of IWR to download files from the internet and can be useful in indentifying the staging of payloads such as downloading Mimikatz.exe before executing it

The command detected shows Invoke-WebRequest being used to download mimikatz from an external source and saving it to disk. This Will likely lead to Network Conections (Event ID 3) being made to the external resource.

### Detecting Process Creation (Powershell In Memory) - Use of System.Net.WebClient
`index="win-event" EventID=4104 (ScriptBlockText="*System.Net.WebClient*" OR ScriptBlockText="*DownloadFile*")
| table _time, User, Computer, ScriptBlockText`
Screenshot:<img width="1059" height="783" alt="image" src="https://github.com/user-attachments/assets/a89903e1-3dba-4b26-8b8f-3ca62b7d2cc5" />

This will return any events detecting the use of System.Net.WebClient to download files from the internet and can be useful in indentifying the staging of payloads such as downloading Mimikatz.exe before executing it

The command detected shows System.Net.Webclient being used to download mimikatz from an external source and saving it to disk. This Will likely lead to Network Conections (Event ID 3) being made to the external resource.

**NOTE**
The first two detection queries can be changed to detect execution in memory from powershell in cases where cmd is not used to spawn powershell

**Invoke-WebRequest**: `index="win-event" EventID=4104 (ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*iwr*")
| table _time, User, Computer, ScriptBlockText`
Screenshot: <img width="1085" height="807" alt="image" src="https://github.com/user-attachments/assets/e826f371-df1e-448f-a9d7-5d864fb99b1b" />

**certutil**: `index="win-event" EventID=4104 ScriptBlockText="*certutil*"
| table _time, User, Computer, ScriptBlockText`
Screenshot: <img width="1022" height="773" alt="image" src="https://github.com/user-attachments/assets/6934a6d2-b9b1-4e16-8dc4-4d7fe7481892" />

### Detecting Process Creation (CMD to powershell) - Starting Mimikatz.exe
`index=sysmon OR index=win-event
(EventID=1 OR EventCode=4688)
Image="*\\mimikatz.exe*"
| table _time, Computer, User, ParentImage, CommandLine, ProcessId`

This will look for any executions of mimikatz.exe inclduing from CMD to powershell and in memory executions from previously spawned powershell sessions.

### Detecting Network Connections
This demonstrates how an attacker could gather information on network connections being made by powershell and display the results so they can correlate the time of the process creation with the network connection and see what hosts were contacted.
`index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort`
Screenshot: <img width="1015" height="762" alt="image" src="https://github.com/user-attachments/assets/3a5bd2be-e1aa-4564-bd44-5ef1ce61133c" />

### Detecting File Creations
In order to detect all files created we can run a command which looks for files being created by either powershell itself or the certutil utility. This will show commands executed from an already spawned powershell session also 
`index=sysmon EventID=11 (Image="*\\powershell.exe*" OR Image="*\\certutil.exe*") User="DESKTOP-IO6MLSF\\labadmin"
| table _time, User, Computer, Image, ProcessId, TargetFilename
| sort _time`

Screenshot: <img width="1018" height="790" alt="image" src="https://github.com/user-attachments/assets/5e64f67a-c9d9-40bf-bbeb-3c02a6eeca61" />


## Detection Query (Realistic Soc Use)
### Detecting Process Creation
In our lab demo we knew the ParentImage would be cmd but in a real environment there is various options an attacker can use, rather than focus on the parent image we know the image being run is powershell, we can instead focus on any events where the flags responsible for Execution in memory are present.
`index=sysmon OR index=win-event
(
    (EventID=1 Image="*\\powershell.exe") OR
    (EventCode=4688 New_Process_Name="*\\powershell.exe")
)
(CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*")
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort _time`

This looks in both the sysmon and Windows Event Viewer for events where powershell was used to run commands which will execute in memory.
Screenshot:<img width="1028" height="780" alt="image" src="https://github.com/user-attachments/assets/3f0f2832-f026-42b2-9757-429af92f0245" />




### Detecting Network Creation
We can use the query provided in the lab demo as a reliable query to detect network connections made from any powershell instances
`index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort`
<img width="1021" height="364" alt="image" src="https://github.com/user-attachments/assets/2021a740-58cf-40e9-b936-4a843f60198b" />

This is useful when determining the ip and port connected to at the time of the network connection, the URL can be obtained from the decoded command and will likely be a domain controlled by the attacker


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
