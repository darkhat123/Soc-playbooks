# Overview

Playbook Name: Suspicious PowerShell Execution (Executing in Memory Invoke-Expression)

MITRE ATT&CK ID: T1059.001 – PowerShell

Purpose: Provide a structured response workflow for detecting and responding to suspicious PowerShell execution attempts.

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
    EDR/SIEM alerts


## Detection Query (Lab Demo):
### Detecting Process Creation - Use of Invoke-Expression argument
`index="sysmon" EventID=1 Image="*\\powershell.exe" CommandLine="*Invoke-Expression*" | table _time Computer, User, CommandLine`
Screenshot:<img width="1019" height="687" alt="image" src="https://github.com/user-attachments/assets/dab79d7f-8b46-4cc0-b86f-eca24475b09d" />

This shows us any commands ran by users that will run in memory and can help us determine if any malware is being run in memory, this will not generate any EventID 11 file creation events but will still have EventID 3 network connnections.

The command first downloads a resource into a variable which the contents of is then passed to the Invoke-Expression command which runs the content in memory and does any commands such as downloading and printing a files contents without ever actuallyt touching the disk


### Detecting Network Connections
This demonstrates how an attacker could gather information on network connections being made by powershell and display the results so they can correlate the time of the process creation with the network connection and see what hosts were contacted.
`index="sysmon" EventID=3 Image="*\\powershell.exe" | table _time, User, Computer, Image,DestinationIp, DestinationPort`
<img width="1031" height="771" alt="image" src="https://github.com/user-attachments/assets/86f11b40-3580-4c2c-90ce-9d177150801a" />


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
