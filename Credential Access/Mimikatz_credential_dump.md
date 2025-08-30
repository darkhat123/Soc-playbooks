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

- cmd.exe, powershell.exe, or LOL used to spawn powershell.exe

- PowerShell execution with flags:

    -Invoke-WebRequest

    -System.Net.WebClient

- Suspicious command-line usage:

    - Invoke-WebRequest (IWR)
    - Invoke-Expression (IEX)
    - certutil.exe
    - mimikatz.exe
  


2. Network Connections (Sysmon Event ID 3)

- Outbound connections to external IPs/domains not in baseline - 192.168.1.105:8080

- Traffic to rare domains (e.g., dynamic DNS, free hosting)

- Use of non-standard ports for HTTP/HTTPS (e.g., 8080, 8443)


3. Script Contents (PowerShell ScriptBlock Logging, Event ID 4104)
- Downloader behavior:
    -Invoke-WebRequest fetching Mimikatz.exe

4. File Creation (Sysmon Event ID 11)

- Dropped Mimikatz.exe to admin account
- Random or suspicious filenames (e.g., Mimikatz.exe)

5. ProcessAccess (Sysmon Event ID 10)


# Detection

## Log Sources:

    Windows Event Logs (4688, 4104, 4103)
    Sysmon Event ID 1 Process Creation
    Sysmon Event ID 3 Network Connection
    Sysmon Event ID 11 File Creation
    Sysmon Event ID 10 ProcessAccess
    EDR/SIEM alerts


## Investigation Steps
- Find downloaded files (Sysmon Event ID 1)
- Find Created Files (Sysmon Event ID 11)
- Find Netowrk connections to external resources (Sysmon Event ID 3)
- Detect execution of downloaded file (Mimikatz.exe) (Sysmon Event ID 1)
- Detect Access to lsass from the malicious image (Sysmon Event ID 10)
- Check file reputation (Virustotal)
## Detection Query (Lab Demo):
### Detecting Process Creation (CMD to powershell - Use of Certutil.exe
`index=sysmon EventID=1 Image="*\\certutil.exe"
| table _time, Computer, User, ParentImage, CommandLine, Hashes
| sort _time`
Screenshot:<img width="1020" height="781" alt="image" src="https://github.com/user-attachments/assets/824a6855-f6ab-480a-b7c9-fa50185b0b0c" />

This will return any events detecting the use of Certutil to download files from the internet and can be useful in indentifying the staging of payloads such as downloading Mimikatz.exe before executing it

The command detected shows certutil being used to download mimikatz from an external source and saving it to disk. This Will likely lead to Network Conections (Event ID 3) being made to the external resource.

We can also take the hash of the file and check VirusTotal to determine its reputation.


### Detecting Process Creation (CMD to powershell) - Use of Invoke-WebRequest
`index="sysmon" EventID=1 Image="*\\powershell.exe*" 
(
    CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr*"
)
| table _time, Computer, User, CommandLine, ParentImage, Hashes
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
| table _time, Computer, User, ParentImage, CommandLine, ProcessId, Hashes`

Screenshot: <img width="1020" height="761" alt="image" src="https://github.com/user-attachments/assets/6327499d-17ed-4ab0-8a94-4efa855552c7" />

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


### Detecting Process Acesss
The `sekurlsa::logonpasswords` command in mimikatz is ran to dump the contents of the LSASS Service. LSASS is responsible for enforcing the security policy on the sytem. It handles logins, grants access tokens and manages password changes. All of these operations lead to credentials being available in the process memory of lsass.exe, this can be accessed with admin privileges and the credentials can then be dumped

Query: `index=sysmon EventID=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage="C:\\Users\\labadmin\\mimikatz.exe" |table SourceUser,Computer, GrantedAccess, SourceImage, TargetImage`
Screenshot: <img width="1019" height="766" alt="image" src="https://github.com/user-attachments/assets/00a856b4-2f14-43d5-a67e-91b66547a852" />

3. Investigation (Mapped to ATT&CK)

- Correlate parent-child process chains

- Look for abnormal spawns (winword.exe → powershell.exe, cmd.exe → certutil.exe).

    - MITRE:

        - T1059.001 – Command and Scripting Interpreter: PowerShell

        - T1218 – Signed Binary Proxy Execution (LOLBins like certutil.exe)

- Validate user context

- Identify if the process ran under a privileged account.

    - MITRE:

        - T1078 – Valid Accounts

        - T1078.002 – Domain Accounts

- Inspect command-line arguments

- Look for encoded or obfuscated PowerShell.

    - MITRE:

        - T1027 – Obfuscated Files or Information

        - T1059 – Command and Scripting Interpreter

- Check file and network artifacts

    - Event ID 11 (file creation of mimikatz.exe).

    - Event ID 3 (network connections for download).

    - MITRE:

        - T1105 – Ingress Tool Transfer

        - T1071.001 – Application Layer Protocol: Web Protocols

- Look for credential access attempts

    - Event ID 10 (ProcessAccess to lsass.exe).

    - MITRE:

        - T1003.001 – LSASS Memory

4. Containment (Mapped to ATT&CK)

- Process isolation (kill mimikatz.exe / PowerShell).

    - MITRE: N/A (defensive action).

- Host isolation (remove from network).

    - MITRE: N/A (defensive action).

- Account lockdown (disable/reset).

    - MITRE (attacker side): T1078 – Valid Accounts

    - Response: Stop adversary from leveraging stolen creds.

- Network controls (block IPs/domains).

    - MITRE (attacker side):

        - T1071 – Application Layer Protocol

        - T1090 – Proxy (if relays observed)

5. Eradication (Mapped to ATT&CK)

- Delete malicious binaries/scripts

- Remove mimikatz.exe and staged files.

    - MITRE:

        - T1105 – Ingress Tool Transfer

- Check persistence mechanisms (registry, scheduled tasks, services).

    - MITRE:

        - T1053 – Scheduled Task/Job

        - T1547 – Boot or Logon Autostart Execution

- Malware scanning

    - Detect secondary tools (Cobalt Strike, etc.).

    - MITRE:

        - T1055 – Process Injection (if beacon is injected)

        - T1105 – Additional payloads

- Privilege checks

    - Verify admin groups and local users.

    - MITRE:

        - T1098 – Account Manipulation

6. Recovery (Mapped to ATT&CK)

- Credential hygiene

    - Reset passwords, rotate Kerberos keys.

    - MITRE (attacker side):

    - T1558 – Steal or Forge Kerberos Tickets

    - T1552 – Unsecured Credentials

- System restoration

    - Restore clean images, patch systems.

    - MITRE: Prevents reinfection using known vulnerabilities (T1190 – Exploit Public-Facing Application).

- Monitoring
    
    - Ensure Sysmon + logging re-enabled.

    - MITRE:

        - T1562 – Impair Defenses

- Validation

    - Confirm no persistence remains.

    - MITRE:

        - T1547 – Persistence via Autostart

        - T1053 – Scheduled Tasks

7. Lessons Learned (Mapped to ATT&CK)

- Logging & Monitoring Improvements

    - Capture PowerShell Script Block, Sysmon IDs 1/3/10/11.

        - MITRE:

            - T1059.001 – PowerShell

            - T1003.001 – LSASS Memory

- Security Controls

    - AppLocker / WDAC to block unsigned tools.

    - Credential Guard to protect LSASS.

        - MITRE:

            - T1562 – Impair Defenses (mitigating attacker attempts to bypass).

- User & SOC Training

    - Spot phishing → Mimikatz delivery vector.

        - MITRE:

            - T1566 – Phishing

            - T1204 – User Execution

- Incident Simulation

    - Purple team exercises against credential dumping.

        - MITRE:

            - T1003 – Credential Dumping

            - T1555 – Credentials from Password Stores
