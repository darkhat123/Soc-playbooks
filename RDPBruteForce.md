# Scenario: RDP Brute Force Attack
## Misconfigurations in the Lab

Remote Desktop Protocol (RDP) enabled → Provides remote access but greatly expands the attack surface.

Network Level Authentication (NLA) disabled → Removes an extra layer of pre-authentication security, making brute-force easier.

Weak or guessable credentials (attackerLab / 123456) → Simulates real-world poor password hygiene.

Excessive permissions (all local users can attempt RDP) → Increases the pool of accounts attackers can target.

Auditing enabled → Ensures all failed and successful attempts are captured in the Security and TerminalServices logs.

## Real-World Relevance

RDP is one of the most exploited attack vectors in enterprise environments. Misconfigured RDP often leads to:

Credential Stuffing & Brute Force Attacks → Attackers try weak passwords until they succeed.

Initial Access Vector for Ransomware → Many ransomware campaigns start with stolen or brute-forced RDP credentials.

Privilege Escalation & Lateral Movement → Once inside, attackers pivot across the network using RDP and SMB.


**This scenario teaches defenders how to:**

Detect brute force patterns (multiple failed logons followed by a success).

Monitor logon types (10 = remote interactive logon).

Alert on suspicious source IPs or abnormal access times.

Correlate activity in Splunk across Security, Sysmon, and TerminalServices logs.

Typical Brute Force Attack
An attacker will use publicly available brute force tools from github such as crowbar to supply a list of common passwords against a known username or with common usernames.

Attack Demonstrated {insert attack md link}


# Splunk Queries
Identify the sequence of Failed Login Events followed by a successful login

## Real time queries
Failed Login Event ID: 4625
Successful Login Event ID: 4624

`index=win-event (EventCode=4625 OR EventCode=4624) Logon_Type=10
| eval status=if(EventCode=4625,"Failed","Success")
| stats count(eval(status="Failed")) as failed_attempts 
        count(eval(status="Success")) as success_attempts 
        min(_time) as first_seen 
        max(_time) as last_seen 
        by Source_Network_Address TargetUserName
| where failed_attempts >= 3 AND success_attempts >= 1 AND (last_seen - first_seen) <= 600
| table Source_Network_Address TargetUserName failed_attempts success_attempts first_seen last_seen`

**Expected Output**
<img width="1027" height="775" alt="image" src="https://github.com/user-attachments/assets/99743530-61b2-4a92-94a9-9354cf40af04" />






