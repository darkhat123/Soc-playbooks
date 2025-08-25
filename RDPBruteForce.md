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

Attack Demonstrated: https://github.com/darkhat123/Attack-Demonstrations/blob/main/RDP%20Brute%20force%20No%20Nla%20Attack.md

# MITRE ATT&CK Framework Mapping

The brute force attack on RDP credentials demonstrated in this report aligns with specific techniques outlined in the MITRE ATT&CK framework, which is widely used for categorizing and understanding adversary tactics and techniques.

-**T1110** - Brute Force:
This technique involves the repeated guessing of passwords or credentials to gain unauthorized access. In this demonstration, we leveraged brute force tools to systematically attempt password combinations against the Remote Desktop Protocol service.

-**T1021.001** - Remote Services: Remote Desktop Protocol (RDP):
This sub-technique under Remote Services describes the use of RDP as a method for lateral movement or initial access. The attack exploited exposed RDP endpoints with weak or guessable credentials to gain unauthorized access.



-**T1078** – Valid Accounts - This technique is usually the result of a combination of the above two techniques successfully obtaining valid credentials

# Immediate Incident Response

- Isolate the affected systems: Temporarily block the attacking IPs at the firewall or network perimeter to stop ongoing attempts.

- Disable or lock compromised accounts: Immediately disable accounts showing signs of compromise or suspicious login activity.

- Force password resets: Reset passwords for accounts targeted or suspected to be compromised, especially with weak or default passwords.

- Review active sessions: Check for any active or unauthorized RDP sessions and terminate them.

2. Investigation and Forensics


- Check Windows Security Event Logs (4625, 4624, 4648) for login patterns.

- Review TerminalServices logs for session details.

- Correlate with Sysmon logs for process creation or network connections.

- Examine network captures: Use Wireshark or similar tools to confirm the attacker's behavior and tools used.

 - Identify attack sources: Map IP addresses and check for any repeated patterns or known malicious IPs.

- Check for persistence: Look for malware, backdoors, or scheduled tasks that could maintain attacker access.

3. Containment and Remediation

Implement stronger access controls:

- Enforce Network Level Authentication (NLA) on all RDP endpoints.

- Restrict RDP access to known IP addresses or VPN users.

- Enable account lockout policies to block accounts after a certain number of failed login attempts.

- Deploy Multi-Factor Authentication (MFA) for all remote access, including RDP.

- Apply patches and updates to RDP servers and endpoints.

- Audit user privileges and remove unnecessary admin rights.

5. Long-Term Prevention

- User education and training: Teach users about strong passwords and phishing risks.

Implement logging and alerting:

- Set up continuous monitoring for brute force patterns.

- Alert on multiple failed RDP logins or logins from unusual locations.
- Monitor Event IDs 4625, 4624, 4648 for anomalies
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

# Wireshark queries

## Identify all traffic related to RDP for a specific IP address
Command Used: `ip.addr == 192.168.1.113 and tcp.port==3389`

## Idenitfy only RDP Packets
Command Used: `ip.addr==192.168.1.113 && rdp`

With these two filters we can analyse the traffic and determine whats happening.
A typical indicator of brute force attacks is a significant number of repeating RDP connections which are then quickly terminated, no other traffic follows. Whilst it is unknown whether the tool obtained
valid credentials this can be used to pivot to the affected user and gain contextual information around the brute force attempt

## Identify TCP Reset flags for RDP
To determine whether the brute force was successful in obtaining credentials we can use Hydras treatment of the closing of sessions with the server. All failed attempts will have a RST,ACK to politely close the session from the server to the client. Whilst all successful logins will immediately terminate the connection via the client using just the RST flag

Command Used: `tcp.flags.reset == 1 and tcp.port == 3389`

From windows 10 onwards even with NLA disabled policies enforce the use of encrypted TLS and therefore no credentials are transmitted over the network.




