# Soc-playbooks

🛡️ Windows SOC Attack Simulation Lab
📖 Overview

This project sets up a Windows 10 virtual machine that is intentionally misconfigured to provide a safe environment for practicing detection engineering, adversary simulation, and blue team analysis.

The lab is designed to let you:

Generate realistic attacker activity from a Kali Linux machine.

Collect Windows event logs (Security, Sysmon, TerminalServices, SMB, RDP, etc.) into Splunk.

Explore the attack chain from initial access → execution → lateral movement → persistence → detection.

🎯 Lab Purpose

The goal of this lab is to simulate a Windows workstation that represents a "typical" but misconfigured enterprise endpoint, allowing you to:

Observe brute force attempts against RDP and SMB.

Analyze malicious process execution via Sysmon logs.

Detect failed and successful logons in Security & TerminalServices logs.

Test honey files and object access auditing.

Build and tune Splunk detections against attacker behavior.

⚙️ Key Features

Users & Groups

victimLab (target account)

attackerLab (simulated compromised credentials)

analystLab (blue team defender)

RedTeam / BlueTeam local groups

Misconfigurations for Attack Simulation

RDP and WinRM enabled (with Network Level Authentication disabled).

SMB and File & Printer Sharing enabled.

Advanced auditing enabled (Logon, Process Creation, File Share, etc.).

Honey files placed in sensitive directories.

Log Sources Ingested into Splunk

Security

Sysmon (process & network telemetry)

TerminalServices (RDP session activity)

System & Application logs

🧪 How It Works

Launch attacks from Kali Linux (brute force, lateral movement, credential dumping, etc.).

Windows 10 VM records the activity in event logs.

Logs are ingested into Splunk for hunting and detection.

Analyst investigates alerts and traces the attack chain.
