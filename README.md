# Soc-playbooks

🛡️ Windows SOC Attack Simulation Lab
📖 Overview

This project sets up a Windows 10 virtual machine that is intentionally misconfigured to provide a safe environment for practicing detection engineering, adversary simulation, and blue team analysis.

The lab is designed to let you:

- Generate realistic attacker activity from a Kali Linux machine.

- Collect Windows event logs (Windows Events, Sysmon, TerminalServices, SMB, RDP, etc.) into Splunk.

- Explore the attack chain from initial access → execution → lateral movement → persistence → detection.

🎯 Lab Purpose

The goal of this lab is to simulate a Windows workstation that represents a "typical" but misconfigured enterprise endpoint, allowing you to execute full attack chains in a windows environment
⚙️ Key Features

Users & Groups

- victimLab (target account)

- attackerLab (simulated compromised credentials)

- analystLab (blue team defender)

- RedTeam / BlueTeam local groups

Misconfigurations for Attack Simulation

- RDP and WinRM enabled (with Network Level Authentication disabled).

- SMB and File & Printer Sharing enabled.

- Advanced auditing enabled (Logon, Process Creation, File Share, etc.).

- Honey files placed in sensitive directories.

Log Sources Ingested into Splunk

- Windows Events
- Powershell 
- Sysmon (process & network telemetry)
- TerminalServices (RDP session activity)
- System & Application logs

🧪 How It Works

1. Launch attacks from Kali Linux (brute force, lateral movement, credential dumping, etc.).

2. Windows 10 VM records the activity in event logs.

3. Logs are ingested into Splunk for hunting and detection.

Analyst investigates alerts and traces the attack chain.
