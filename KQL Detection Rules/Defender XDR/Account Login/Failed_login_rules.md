# Purpose
These detection rules exist to assist in quickly detecting malicious/anomalous Login events on windows machines locally.

The reference guide for identifying the schema of the SecurityEvents table and determining the key columns for filtering and gathering statistics on the data: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent
# Failed logins for a certain account within a 5 minute timeframe ( All Time)
In situations where we want to check what windows machines have have had a suspicious number of failed login attempts within an unfeasable timeframe we can look in the SecurityEvent table which stores the security events
for all windows hosts its configured to ingest these logs from. We then use the EventID as a filter to only show failed login attempts. Using the summarize we display the Failed Attempts which uses an aggregation function count ()
which will fill the FailedAttempts variable, we will make a unique set of computers that were used in the process of attempting to sign into the account. We will then count the number of Failed attempts for each
account using their account and a timeframe of five minutes, any with more than five records in these 5 minute bins will be returned

`SecurityEvent_CL
| where EventID_s == 4625
| summarize FailedAttempts = count(), Hosts = makeset(Computer)
          by Account = Account_s, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
`

This is useful for quickly identifying the User accounts that are being targeted with brute force attacks or password spray attacks and shows us all user accounts with these anomalous bursts that have been
attempted, alongside a set of hosts that the accounts were attempted on. 

From this we can further investigate also map out all entities that have been contacted and the scope of our invesitgation.

We would then use feed this list of usernames to a new KQL query and see if any of these logins with high activity were successfully logged into suggesting compromise of the user account and any associated
entities.

We can see here that many accounts have been contacted all within this same timeframe, this suggests a distributed password spraying and brute force attack on these hosts


This is an example of a historical query which can be useful for providing insights into the most targeted accounts and when they occured. However this would be filled with pointless data from years ago.

# Failed logins for a certain account within a 5 minute timeframe ( Near Real-Time)

`SecurityEvent_CL
| where EventID_s == 4625
| where TimeGenerated > ago(5m)
| summarize FailedAttempts = count()
          by Account = Account_s
| where FailedAttempts >= 5
`



What Accounts we are likely to find:

System Account login attempts
User account login attempts
Domain login attempts
Workgroup login attempts

What authentication types we can expect
Neogtiate NTLM

Just because a 4625 has been detected with a certain account doesnt suggest the account actually exists, we would need to gather more context to determine the existence of the account,
an easy way to do this is to find accounts that had many failed login attempts followed by a successful login

We would then want to enrich as much data about the alert as possible, if multiple attempts were made to connect to hosts wed want to know the hostnames, ip's, domain names, workgroup names and associated usernames

This lets us know what machine the attacker is on, what level of access he has, where he inititiated his attack from and what he might be able to do next

