**Incident: Privilege Escalation via PowerShell Malware Execution**

**Summary**

An attacker used compromised credentials to access an internal system and executed a PowerShell-based attack to download and run a malicious payload (svohost.exe), resulting in privilege escalation and system compromise.

**Triage**

The alert was triggered by endpoint security detecting execution of a suspicious binary. Initial validation confirmed:

- Unusual process execution
- PowerShell involvement
- External IP interaction

**Investigation & Analysis**

- Initial Access  
   Logs indicate that the attacker authenticated using valid credentials for user "Victor" from external IP 185.107.56.141.  
   This suggests potential credential compromise or reuse.
- Execution Chain Analysis  
   The malicious process: _svohost.exe was spawned by powershell.exe_

This parent-child relationship is suspicious because PowerShell is commonly abused by attackers to execute scripts and download payloads.

- Command Behavior Analysis  
   The PowerShell script performed the following actions:
  - Downloaded a file from an external source
  - Extracted it using 7-Zip
  - Executed the payload

This sequence is indicative of payload delivery + execution phase of an attack

- Threat Intelligence Correlation  
   The file hash was checked and flagged as malicious by multiple vendors (51/72), reinforcing the likelihood of malware execution.
- Behavioral Assessment  
   The combination of:
  - External login using valid credentials
  - PowerShell-based download activity
  - Execution of unknown binary

strongly indicates post-compromise exploitation and privilege escalation

**Conclusion**

There is high confidence that the system was compromised, with the attacker successfully executing malware and escalating privileges.

**Impact Assessment**

- Full system compromise
- Potential persistence mechanisms installed
- Risk of lateral movement
- Possible data exfiltration or further payload deployment

**Recommended Actions**

- Immediately isolate affected host
- Reset compromised credentials
- Block attacker IP
- Perform full endpoint forensic analysis
- Check for persistence mechanisms
- Review network logs for lateral movement