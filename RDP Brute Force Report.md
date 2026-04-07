**Incident: RDP Brute Force Leading to Account Compromise**

**Summary**

A series of repeated failed login attempts originating from an external IP address (218.92.0.56) targeted user "Mathew" on host 172.16.17.148, followed by a successful authentication. The pattern strongly indicates a brute-force attack resulting in credential compromise.

**Triage**

An alert was triggered indicating potential brute-force activity over RDP. Initial review confirmed:

- High volume of failed login attempts (Event ID 4625)
- Followed by a successful login (Event ID 4624) from the same IP

This sequence is a known indicator of credential brute-force attacks.

**Investigation & Analysis**

- Authentication Pattern Analysis  
   Multiple Event ID 4625 entries were observed within a short time window from a single external IP. This behaviour is abnormal, as legitimate users typically do not generate repeated failed login attempts at high frequency.
- Successful Compromise Confirmation  
   A subsequent Event ID 4624 confirmed successful authentication from the same IP, indicating that valid credentials were eventually discovered.
- Post-Login Activity Review  
   Following the successful login, command execution logs revealed the use of:

_whoami_

This suggests attacker interaction with the system to validate access level and privileges.

- Behavioural Assessment  
   The sequence of events (failed attempts → success → command execution) strongly suggests:
  - Credential brute-force attack
  - Unauthorized access to the system

**Conclusion**

Based on authentication patterns and post-login activity, there is high confidence that the account "Mathew" was compromised through a brute-force attack.

**Impact Assessment**

- Unauthorized access to internal host
- Potential exposure of sensitive data
- Risk of privilege escalation depending on user permissions
- Possible lateral movement within the network

**Recommended Actions**

- Immediately isolate host **172.16.17.148**
- Reset credentials for affected user
- Block source IP at firewall level
- Enable account lockout policies
- Enforce MFA for RDP access
- Review logs for lateral movement or persistence mechanisms