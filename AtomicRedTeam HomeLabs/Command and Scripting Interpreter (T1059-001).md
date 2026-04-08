**Alert Summary**

A suspicious process chain was identified involving PowerShell spawning CMD, which in turn spawned another PowerShell where it ran encoded commands. This behaviour is indicative of obfuscated script execution commonly associated with malicious activity.

**Event Details**

- Timestamp: 2026-04-07 16:32:02
- User: ROOT\\root
- Process Chain: powershell.exe → cmd.exe → powershell.exe
- Command Observed:
- "cmd.exe" /c powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==

**Detection & Query Analysis:**

The following Splunk query was used to identify suspicious PowerShell execution:

_index=\* Image="\*powershell.exe" |search "-e" | table \_time User Image CommandLine ParentImage_

This query filters for PowerShell processes executing encoded commands, which is a common indicator of obfuscation.

**Analysis**

- The initial PowerShell spawned a cmd terminal, which then spawned another PowerShell terminal where suspicious commands were run.
- The use of "-e" (encoded commands) flag suspicious behaviour and execution of Base64-encoded contents.
- The use of "cmd.exe /c" suggests non-interactive, automated execution.

**Hypothesis**

This activity likely represents obfuscated PowerShell execution, potentially related to:

- Initial access payload execution
- Post-exploitation scripting
- Living-off-the-land techniques (LOLBins)

**Investigation Steps Taken**

- Identified parent-child process relationship in logs
- Extracted and reviewed command-line arguments
- Detected Base64-encoded PowerShell execution
- Decoded payload for further analysis

**Indicators of Compromise (IOCs)**

- powershell.exe with "-e" flag
- cmd.exe spawning powershell.exe
- Suspicious process chain: PowerShell → cmd → PowerShell

**Severity Assessment**

Severity: **High**

Reason:

- Encoded PowerShell execution
- Multi-layered process chain
- Common attacker tradecraft

**Conclusion**

The alert is classified as a True Positive due to the detection of obfuscated PowerShell execution using Base64 encoding and Invoke-Expression (IEX), along with a suspicious process chain (powershell.exe → cmd.exe → powershell.exe). Although the decoded payload is benign and only prints a message, the techniques observed are commonly associated with malicious activity and defence evasion. This activity warrants further investigation and needs to be escalated to L2 for deeper analysis of the host, user activity, and potential related events.