**Alert Summary**

A sequence of suspicious activities was identified involving PowerShell which spawned a cmd terminal, which in turn spawned and executed system utilities such as reg.exe, ScEdit.exe and cscirpt.exe.

**MITRE ATT&CK Mapping**

- T1547.001 - Registry Run Keys / Startup Folder
- T1059.001 - PowerShell Execution
- T1059.003 - Command Shell

**Investigation Details**

- **Initial Execution**

PowerShell was identified was initiating process of cmd, which later spawned child processes such are ScEdit.exe, cscript.exe, which are system utilities. This indicates automated script execution rather than manual user interaction.

- **Registry Persistence**

Registry modifications were observed:

- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx

These modifications establish persistence by executing payloads during system startup or user logon.

- **Startup Folder Persistence**

Files were copied into Startup directories:

- C:\\Users\\root\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\
- C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\

Scripts such as .vbs and .jse were executed using cscript.exe, ensuring execution upon login.

- **Script & Payload Execution**

Scripts and batch files were executed, including:

- VBScript (.vbs)
- JScript (.jse)
- Batch files (.bat)

These were executed using cscript.exe and cmd.exe, indicating staged execution of payloads.

- **Advanced Registry Modifications**

Critical registry keys were modified, including:

- Winlogon (Userinit, Shell)
- Session Manager (BootExecute)

These modifications enable execution at system startup and indicate advanced persistence techniques.

The observed activity demonstrates automated execution of multiple persistence mechanisms within a short time frame, which is highly indicative of scripted or malicious behaviour rather than normal administrative activity.

The use of multiple persistence techniques suggests an attempt to ensure redundancy and maintain access even if one method is detected or removed.

Additionally, the use of legitimate system binaries (PowerShell, cmd.exe, reg.exe, cscript.exe) indicates Living-off-the-Land techniques, commonly used by attackers to evade detection.

**Timeline**

| **Time** | **Event**                       |
| -------- | ------------------------------- |
| 08:59:59 | PowerShell execution initiated  |
| 08:59:59 | cmd.exe spawned                 |
| 08:59:59 | reg.exe added Run key           |
| 09:00:01 | RunOnce registry modified       |
| 09:00:05 | Files copied to Startup folders |
| 09:00:05 | cscript.exe executed scripts    |
| 09:00:07 | Batch file executed             |
| 09:00:11 | Winlogon registry modified      |
| 09:00:13 | Session Manager modified        |

**Splunk Queries Used**

_index=main sourcetype="xmlwineventlog" User="ROOT\\\\root" | search "cmd" OR "reg.exe" OR "\*powershell" | table \_time User ParentImage CommandLine Image_

The query searches for all the logs and retrieves results where the user is root, and searches for processes such as cmd, reg.exe or powershell.

**Severity Assessment**

Severity: **High**

Reason:

- - Multiple persistence mechanisms
    - System-level registry modification
    - Script-based execution
    - Use of LOLBins

**Conclusion**

The activity is classified as a True Positive, demonstrating multiple persistence techniques executed via PowerShell and system utilities.

The observed behavior closely resembles real-world attacker techniques used to establish redundant persistence and evade detection.

In a production environment, this activity would require immediate escalation for further host investigation.
