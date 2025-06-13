 # Incident Response Project — Let’sDefend.io

Platform Used: https://letsdefend.io (Free SOC Analyst Lab Environment)
Alert Investigated: SOC145 – Ransomware Detected

## 📌 Summary
Severity: High
Type: Malware (Ransomware)
Details: The alert showed file creation date and time, source IP address, host name, file name, hash, and file size.

📝 Investigation Process
## ✅ Step 1: Took Ownership
Claimed the alert and initiated a new case in the platform.

## ✅ Step 2: Define Threat Indicator
Set Threat Indicator to "Others" based on evaluation of source address in:
Log Management
Endpoint Security

## ✅ Step 3: Review Logs and Host Data
Log Management: No activity was shown for the file creation date.
Endpoint Security:
No browser history
No command history
No network connection logs
→ Possible log or evidence tampering by attacker.

## ✅ Step 4: Malware Analysis
Tool Used: VirusTotal
Results: 60 security vendors + 3 sandboxes flagged the file as malicious (Confirmed ransomware).

## ✅ Step 5: C2 Communication Check
Reviewed logs to identify potential Command & Control (C2) communication.
 Result: No evidence found of C2 server interaction from the source IP.

## 📂 Documentation
Artifacts Added:
File hash
Source IP
Hostname
VirusTotal analysis
Analyst Note: Summarized findings and noted possibility of data being wiped.
Alert Status: Marked as True Positive

## ✅ Conclusion
The investigation confirms that this was a legitimate ransomware alert with multiple vendors validating the file as malicious. Although logs were limited, malware behavior and VirusTotal analysis confirmed the threat. Alert has been properly escalated and documented.
