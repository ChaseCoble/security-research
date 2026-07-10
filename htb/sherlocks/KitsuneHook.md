# KitsuneHook — Threat Intelligence
**Platform:** Hack The Box Sherlocks
**Date Launched:** 2026-06-11
**Date Completed** 2026-07-09
**Difficulty:** Easy
**Category:** Threat Intelligence

## Scenario
Challenge presented a line of questioning concerning the activities of Winnti, specifically in reference to a campaign in early 2024

## Artifacts
Research only

## Investigation

### Question 1 — What is the primary APT designation number used to track this state-sponsored threat actor that has been active since at least 2012
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Since the name of the attacker was provided, Winnti, and the founding time, 2012, a brief research reveals the APT designation report by Mandiant

### Question 2 — What is Symantec's name for this group?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Google search - "[REDACTED APT NUMBER] symantec" which surfaced a Kapersky publication revealing Symantec's name for the group

### Question 3 - What is the name of the campaign that specifically targeted organizations in the manufacturing, materials, and energy sectors?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The Mandiant Report dated back to the APT designation, so was an insufficient source for the groups history. Google Search - "[REDACTED APT] energy manufacturing targeted." This not only revealed the finding, but also the original report of the incident by LAC, which will be used multiple times in the remainder of the investigation.
**Notes:** Interestingly, it was somewhat convuluted to surface the original report, which wasn't even in the top searches. I ultimately navigated from a wiz.io to hackernews to their citation to get the original report, and utilized Google Chrome's native translate function to read it in English. 
### Question 4 - What is the name of the leak that exposed software details of the groups malware?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Contained in the LAC report, they note the source of the leak and its importance in the investigation. Data was also extracted from a US Grand Jury indictment concerning another state sponsored group.
**Notes:** The integration of a Grand Jury Indictment from the United States (LAC is a Japanese security company) from another cyberespionage group shows how important correlation can be for an investigation.

### Question 5 - What is the name of the control panel for managing the Winnti Malware ecosystem?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** This controller was identified in the LAC report as well, and also was identified specifically in the leak and the referenced indictiment

### Question 6 - What version was found in the samples that showed this was the latest iteration of the malware?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The LAC report identified the version with a caveat of conflating two technologies, but is now considered to be validated.

### Question 7 - What type of vulnerability was utilized in the initial exploit?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The MITRE ATT&CK mapping in LAC identified clearly the vulnerability for initial access

### Question 8 - The adversaries deployed multiple web shells including China Chopper and Behinder, what is the third shell?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The LAC report has a heading for the WebShell portion of the attack that lists all 3 of the shells as well as thier methods of operation and probably sources.

### Question 9 - Behinder uses a encryption key consisting of the first 16 characters of the MD4 hash of what word?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Google Search - "Behinder Encryption Key" Revealed a SANGFOR report on Behinder that identifies the signature hash for the default key.

### Question 10 - Which malware uses Microsoft Graph API to fetch commands from email messages?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Interestingly, LAC report did not cover this. However, it does mention some aliases for the group and possible members, one of which is Earth Freyberg. Trend Micros breakdown on Freybergs methods in the campaign reveals the name of the mentioned malware. 
**Notes** During the research I kind of got in the weeds on Microsoft Graph API exploits and I am shocked how many they are and how they continue to be found. Really highlights how integrations and conveniences invite new avenues of exploit.

### Question 11 - In the previously mentioned campaign, there is a loader component that drops the RAT and a kernel level rootkit, what are their names?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The LAC report documents the entire workflow of the attack, detailing the names for both the loader and the rootkit

###Question 12 - Which Windows Service is often abused by DLL side-loading using TSMSISrv.DLL?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The service is described in the execution flow description in the LAC report

###Question 13 - What AES encryption mode is used in the DAT file decryption?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** Under the Decryption of DAT files heading in the LAC report, this is detailed.

###Question 14 - Two samples of the DLL files show compilation timestamps of May 12 2021 and August 17 2021
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The LAC report mentions that the Winnti RAT with plugins was shown on a certain campaign, and a quick google search confirmed the dates lined up.

###Question 15 - The Winnti_Rootkit YARA rule developed by LAC Co. contains some detection strings. What was the string concerning sound hardware?
**Finding:** [REDACTED - challenge less than 6 months old]
**Method:** The LAC report has YARA rules in the appendix. One must remember that some Japanese reports do not use \\ syntax.

## Key Takeaways
- The ********** campaign demonstrates a sophisticated multi-stage infection 
  chain — sideloading to loader to RAT to kernel rootkit — where each component 
  serves a distinct operational purpose. Understanding the chain matters more than 
  knowing individual tool names.
- Primary source primacy is critical in APT research. Multiple vendors name the 
  same tools differently. LAC Co. as the original reporting vendor had the most 
  accurate and specific nomenclature for this campaign, going to secondary sources 
  first caused significant wasted research time.
- YARA rules are underutilized as a research tool. The device object path answer 
  was only findable by reading the rule strings directly rather than relying on 
  prose reporting.
- YARA rule analysis requires awareness of locale-specific encoding conventions.
  The LAC YARA rule used a fullwidth yen sign (¥) as a path separator rather than
  the standard ASCII backslash, consistent with Japanese Shift-JIS encoding where
  ¥ maps to the backslash character. A naive string search without accounting for
  this substitution would fail to match, demonstrating that effective OSINT
  requires cross-cultural and encoding awareness.

## References
- LAC Co., Ltd. - ******** campaign analysis
- Trend Micro - Earth Freybug's Recent Campaign
- Mandiant - APT** Campaign Reporting
