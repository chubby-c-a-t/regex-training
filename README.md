# SOC Analyst RegEx Ingestion Trainer
**Portfolio Project - SIEM Engineering and Data Parsing**

This repository is part of my cybersecurity portfolio. It is an interactive Python tool designed to simulate the challenges of parsing unstructured security logs in a SIEM environment.

---

## Purpose

In modern enterprise environments, security data arrives in completely unformatted structures (Syslog, Windows XML, CEF, JSON). A crucial duty of a SOC analyst or SIEM administrator is configuring parsing layers using Regular Expressions to create searchable, indexed fields. 

This project was specifically built to drill down on the skills required to configure `REGEX` stanzas in Splunk's `transforms.conf`. It dynamically generates unstructured logs and prompts the user to extract specific fields (like Source IPs, Usernames, or Process IDs), providing an interactive way to learn and test RegEx formatting.

---

## Security Context

An analyst's ability to hunt threats is directly tied to the quality of the data in their SIEM. If an SSH brute-force log or a WAF block log is not properly parsed upon ingestion, critical indicators of compromise (IoCs) will not trigger alerts. This trainer models the exact logs an analyst must normalize to ensure security telemetry is accurately indexed.

---

## Requirements

This tool requires no external dependencies outside of standard Python libraries.

1. **Python 3.x:** Ensure Python is installed on your system.
2. **Linux/Unix Environment:** The script utilizes the `readline` library for terminal navigation (arrow key support), which is native to Unix-like environments.

---

## Technical Implementation

The provided `regex_quiz_with_hints.py` script automates the generation of synthetic data and evaluates user input.

The engine executes the following logic:
- **Synthetic Log Generation:** Dynamically generates random IP addresses, usernames, Process IDs, and Timestamps using Python's `random` and `datetime` libraries.
- **Log Formatting:** Weaves these variables into realistic security logs, including standard Linux `sshd` failures, Apache Web Server logs, Fortinet CEF firewall blocks, and Windows Event ID formats.
- **Pattern Validation:** Uses Python's `re` standard library to compile the user's input, search the generated string, and evaluate the specific capture group `()` against the expected generated value.
- **Contextual Hint Engine:** Detects repeated failures or specific syntax errors and outputs context-aware RegEx hints tailored to the exact log type currently displayed.

---

## AI-Assistance Transparency

AI tools were utilized to assist in the development of the Python logic and RegEx hint formatting. All logic was reviewed, tested, and validated manually to ensure accuracy.

---

## Support & License

This project is not supported or maintained, existing solely as an artifact for my cybersecurity portfolio.

**License:** MIT License
