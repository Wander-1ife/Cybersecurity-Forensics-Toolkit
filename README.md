# 🔍 Cybersecurity Forensics Toolkit

## 📖 Introduction

This repository contains three Python scripts developed for forensic investigations: **Malware Forensics**, **Network Forensics**, and **Windows Forensics**. These scripts leverage a combination of programming libraries, APIs, and machine learning techniques to address key challenges in:

- Detecting malicious activity
- Assessing network vulnerabilities
- Examining system-level data

The purpose of this project is to document the technical implementation, results, and potential improvements of these tools — with a strong focus on their practical applications in cybersecurity and digital forensics.

---

## 🎯 Objectives

The primary goal of these tools is to streamline forensic investigations by providing automated methods for:

- **Analyzing files** to detect potential malware and suspicious content.
- **Examining network traffic** to identify anomalies or vulnerabilities.
- **Collecting system-level forensic data**, such as running processes, network activity, and user behavior.

The scripts aim to deliver detailed insights quickly, enabling investigators to make informed decisions.

---

## 🔬 Analysis and Results

### 🦠 Malware Forensics

The **Malware Forensics** script focuses on **static analysis**, examining files without executing them for safer investigation.

**Key Features:**

1. **File Hashing and Metadata Extraction**
   - Uses Python’s `hashlib` library for cryptographic hashes (MD5, SHA256).
   - Extracts file metadata via libraries like `pefile`, `Pillow`, and `PyPDF2`.

2. **Suspicious String Detection**
   - Matches file content against predefined keywords (e.g., malicious URLs, commands).

3. **VirusTotal Integration**
   - Connects to the VirusTotal API for checking file hashes against known threats.

4. **AI-Powered Analysis**
   - Utilizes a pre-trained sentiment analysis model repurposed for classifying strings as benign or potentially malicious, with confidence scoring.

---

### 🌐 Network Forensics

The **Network Forensics** script analyzes **packet capture (PCAP)** files to uncover network-based vulnerabilities.

**Key Features:**

1. **Protocol-Specific Inspection**
   - Parses PCAP files using the `pyshark` library.
   - Analyzes protocols such as HTTP, FTP, DNS, ARP, and ICMP.

2. **Anomaly Detection**
   - Uses the AI model to evaluate packet payload data, flagging suspicious patterns.

3. **Logging and Reporting**
   - Logs flagged packets with details like timestamps, protocol types, source and destination IPs.
   - Generates a JSON-based report for further analysis.

---

### 🖥️ Windows Forensics

The **Windows Forensics** script captures a snapshot of a Windows system’s current state, targeting anomalies or indicators of compromise.

**Key Features:**

1. **System Information Collection**
   - Gathers OS version, CPU stats, memory usage, and boot time.

2. **Monitoring Processes and Network Activity**
   - Lists active processes and network connections, excluding system-level processes.

3. **File Access Analysis**
   - Scans for recently accessed files to detect potential tampering or data exfiltration.

4. **User Account Enumeration**
   - Retrieves a list of user accounts via built-in Windows commands.

5. **Report Generation**
   - Compiles collected data into a human-readable text report summarizing forensic findings.

---

## ⚠️ Challenges and Discussion

While these tools demonstrate the power of combining automation, APIs, and AI in forensic investigations, certain limitations remain:

- **Static Analysis Scope:** Malware script is limited to static analysis; adding dynamic capabilities would increase its effectiveness.
- **Protocol Coverage:** The network script covers major protocols but lacks support for emerging standards like HTTP/3.

---

## 📌 Recommendations

To enhance the effectiveness of these tools, the following improvements are suggested:

1. **Fine-Tuning the AI Model**
   - Retrain the `distilbert` model on datasets tailored for malware and network anomalies.

2. **Dynamic Malware Analysis**
   - Integrate sandboxing techniques to execute and monitor files in a controlled environment.

3. **Unified Reporting**
   - Combine all three scripts into a centralized framework for cohesive reporting.

4. **Expanded Protocol Support**
   - Add support for newer protocols and incorporate geolocation data for flagged IPs.

---

## ✅ Conclusion

The **Malware Forensics**, **Network Forensics**, and **Windows Forensics** scripts together form a versatile and powerful toolkit for cybersecurity investigations. They offer automated, reliable methods for detecting threats, identifying vulnerabilities, and gathering forensic evidence. With further refinements, these tools can significantly advance the efficiency and accessibility of digital forensic investigations.

---
