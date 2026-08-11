# 🛡️ Windows Service & Process Monitoring Agent

> A Windows security assessment agent for process monitoring, service auditing, behavioral detection, digital-signature verification, risk scoring, and security reporting.

The **Windows Service & Process Monitoring Agent** is a Python-based defensive security tool designed to analyze Windows endpoint activity and identify potentially suspicious process and service behavior.

The agent collects system telemetry, analyzes process relationships, audits Windows services, checks executable signatures, detects suspicious configurations, calculates an overall security risk score, and generates a detailed security assessment report.

---

## 🎯 Project Overview

Windows processes and services are common targets for malware, persistence mechanisms, privilege escalation, and execution abuse.

This project provides a lightweight security assessment framework that examines these components using rule-based detection techniques.

The complete assessment follows this workflow:

```text
                    WINDOWS ENDPOINT
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
      PROCESS ENUMERATION        SERVICE ENUMERATION
             │                           │
             ▼                           ▼
      PROCESS TREE ANALYSIS        STARTUP AUDIT
             │                           │
             └─────────────┬─────────────┘
                           ▼
                  DETECTION ENGINE
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       BEHAVIORAL       PATH &       SIGNATURE
       DETECTION       SERVICE       VERIFICATION
                       ANALYSIS
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                      RISK ENGINE
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
            CONSOLE REPORT      PDF REPORT
                  │                 │
                  └────────┬────────┘
                           ▼
                  SECURITY ASSESSMENT
```

---

## 💡 Why This Project?

Windows systems are frequently targeted by malware that abuses processes and services to establish persistence, execute malicious code, escalate privileges, or hide activity.

The project focuses on identifying suspicious endpoint configurations and runtime behavior through:

- Process monitoring
- Process relationship analysis
- Windows service auditing
- Startup service analysis
- Rule-based detection
- Executable path analysis
- Digital signature verification
- Service permission analysis
- Risk scoring
- Structured security reporting

The goal is to provide a practical defensive-security assessment tool that helps identify areas requiring further investigation.

---

## 🎯 Project Objectives

The project was developed to:

- Monitor active Windows processes
- Collect process and parent-process information
- Build parent-child process relationships
- Detect suspicious process behavior
- Identify blacklisted processes
- Detect suspicious executable locations
- Enumerate and audit Windows services
- Analyze automatic/startup services
- Detect suspicious service configurations
- Detect potentially weak service permissions
- Detect newly added or modified services using a service baseline
- Verify executable digital signatures
- Generate security findings and recommendations
- Calculate an overall system risk score
- Maintain timestamped assessment logs
- Generate detailed security assessment reports

---

# 🔍 Key Features

## 1. Process Monitoring

The agent enumerates active Windows processes and collects information such as:

- Process name
- Process ID (PID)
- Parent Process ID (PPID)
- Executable path
- Process metadata

The collected information is passed to the analysis and detection components.

---

## 2. Parent-Child Process Analysis

The agent builds relationships between processes using Process IDs and Parent Process IDs.

This allows suspicious execution chains to be identified.

Example:

```text
Microsoft Word
      │
      └── PowerShell
```

Office applications spawning scripting interpreters such as:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`

can generate a security finding for further investigation.

---

## 3. Blacklisted Process Detection

Running processes are compared against configured blacklist entries.

The blacklist is stored in:

```text
config/blacklist.json
```

A matching process can generate a high-severity security finding.

---

## 4. Suspicious Executable Path Detection

The agent analyzes executable locations and identifies processes running from potentially risky directories.

Examples include:

```text
Temp
Downloads
Desktop
Public
```

AppData locations are also analyzed with trusted application paths taken into consideration.

Development environments such as:

```text
.venv
venv
```

are excluded from suspicious-path detection to reduce false positives when the monitoring agent itself is running inside a Python virtual environment.

---

## 5. Windows Service Auditing

The agent enumerates Windows services and collects information including:

- Service name
- Display name
- State
- Start mode
- Executable path
- Service account
- Process ID
- Description

This information is used for service configuration and startup analysis.

---

## 6. Startup Service Auditing

Automatic-start services receive additional security analysis.

The startup audit checks for potentially suspicious configurations including:

- Suspicious executable paths
- Unexpected service accounts
- Missing executable paths
- Weak service permissions
- Service configuration changes
- Newly detected services

---

## 7. Service Permission Analysis

The agent analyzes Windows service security configuration and identifies potentially dangerous service-management permissions granted to broad principals.

The assessment can identify permissions such as:

```text
SERVICE_CHANGE_CONFIG
WRITE_DAC
WRITE_OWNER
GENERIC_WRITE
GENERIC_ALL
```

Potentially dangerous permissions are reported as security findings for investigation.

The agent does not automatically modify the affected service configuration.

---

## 8. New & Modified Service Detection

The agent maintains a local Windows service baseline:

```text
config/service_baseline.json
```

The baseline is intentionally local and is excluded from version control.

It can be used to identify changes between assessments, including:

- Newly added services
- Modified service executable paths
- Modified startup modes
- Modified service accounts

This provides a simple mechanism for detecting service configuration changes over time.

---

## 9. Digital Signature Verification

Executable files associated with running processes are checked for digital signatures.

The verification process records information such as:

- Executable path
- Signature status
- Publisher information
- Verification result

Unsigned executables are reported as security findings requiring investigation.

> **Important:** An unsigned executable is not automatically malicious. It is treated as a security observation that should be investigated.

---

# ⚠️ Risk Assessment

Security findings generated by the detection components are passed to the risk engine.

The agent calculates an overall:

```text
Risk Score: 0–100
```

and maps the result to a severity level:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Example:

```text
╭──────────────────────────────────────╮
│          SECURITY ASSESSMENT         │
├──────────────────────────────────────┤
│ Processes Scanned : 325              │
│ Services Scanned  : 311              │
│ Findings          : 5                │
│ Risk Score        : 75 / 100         │
│ Risk Level        : HIGH             │
╰──────────────────────────────────────╯
```

The risk score provides a high-level summary of the findings identified during the assessment.

---

# 📊 Reporting

The agent provides both a formatted command-line security assessment and a detailed PDF report.

## Console Reporting

The CLI displays:

- Scan progress
- Number of processes collected
- Number of services collected
- Detection findings
- Startup audit results
- Signature verification results
- Risk score
- Risk level
- Scan duration
- Security findings
- Recommendations
- PDF report location

The assessment follows seven primary stages:

```text
[1/7] Collecting active Windows processes
[2/7] Collecting Windows services
[3/7] Building parent-child process tree
[4/7] Running security detections
[5/7] Auditing startup services
[6/7] Verifying executable digital signatures
[7/7] Calculating overall system risk
```

---

## 📄 PDF Security Report

After the assessment completes, a detailed PDF report is generated under:

```text
reports/
```

The report contains sections covering:

- Scan information
- Risk summary
- Security findings
- Process information
- Windows service information
- Startup service audit
- Digital signature verification
- Recommendations
- Final assessment

The PDF provides a consolidated record of the security assessment.

---

# 📝 Logging

Assessment activity is recorded in:

```text
logs/application.log
```

The logging system records events such as:

- Process scanning
- Windows service scanning
- Process-tree construction
- Detection analysis
- Startup service auditing
- Digital signature verification
- Risk assessment
- Report generation
- Assessment completion

Logs contain timestamps and severity levels to support troubleshooting and security analysis.

---

# 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| **Python** | Core implementation |
| **psutil** | Process enumeration and system telemetry |
| **WMI** | Windows service enumeration |
| **pywin32** | Windows-specific integration |
| **ReportLab** | PDF report generation |
| **Colorama** | CLI formatting and presentation |

---

# 🏗️ Project Architecture

The project is organized into separate monitoring, detection, analysis, reporting, and utility components.

```text
Windows-Service-Process-Monitoring-Agent/
│
├── config/
│   ├── whitelist.json
│   ├── blacklist.json
│   └── rules.json
│
├── core/
│   ├── __init__.py
│   ├── process_monitor.py
│   ├── process_tree.py
│   ├── service_monitor.py
│   ├── startup_audit.py
│   ├── detection_engine.py
│   ├── rule_engine.py
│   ├── risk_engine.py
│   ├── signature_verifier.py
│   └── report_generator.py
│
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── config_loader.py
│
├── security_assessment_pdf/
│   └── pdf_generator.py
│
├── docs/
│   └── TESTING.md
│
├── logs/
│   └── application.log
│
├── reports/
│   └── Security_Assessment_*.pdf
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

> `config/service_baseline.json` is generated locally by the application and intentionally excluded from version control.

---

# ⚙️ Installation

## 1. Clone the repository

```powershell
git clone https://github.com/Siri-Bharadwaj-R/Windows-Service-Process-Monitoring-Agent.git
```

```powershell
cd Windows-Service-Process-Monitoring-Agent
```

## 2. Create a virtual environment

```powershell
python -m venv .venv
```

## 3. Activate the virtual environment

```powershell
.venv\Scripts\Activate.ps1
```

## 4. Install dependencies

```powershell
pip install -r requirements.txt
```

---

# ▶️ Running the Agent

Run the monitoring agent from the project root:

```powershell
python main.py
```

The complete assessment pipeline is executed:

```text
Process Enumeration
        ↓
Service Enumeration
        ↓
Process Tree Construction
        ↓
Security Detection
        ↓
Startup Service Audit
        ↓
Digital Signature Verification
        ↓
Risk Assessment
        ↓
Console + PDF Reporting
```

After completion, review:

```text
logs/
```

for assessment logs and:

```text
reports/
```

for generated security assessment reports.

---

# 🧪 Testing & Validation

Testing and validation documentation is available in:

```text
docs/TESTING.md
```

The implementation has been validated using the following checks.

## Syntax Validation

```powershell
python -m compileall core utils security_assessment_pdf main.py
```

All Python source files compiled successfully without syntax errors.

## Core Module Import Validation

The major monitoring, detection, risk assessment, reporting, and PDF generation modules were successfully imported.

Expected result:

```text
ALL CORE IMPORTS OK
```

## End-to-End Validation

```powershell
python main.py
```

The complete assessment pipeline was successfully executed, including:

1. Process enumeration
2. Windows service enumeration
3. Process tree construction
4. Security detection
5. Startup service auditing
6. Digital signature verification
7. Risk assessment
8. Console reporting
9. PDF report generation

---

# 🛡️ Security Scope

This project is designed as a **defensive Windows security monitoring and assessment tool**.

It can be used for:

- Endpoint security analysis
- Windows security monitoring
- Detection engineering
- Security research and learning
- Defensive cybersecurity experimentation
- Security assessment reporting

The agent focuses on:

```text
OBSERVE → DETECT → ASSESS → REPORT
```

The agent does not automatically:

- Terminate processes
- Delete services
- Modify service permissions
- Remove executable files
- Remediate detected threats

Detected findings should be investigated and validated before taking corrective action.

---

# 🚫 Project Limitations

This project is **not**:

- ❌ An antivirus
- ❌ A malware removal tool
- ❌ A kernel-mode security driver
- ❌ A commercial EDR solution
- ❌ A replacement for Windows Defender
- ❌ A complete digital-forensics platform

The detection engine is rule-based and therefore may produce findings that require manual investigation.

For example:

> An unsigned executable or suspicious service path does not automatically mean that the file or service is malicious.

---

# 🔮 Future Improvements

Potential future extensions include:

- Real-time event-driven process monitoring
- Windows Event Log integration
- Advanced behavioral analytics
- Expanded service ACL analysis
- Improved executable reputation analysis
- Authenticode certificate-chain validation
- Persistent historical service baselines
- Email or webhook alerting
- Interactive graphical dashboard
- MITRE ATT&CK technique mapping
- Multi-host monitoring
- Centralized endpoint monitoring

---

# 📚 Documentation

Additional testing and validation information:

```text
docs/TESTING.md
```

Generated security assessment reports:

```text
reports/
```

Runtime logs:

```text
logs/
```

---

# 📌 Project Status

**Status: ✅ Functional Security Assessment Agent**

The current implementation includes:

- Process enumeration
- Process-tree analysis
- Parent-child detection
- Blacklist detection
- Suspicious executable-path detection
- Windows service enumeration
- Startup service auditing
- Service permission analysis
- New/modified service detection
- Digital signature verification
- Risk scoring
- CLI security reporting
- PDF security assessment
- Centralized logging
- Testing and validation documentation

---

# 👩‍💻 Project

## Windows Service & Process Monitoring Agent

A practical Windows defensive-security project focused on:

```text
╔══════════════════════════════════════════╗
║                                          ║
║       MONITOR → DETECT → ASSESS → REPORT ║
║                                          ║
╚══════════════════════════════════════════╝
```

Built with **Python** for Windows endpoint security analysis and defensive monitoring.