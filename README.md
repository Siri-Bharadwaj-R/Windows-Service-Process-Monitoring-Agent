# Windows Service & Process Monitoring Agent

A Windows security assessment agent for analyzing processes, services, startup configurations, process hierarchies, and executable signatures to identify suspicious or potentially unauthorized activity.

The agent combines **process monitoring, rule-based detection, service auditing, digital signature verification, risk scoring, structured logging, and automated PDF reporting** into a single security assessment workflow.

---

## Overview

Windows processes and services are common targets for malware execution, persistence, privilege escalation, and defense evasion.

This project provides a practical defensive security framework that examines the current state of a Windows system and identifies security-relevant anomalies through configurable detection rules and security baselines.

The assessment covers:

- Active processes and executable information
- Parent-child process relationships
- Windows service configurations
- Startup services and service permissions
- Whitelist and blacklist rules
- Executable digital signatures
- Security findings and severity levels
- Overall system risk
- Recommendations and remediation steps

---

## Features

### Process Monitoring

Collects information about currently running Windows processes, including:

- Process name
- PID
- Parent PID
- Executable path
- Process information required for security analysis

### Parent-Child Process Analysis

Builds a process hierarchy using PID and PPID relationships.

The analysis helps identify unusual process lineage and provides visibility into how processes were spawned.

Example:

```text
services.exe
    └── svchost.exe
         └── child_process.exe
```

Representative relationships are displayed in the terminal and included in the generated security assessment report.

### Windows Service Monitoring

Enumerates Windows services and analyzes relevant service configuration information, including executable paths and startup configuration.

### Startup Service Auditing

Audits automatically starting services to identify potentially risky configurations.

The audit can detect issues such as:

- Weak service permissions
- Suspicious service configurations
- Unusual executable locations
- Potential service-based privilege escalation risks

### Unauthorized & Suspicious Process Detection

Uses configurable security rules to identify processes that require investigation.

Detection includes:

- Whitelist comparison
- Blacklist comparison
- Executable path analysis
- Process relationship analysis
- Suspicious runtime conditions

### Digital Signature Verification

Checks executable files for valid digital signatures.

Unsigned or unverifiable executables are reported as security findings so that their origin and authorization can be reviewed.

### Rule-Based Detection

Detection logic is separated from the monitoring components through configurable JSON files.

```text
config/
├── whitelist.json
├── blacklist.json
├── rules.json
└── service_baseline.json
```

This allows security rules and baselines to be modified without changing the core monitoring architecture.

### Risk Assessment

Findings are classified into:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

The agent calculates an overall system risk score based on the detected findings.

Example:

```text
Risk: 75/100  HIGH
```

### Automated Security Reporting

After an assessment, the agent generates a structured PDF security report containing:

- Scan summary
- System risk assessment
- Severity distribution
- Detailed security findings
- Process information
- Service information
- Parent-child relationships
- Startup service findings
- Digital signature results
- Recommendations
- Next steps
- Scan information

### Logging

Assessment activity is recorded in timestamped application logs.

```text
logs/application.log
```

The logs provide a trace of the assessment process, detection results, auditing activity, and report generation.

---

## Detection Workflow

```text
START
  │
  ▼
Enumerate Processes & Services
  │
  ▼
Collect Process & Service Information
  │
  ▼
Build Parent-Child Process Tree
  │
  ▼
Run Security Detection Rules
  │
  ├── Whitelist / Blacklist Analysis
  ├── Process Relationship Analysis
  └── Executable Path Analysis
  │
  ▼
Audit Startup Services
  │
  ├── Service Configuration
  └── Service Permissions
  │
  ▼
Verify Executable Digital Signatures
  │
  ▼
Calculate System Risk
  │
  ▼
Generate Findings & Recommendations
  │
  ▼
Generate PDF Security Assessment
  │
  ▼
END
```

---

## Detection Categories

| Detection Area | Purpose |
|---|---|
| Process Monitoring | Enumerates and analyzes active processes |
| Parent-Child Analysis | Examines process lineage and relationships |
| Whitelist Detection | Identifies processes outside the approved baseline |
| Blacklist Detection | Detects configured prohibited processes |
| Executable Path Analysis | Examines potentially suspicious executable locations |
| Service Monitoring | Collects and analyzes Windows service information |
| Startup Service Audit | Examines automatically starting services |
| Service Permissions | Detects potentially weak service permissions |
| Digital Signatures | Identifies unsigned or unverifiable executables |
| Risk Assessment | Calculates overall system security risk |

---

## Security Assessment Report

Each completed assessment generates a PDF report in:

```text
reports/
```

The report provides a consolidated view of the system assessment, including detailed findings and supporting process, service, startup, and signature information.

---

## Project Architecture

```text
Windows-Service-Process-Monitoring-Agent/
│
├── config/
│   ├── whitelist.json
│   ├── blacklist.json
│   ├── rules.json
│   └── service_baseline.json
│
├── core/
│   ├── detection_engine.py
│   ├── process_monitor.py
│   ├── process_tree.py
│   ├── report_generator.py
│   ├── risk_engine.py
│   ├── rule_engine.py
│   ├── service_monitor.py
│   ├── signature_verifier.py
│   └── startup_audit.py
│
├── security_assessment_pdf/
│   ├── digital_signature_results.py
│   ├── finding_statistics.py
│   ├── pdf_generator.py
│   ├── process_information.py
│   ├── recommendations.py
│   ├── risk_overview.py
│   ├── scan_information.py
│   ├── security_findings.py
│   ├── service_information.py
│   └── startup_audit.py
│
├── utils/
│   ├── config_loader.py
│   ├── display.py
│   └── logger.py
│
├── tests/
│   ├── test_detection_engine.py
│   ├── test_process_monitor.py
│   ├── test_process_tree.py
│   ├── test_report_generator.py
│   ├── test_risk_engine.py
│   ├── test_service_monitor.py
│   ├── test_signature_verifier.py
│   └── test_startup_audit.py
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

---

## Technologies

### Programming

- Python

### Windows System Monitoring

- psutil
- Windows process information
- Windows service interfaces
- Executable signature verification

### Security

- Rule-based detection
- Process hierarchy analysis
- Service security auditing
- Whitelist / blacklist analysis
- Digital signature verification
- Risk scoring

### Reporting

- ReportLab
- Automated PDF generation

### Testing

- Python testing framework
- Unit tests for monitoring, detection, process trees, risk analysis, reporting, service auditing, startup auditing, and signature verification

---

## Installation

Clone the repository:

```powershell
git clone https://github.com/Siri-Bharadwaj-R/Windows-Service-Process-Monitoring-Agent.git
cd Windows-Service-Process-Monitoring-Agent
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate the virtual environment:

```powershell
.venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## Usage

Run the security assessment from the project directory:

```powershell
python main.py
```

The agent will perform the complete assessment and display the results in the terminal.

A PDF security assessment will be generated automatically in:

```text
reports/
```

Application logs will be stored in:

```text
logs/application.log
```

---

## Testing

Run the complete test suite with:

```powershell
python -m unittest discover tests
```

The test suite covers the major monitoring, detection, analysis, reporting, and verification components.

---

## Security Considerations

This project is intended for defensive security assessment and monitoring of Windows systems.

Some Windows process, service, permission, or executable information may require elevated privileges depending on the system configuration.

Findings should be reviewed before performing remediation or configuration changes.

---

## License

This project was developed as part of an internship project.
