# AeroDrift

AeroDrift is a cloud security drift detection and self-healing prototype that models cloud infrastructure as a graph, detects unsafe configuration changes, generates remediation actions, verifies the fix, stores incident history, and generates incident reports.

## 🚀 Features

- Cloud infrastructure ingestion using mock AWS data
- Network topology generation using NetworkX
- Internet-to-database exposure detection
- Security drift detection
- Automated mock remediation
- Post-remediation verification
- Before/after topology diff
- SQLite-based drift history
- Rich CLI security dashboard
- Rich incident history table
- Automated incident report generation
- PDF incident report generation

## 🧠 How AeroDrift Works

```text
Mock AWS Configuration
          ↓
    AWS Data Ingestion
          ↓
    NetworkX Topology
          ↓
     Drift Detection
          ↓
   Remediation Engine
          ↓
    Mock Remediation
          ↓
   Verification Check
          ↓
    Topology Diff
          ↓
    SQLite History
          ↓
   Incident Report
          ↓
      PDF Report