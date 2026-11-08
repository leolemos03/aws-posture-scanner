# AWS Cloud Security Posture Scanner (CSPM)

An automated, lightweight Cloud Security Posture Management (CSPM) tool built in Python using AWS Boto3. The scanner audits AWS infrastructure against security best practices, detects critical misconfigurations across Identity, Storage, and Compute services, and exports audit findings into timestamped JSON reports.

---

## Author
* **Leonardo Lemos da Silva (Leo Lemos)**
* Focus: Cloud Security Engineering & Systems Administration

---

## Project Overview & Objectives

In cloud environments, misconfigurations (such as unrestricted administrative access or exposed storage buckets) represent one of the leading vectors for security breaches. 

This project aims to:
* **Automate Security Visibility:** Provide fast, programmatically accessible posture assessments without requiring complex, third-party enterprise tooling.
* **Identify High-Risk Attack Vectors:** Surface unauthenticated public access, lack of multi-factor authentication (MFA) on IAM principals, and open management ports.
* **Demonstrate Modular Architecture:** Follow clean coding design patterns with isolated audit engines orchestrated by a central execution workflow.
* **Deliver Structured Telemetry:** Output findings directly to the console while generating machine-readable JSON reports for ingestion into downstream reporting or SIEM pipelines.

---

## System Architecture

The application adopts an orchestrator-worker pattern. The central orchestrator (`scanner.py`) initializes AWS API sessions, runs modular checks located inside `audits/`, consolidates security findings, prints human-readable telemetry, and saves the final audit report.


aws-posture-scanner/
│
├── scanner.py                  # Orchestrator & report aggregator
├── requirements.txt            # Python dependencies (boto3)
├── .gitignore                  # Git hygiene (ignoring reports, cache)
├── README.md                   # Project documentation
│
├── audits/                     # Service-specific audit modules
│   ├── __init__.py
│   ├── s3_audit.py             # Amazon S3 public access audit
│   ├── iam_audit.py            # AWS IAM credential hygiene & MFA audit
│   └── ec2_audit.py            # Amazon EC2 security group exposure analysis
│
└── reports/                    # Generated audit logs
    └── scan_YYYYMMDD_HHMMSS.json

    