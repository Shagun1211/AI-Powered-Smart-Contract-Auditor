# AI-Powered-Smart-Contract-Auditor

An AI-assisted security auditing platform for Solidity smart contracts that combines rule-based static analysis with Large Language Model (LLM) reasoning to identify vulnerabilities, explain security risks, and generate a professional audit report.

---

## Overview

Smart contracts are immutable once deployed, making security vulnerabilities extremely expensive to fix after deployment. This project automates the initial security review process by combining traditional static analysis with AI-powered semantic analysis.

The application analyzes Solidity contracts, detects common vulnerabilities, assigns severity levels, recommends fixes, and generates a downloadable PDF audit report.

---

## Key Features

- Static vulnerability detection using Slither
- AI-powered semantic analysis using Groq LLM
- Detection of common Solidity security issues
- Severity classification (Critical, High, Medium, Low)
- Security recommendations with mitigation suggestions
- Overall contract risk score
- Professional PDF audit report generation
- Simple web interface for uploading and analyzing contracts

---

## Workflow

```text
Upload Solidity Contract
            │
            ▼
 Static Analysis (Slither)
            │
            ▼
 AI Semantic Analysis (Groq LLM)
            │
            ▼
 Merge & Prioritize Findings
            │
            ▼
 Risk Score + Recommendations
            │
            ▼
 Generate PDF Audit Report
```

---

## Vulnerabilities Covered

- Reentrancy
- Integer Overflow / Underflow
- Access Control Issues
- Unchecked External Calls
- Timestamp Dependency
- Low-Level Calls
- Denial of Service
- Front-running Risks

---

## Technology Stack

| Component | Technology |
|----------|-------------|
| Backend | FastAPI |
| Language | Python |
| Static Analysis | Slither |
| AI Model | Groq LLaMA |
| PDF Reports | ReportLab |
| Frontend | HTML, CSS, JavaScript |

---

## Project Structure

```
Smart-Contract-Auditor/
│
├── main.py
├── parser.py
├── llm_analyzer.py
├── pdf_generator.py
├── index.html
├── vulnerable.sol
└── README.md
```

---

## Installation

```bash
pip install fastapi uvicorn
pip install slither-analyzer
pip install groq
pip install reportlab

solc-select install 0.8.0
solc-select use 0.8.0
```

---

## Running the Project

```bash
uvicorn main:app --reload
```

Open `index.html` in your browser and upload a Solidity contract for analysis.

---

## Future Improvements

- Support multiple Solidity compiler versions
- Multi-file project auditing
- OWASP-style security scoring
- Historical audit report storage
- Integration with GitHub repositories

---

## Author

**Shagun Peddulwar**

Computer Science Engineering Student

Interested in AI, Machine Learning, Blockchain Security, and Backend Development.
