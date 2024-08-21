# File Scanner and Behavior Analyzer

This Python script is designed to scan files in a specified directory for known malicious signatures and analyze their behavior in a sandbox environment. The results of the scan are stored in a SQLite database and can also be saved to a text file.

## Features

- **MD5 Signature Calculation:** 
  - The script calculates the MD5 hash of each file and compares it with known malicious signatures.
  
- **Sandbox Analysis:**
  - Files are executed in a sandbox environment to detect suspicious behavior.

- **Directory Scanning:**
  - The script recursively scans all files within a specified directory.

- **Database Storage:**
  - Scan results are stored in a SQLite database for future reference.

- **Text File Export:**
  - Results can be saved to a text file for further analysis or record-keeping.

- **Result Display:**
  - Previously stored scan results can be displayed on the console.

## Prerequisites

- Python 3.x
- SQLite3
- A sandbox environment tool (e.g., `sandbox-executor`) for behavior analysis

## Installation

1. Clone this repository:
   ```bash
   git clone 
