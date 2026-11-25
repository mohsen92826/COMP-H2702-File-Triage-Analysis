# File Triage & Hash Analysis

**Module:** COMP H2702 – Scripting for Cybersecurity  
**Scenario:** C – File Triage & Hash Analysis

## Project purpose
This program examines the supplied safe teaching files. It records file details,
calculates SHA-256 hashes, compares each hash with the supplied reference CSV,
identifies duplicate files and saves reports.

## Files and folders
- `main.py` – the Python program
- `sample_files/` – the five supplied sample files
- `hashes_reference.csv` – the supplied reference hash list
- `reports/` – generated reports
- `File_Triage_Workflow.drawio` and `File_Triage_Workflow.png` – workflow diagram
- `requirements.txt` – package list
- `README.txt` – original dataset explanation

## Requirements
Python 3. The program currently uses Python's built-in modules, so no third-party
packages need to be installed.

## How to run
1. Open a terminal in the `File_Triage_Project` folder.
2. Run `python main.py`.
3. Press Enter to use the supplied `sample_files` folder.
4. Press Enter to use the supplied `hashes_reference.csv` file.
5. Read the results in the terminal.
6. Open the `reports` folder to view the TXT, CSV and JSON reports.

You can also enter a different safe folder path and reference CSV path when
prompted. The program processes the files directly inside the selected folder.

## What the program records
For each file, the program records its filename, extension, size in bytes,
last-modified time, SHA-256 hash and KNOWN/UNKNOWN status.

Files with the same SHA-256 hash are grouped as duplicates.

## Reports
The program creates:
- `reports/triage_report.csv`
- `reports/triage_report.txt`
- `reports/triage_report.json`

## Safety and limitations
The supplied files are safe synthetic teaching samples. Do not replace them
with malware or upload them to external services. A reference hash match means
the file has identical content to a reference entry; it does not explain the
file's behaviour. An UNKNOWN result does not prove that a file is malicious or
safe.

## Dataset
The supplied `README.txt` describes the teaching dataset and its intended use.
