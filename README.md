# NVD Vulnerability Checker

This repository contains a Python script that scans a `requirements.txt` file for vulnerabilities using the National Vulnerability Database (NVD) API.

## Setup

1. **Install Dependencies:**  
   Run ``pip install requests packaging`` in your terminal.

2. **API Key:**  
   Create a file called ``NVD_key.txt`` in the project root directory and paste your NVD API key into it.

3. **Requirements File:**  
   Ensure you have a ``requirements.txt`` file listing your dependencies.

## Running the Script

To run the script, execute the following command in your terminal:

``python find_vuln.py``

After the script finishes, it will generate two CSV files in the project directory:
- ``found_vulnerabilities.csv`` – Contains detailed vulnerability information.
- ``vulnerability_summary.csv`` – Contains an aggregated summary per package, broken down into Critical, High, Medium, and Low severities.

## How It Works

- **Parsing Requirements:**  
  The script uses the `packaging` library to parse your ``requirements.txt`` robustly, supporting various version specifiers (>, <, ==, <=, >=). If a dependency has a pinned version (using ``==``), that version is used to filter vulnerabilities.

- **Querying the NVD API:**  
  For each dependency, the script performs a broad keyword search against the NVD CVE API. The API key is sent in the HTTP header.

- **Processing Vulnerabilities:**  
  The script examines each returned CVE to determine if it applies to the dependency by looking for the package name in the vulnerability's configuration. If a pinned version is provided, it filters the CVEs based on version ranges. Each CVE is then classified by severity (Critical, High, Medium, or Low) based on its CVSS v3.1 score.

- **CSV Output:**  
  The script produces two CSV files:
  - A detailed CSV (``found_vulnerabilities.csv``) listing each vulnerability.
  - A summary CSV (``vulnerability_summary.csv``) that aggregates the total number of vulnerabilities and a breakdown of Critical, High, Medium, and Low per package.

## License

This project is provided "as is" without any warranty. Feel free to use and modify the script as needed under the GPL.
