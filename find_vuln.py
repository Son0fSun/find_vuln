import requests
import time
import csv
from packaging.requirements import Requirement
from packaging.version import parse as parse_version, InvalidVersion

# NVD CVE API endpoint
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_api_key(file_path="NVD_key.txt"):
    """Load the NVD API key from a file."""
    try:
        with open(file_path, 'r') as f:
            key = f.read().strip()
            if not key:
                print("Warning: API key file is empty.")
                return None
            return key
    except FileNotFoundError:
        print(f"Warning: Could not find {file_path}. Proceeding without API key.")
        return None

def parse_requirements(file_path):
    """
    Parse requirements.txt using packaging.requirements.
    
    Returns a dictionary mapping package names to either:
      - A pinned version string (if an '==' specifier is present)
      - Otherwise, the full SpecifierSet (which may be empty)
    """
    packages = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    req = Requirement(line)
                    # Look for a pinned version (==); if found, use that version.
                    pinned = None
                    for spec in req.specifier:
                        if spec.operator == "==":
                            pinned = spec.version
                            break
                    packages[req.name] = pinned if pinned is not None else req.specifier
                except Exception as e:
                    print(f"Error parsing requirement line '{line}': {e}")
        return packages
    except FileNotFoundError:
        print(f"Error: Could not find {file_path}")
        return {}

def query_nvd_api(keyword, api_key=None):
    """
    Query the NVD CVE API using a broad keyword search.
    
    The API key is passed in the HTTP header.
    """
    params = {"resultsPerPage": 2000, "keywordSearch": keyword}
    headers = {"User-Agent": "NVD-Vulnerability-Checker/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(NVD_CVE_URL, params=params, headers=headers, timeout=10)
        print(f"CVE API Response for '{keyword}': {response.status_code} - {response.text[:200]}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error querying NVD API for '{keyword}': {e}")
        return None

def classify_severity(cvss_score):
    """
    Classify the vulnerability based on the CVSS v3.1 score.
    
    Returns one of "Critical", "High", "Medium", "Low", "None" or "N/A".
    """
    try:
        score = float(cvss_score)
    except Exception:
        return "N/A"
    if score == 0.0:
        return "None"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    elif 9.0 <= score <= 10.0:
        return "Critical"
    else:
        return "Unknown"

def process_vulnerabilities(data, package_name, pkg_version=None):
    """
    Process the NVD vulnerability data.
    
    If pkg_version is provided (i.e. a pinned version from requirements.txt),
    the function attempts to filter CVEs by checking each vulnerability’s configuration 
    to see if the version would be affected.
    
    Only vulnerabilities whose configuration criteria include the package name 
    (case-insensitive) are considered.
    
    Each accepted vulnerability is annotated with a "Severity" field.
    """
    if not data or "vulnerabilities" not in data:
        return 0, []
    
    total_results = data.get("totalResults", 0)
    if total_results == 0:
        return 0, []
        
    vuln_data = []
    pkg_ver_obj = None
    if pkg_version:
        try:
            pkg_ver_obj = parse_version(pkg_version)
        except InvalidVersion:
            pkg_ver_obj = None

    for vuln in data["vulnerabilities"]:
        cve = vuln["cve"]
        cve_id = cve.get("id", "UNKNOWN")
        description = cve["descriptions"][0]["value"] if cve.get("descriptions") else ""
        affected = False if pkg_ver_obj else True

        if "configurations" in cve:
            for config in cve["configurations"]:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if package_name.lower() in cpe_match.get("criteria", "").lower():
                            if pkg_ver_obj:
                                try:
                                    if "versionEndExcluding" in cpe_match:
                                        end_ver = parse_version(cpe_match["versionEndExcluding"])
                                        if pkg_ver_obj < end_ver:
                                            affected = True
                                    elif ("versionStartIncluding" in cpe_match and 
                                          "versionEndIncluding" in cpe_match):
                                        start_ver = parse_version(cpe_match["versionStartIncluding"])
                                        end_ver = parse_version(cpe_match["versionEndIncluding"])
                                        if start_ver <= pkg_ver_obj <= end_ver:
                                            affected = True
                                    else:
                                        affected = True
                                except InvalidVersion:
                                    affected = True
                            else:
                                affected = True

        if affected:
            cvss_score = "N/A"
            if "metrics" in cve:
                if "cvssMetricV31" in cve["metrics"]:
                    cvss_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in cve["metrics"]:
                    cvss_score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            
            severity = classify_severity(cvss_score)
            print(f"CVE: {cve_id}")
            print(f"CVSS Score: {cvss_score} -> Severity: {severity}")
            print(f"Description: {description[:200]}...")
            print("-" * 80)
            vuln_data.append({
                "Package": package_name,
                "CVE": cve_id,
                "CVSS_Score": cvss_score,
                "Severity": severity,
                "Description": description
            })

    return len(vuln_data), vuln_data

def write_detailed_csv(vuln_data, filename="found_vulnerabilities.csv"):
    """Write the detailed vulnerability data to a CSV file."""
    if not vuln_data:
        print("No vulnerabilities to write to CSV.")
        return
    headers = ["Package", "CVE", "CVSS_Score", "Severity", "Description"]
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(vuln_data)
        print(f"Detailed vulnerability data written to {filename}")
    except Exception as e:
        print(f"Error writing detailed CSV: {e}")

def write_summary_csv(summary, filename="vulnerability_summary.csv"):
    """Write the aggregated vulnerability summary to a CSV file."""
    headers = ["Package", "Total", "Critical", "High", "Medium", "Low"]
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for pkg, stats in summary.items():
                row = {
                    "Package": pkg,
                    "Total": stats["Total"],
                    "Critical": stats["Critical"],
                    "High": stats["High"],
                    "Medium": stats["Medium"],
                    "Low": stats["Low"]
                }
                writer.writerow(row)
        print(f"Vulnerability summary data written to {filename}")
    except Exception as e:
        print(f"Error writing summary CSV: {e}")

def main(requirements_file="requirements.txt", key_file="NVD_key.txt"):
    api_key = load_api_key(key_file)
    if api_key:
        print("API key loaded successfully.")
    else:
        print("Running without API key – requests will be rate limited.")
    
    packages = parse_requirements(requirements_file)
    if not packages:
        print("No packages to process.")
        return

    total_vulns = 0
    all_vuln_data = []
    package_vuln_summary = {}
    print(f"\nScanning {len(packages)} packages for vulnerabilities...")
    print("=" * 80)
    
    for package, spec in packages.items():
        print(f"\nChecking package: {package}")
        if isinstance(spec, str):
            print(f"Pinned version: {spec}")
        else:
            print(f"Version specifier: {spec}")
        # Use the package name as the keyword for the NVD search.
        data = query_nvd_api(package, api_key=api_key)
        if data:
            vulns_found, vuln_data = process_vulnerabilities(data, package, pkg_version=spec if isinstance(spec, str) else None)
            total_vulns += vulns_found
            all_vuln_data.extend(vuln_data)
            
            # Build aggregated counts for this package.
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for v in vuln_data:
                sev = v.get("Severity", "N/A")
                if sev in sev_counts:
                    sev_counts[sev] += 1
            package_vuln_summary[package] = {
                "Total": vulns_found,
                "Critical": sev_counts["Critical"],
                "High": sev_counts["High"],
                "Medium": sev_counts["Medium"],
                "Low": sev_counts["Low"]
            }
            print(f"Vulnerabilities found for {package}: {vulns_found} "
                  f"(Critical: {sev_counts['Critical']}, High: {sev_counts['High']}, "
                  f"Medium: {sev_counts['Medium']}, Low: {sev_counts['Low']})")
        else:
            print(f"No vulnerabilities found or error occurred for {package}")
        sleep_time = 0.6 if api_key else 6
        time.sleep(sleep_time)

    print("\n" + "=" * 80)
    print("Final Vulnerability Summary per Package:")
    for pkg, summary in package_vuln_summary.items():
        print(f"{pkg}: Total {summary['Total']} "
              f"(Critical: {summary['Critical']}, High: {summary['High']}, "
              f"Medium: {summary['Medium']}, Low: {summary['Low']})")
    print(f"\nScan complete. Total vulnerabilities found: {total_vulns}")
    write_detailed_csv(all_vuln_data)
    write_summary_csv(package_vuln_summary)

if __name__ == "__main__":
    main("requirements.txt", "NVD_key.txt")
