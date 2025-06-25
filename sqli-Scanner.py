#!/usr/bin/env python3
"""
Interactive SQL Injection Scanner with Direct URL Input
"""

import os
import subprocess
import time
import re
import json
import argparse
from datetime import datetime

# Global configuration
CONFIG = {
    "risk_level": 3,
    "test_level": 5,
    "threads": 5,
    "timeout": 600,
    "output_dir": "scan_results",
    "tor_proxy": None,
    "crawl_depth": 0
}

def create_output_directory():
    """Create unique output directory for scan results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"{CONFIG['output_dir']}/scan_{timestamp}"
    os.makedirs(output_path, exist_ok=True)
    return output_path

def get_target_urls():
    """Prompt user for URLs to scan"""
    print("\n" + "="*50)
    print("SQL INJECTION SCANNER - URL INPUT")
    print("="*50)
    print("Enter target URLs (one per line). Press Enter twice when done.")
    print("Examples:")
    print("  http://test-site.com/login.php")
    print("  https://example.com/search?query=test")
    print("  https://demo-site.net/profile?id=1\n")
    
    urls = []
    while True:
        try:
            url = input("URL> ").strip()
            if not url:
                if urls:
                    break  # Done entering URLs
                continue
                
            # Validate URL format
            if not re.match(r"https?://[^\s/$.?#].[^\s]*", url):
                print(f"  ! Invalid URL format: {url}")
                continue
                
            urls.append(url)
            print(f"  + Added: {url}")
            
        except KeyboardInterrupt:
            print("\n\nScan cancelled.")
            exit(0)
            
    return urls

def scan_url(url, output_path):
    """Perform SQLi scan on a single URL"""
    print(f"\n{'='*50}")
    print(f"SCANNING: {url}")
    print(f"OUTPUT: {output_path}")
    print("="*50)
    
    # Create safe filename for log
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", url)
    if len(safe_name) > 50:
        safe_name = safe_name[:50] + "_" + str(hash(url))[-5:]
    
    log_file = os.path.join(output_path, f"{safe_name}.log")
    
    # Build sqlmap command
    command = [
        "sqlmap",
        "-u", url,
        "--batch",               # Non-interactive
        "--output-dir", output_path,
        "--flush-session",      # Clear previous session
        "--risk", str(CONFIG["risk_level"]),
        "--level", str(CONFIG["test_level"]),
        "--threads", str(CONFIG["threads"])
    ]
    
    # Add optional parameters
    if CONFIG["crawl_depth"] > 0:
        command.extend(["--crawl", str(CONFIG["crawl_depth"])])
    
    if CONFIG["tor_proxy"]:
        command.extend(["--tor", "--tor-type=SOCKS5"])
    
    # Execute scan
    start_time = time.time()
    try:
        with open(log_file, "w") as log_handle:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Stream output to console and log file
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan started...")
            for line in process.stdout:
                print(line, end='')
                log_handle.write(line)
                log_handle.flush()
            
            # Wait with timeout
            try:
                process.wait(timeout=CONFIG["timeout"])
            except subprocess.TimeoutExpired:
                process.kill()
                print("\n[!] Scan timed out")
            
        # Capture any remaining errors
        if process.stderr:
            with open(log_file, "a") as log_handle:
                for line in process.stderr:
                    log_handle.write(line)
    
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {str(e)}")
        return False
    
    duration = time.time() - start_time
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scan completed in {duration:.2f} seconds")
    return True

def analyze_results(output_path):
    """Parse scan results and generate vulnerability report"""
    print("\n" + "="*50)
    print("ANALYZING RESULTS")
    print("="*50)
    
    summary = {
        "total_scans": 0,
        "vulnerable": 0,
        "vulnerabilities": []
    }
    
    # Process each log file
    for filename in os.listdir(output_path):
        if not filename.endswith(".log"):
            continue
            
        summary["total_scans"] += 1
        log_path = os.path.join(output_path, filename)
        
        # Parse log file
        with open(log_path, "r", errors="ignore") as f:
            log_content = f.read()
        
        # Extract scan details
        url_match = re.search(r"target URL: (https?://[^\s]+)", log_content)
        url = url_match.group(1) if url_match else "Unknown URL"
        
        # Check for vulnerabilities
        vuln_found = False
        vuln_details = {
            "url": url,
            "vulnerable_parameters": [],
            "log_file": filename
        }
        
        # Find all vulnerable parameters
        vuln_sections = re.findall(
            r"Parameter: (.+?)\n\s+Type: (.+?)\n\s+Title: (.+?)\n\s+Payload: (.+?)(?=\n\n|\Z)", 
            log_content, 
            re.DOTALL
        )
        
        for param, vuln_type, title, payload in vuln_sections:
            vuln_found = True
            vuln_details["vulnerable_parameters"].append({
                "parameter": param,
                "type": vuln_type,
                "title": title.strip(),
                "payload": payload.strip()
            })
        
        # Add to summary if vulnerable
        if vuln_found:
            summary["vulnerable"] += 1
            summary["vulnerabilities"].append(vuln_details)
    
    # Generate reports
    generate_text_report(summary, output_path)
    generate_json_report(summary, output_path)
    
    return summary

def generate_text_report(summary, output_path):
    """Generate human-readable text report"""
    report_path = os.path.join(output_path, "scan_summary.txt")
    
    with open(report_path, "w") as f:
        f.write("SQL Injection Scan Summary\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total URLs Scanned: {summary['total_scans']}\n")
        f.write(f"Vulnerable URLs Found: {summary['vulnerable']}\n\n")
        
        if summary["vulnerable"] > 0:
            f.write("VULNERABILITIES FOUND:\n")
            f.write("=" * 50 + "\n")
            
            for i, vuln in enumerate(summary["vulnerabilities"], 1):
                f.write(f"\n#{i} URL: {vuln['url']}\n")
                f.write(f"  Log File: {vuln['log_file']}\n")
                
                for j, param in enumerate(vuln["vulnerable_parameters"], 1):
                    f.write(f"\n  Vulnerability #{j}:\n")
                    f.write(f"    Parameter: {param['parameter']}\n")
                    f.write(f"    Type: {param['type']}\n")
                    f.write(f"    Title: {param['title']}\n")
                    f.write(f"    Payload: {param['payload']}\n")
                
                f.write("\n" + "-" * 50 + "\n")
        else:
            f.write("No SQL injection vulnerabilities found\n")
    
    print(f"Text report generated: {report_path}")

def generate_json_report(summary, output_path):
    """Generate JSON report for programmatic use"""
    report_path = os.path.join(output_path, "scan_results.json")
    
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"JSON report generated: {report_path}")

def display_banner():
    """Show program banner"""
    print(r"""
   _____ ____  __  __       _      ____  _                
  / ___// __ \/ / / /      | | /| / / /_(_)___  ___  _____
  \__ \/ / / / / / /       | |/ |/ / __/ / __ \/ _ \/ ___/
 ___/ / /_/ / /_/ /        |__/|__/\__/_/ .___/\___/_/    
/____/\____/\____/                     /_/                

Interactive SQL Injection Scanner
=================================
""")

def main():
    """Main program execution"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Interactive SQL Injection Scanner")
    parser.add_argument('--risk', type=int, choices=range(1, 4), default=3,
                        help='Risk level (1-3, default=3)')
    parser.add_argument('--level', type=int, choices=range(1, 6), default=5,
                        help='Test level (1-5, default=5)')
    parser.add_argument('--threads', type=int, default=5,
                        help='Number of parallel threads (default=5)')
    parser.add_argument('--timeout', type=int, default=600,
                        help='Timeout per scan in seconds (default=600)')
    parser.add_argument('--crawl', type=int, default=0,
                        help='Crawl depth (0 to disable, default=0)')
    parser.add_argument('--tor', action='store_true',
                        help='Use Tor for anonymity')
    parser.add_argument('--output', default="scan_results",
                        help='Output directory (default=scan_results)')
    
    args = parser.parse_args()
    
    # Update configuration
    CONFIG.update({
        "risk_level": args.risk,
        "test_level": args.level,
        "threads": args.threads,
        "timeout": args.timeout,
        "crawl_depth": args.crawl,
        "tor_proxy": "socks5://127.0.0.1:9050" if args.tor else None,
        "output_dir": args.output
    })
    
    # Display banner and configuration
    display_banner()
    print("Scan Configuration:")
    print(f"  Risk Level: {CONFIG['risk_level']}")
    print(f"  Test Level: {CONFIG['test_level']}")
    print(f"  Threads: {CONFIG['threads']}")
    print(f"  Timeout: {CONFIG['timeout']} seconds")
    print(f"  Crawl Depth: {CONFIG['crawl_depth']}")
    print(f"  Tor: {'Enabled' if CONFIG['tor_proxy'] else 'Disabled'}")
    print(f"  Output Directory: {CONFIG['output_dir']}")
    
    # Get target URLs from user
    urls = get_target_urls()
    
    if not urls:
        print("\nNo URLs provided. Exiting.")
        return
    
    # Create output directory
    output_path = create_output_directory()
    
    # Perform scans
    for url in urls:
        scan_url(url, output_path)
    
    # Analyze results
    analyze_results(output_path)
    
    print("\nScanning complete! Check the output directory for results.")
    print(f"Full results at: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    main()