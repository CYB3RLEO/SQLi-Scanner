# Interactive SQL Injection Scanner

A powerful, interactive command-line tool for detecting SQL injection vulnerabilities in web applications. This scanner integrates with `sqlmap` to provide real-time scanning and comprehensive reporting capabilities.

## Features

- **Interactive URL input** - Enter target URLs during runtime
- **Real-time scanning** - View live scan progress
- **Comprehensive reporting** - Generate both text and JSON reports
- **Customizable scanning** - Adjust risk level, threads, timeout, etc.
- **Anonymization support** - Route scans through Tor network
- **Crawling capability** - Automatically discover additional pages to test
- **Organized output** - Timestamped directories for each scan session

## Requirements

- Python 3.6+
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- (Optional) Tor for anonymous scanning

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/sql-injection-scanner.git
cd sql-injection-scanner
```

2. **Install dependencies**:
```bash
# Install sqlmap
pip install sqlmap

# Install Tor (optional, for anonymization)
sudo apt install tor
```

3. **Make the script executable**:
```bash
chmod +x sql_scanner.py
```

## Usage

### Basic Scan:
```bash
./sql_scanner.py
```

### Advanced Options:
```bash
./sql_scanner.py \
  --risk 3 \         # Risk level (1-3, default: 3)
  --level 5 \        # Test level (1-5, default: 5)
  --threads 8 \      # Parallel threads (default: 5)
  --timeout 900 \    # Timeout per scan in seconds (default: 600)
  --crawl 10 \       # Crawl depth (0 to disable, default: 0)
  --tor \            # Enable Tor anonymization
  --output results   # Custom output directory (default: scan_results)
```

### Interactive Session Flow:
1. The program displays a banner and configuration
2. Enter target URLs when prompted (one per line)
3. Press Enter twice when finished entering URLs
4. Scans execute sequentially with real-time output
5. Analysis runs automatically after all scans complete
6. Reports are generated in the output directory

## Output Structure

Each scan session creates a timestamped directory containing:
```
scan_YYYYMMDD_HHMMSS/
├── URL_safe_name.log       # Full scan log for each URL
├── scan_summary.txt        # Human-readable vulnerability summary
└── scan_results.json       # Machine-readable vulnerability report
```

Sample report contents:
```text
SQL Injection Scan Summary
==================================================

Scan Date: 2023-07-15 14:30:22
Total URLs Scanned: 2
Vulnerable URLs Found: 1

VULNERABILITIES FOUND:
==================================================

#1 URL: https://vulnerable-site.com/login.php
  Log File: https_vulnerable_site_com_login_php.log

  Vulnerability #1:
    Parameter: username
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=admin' OR 1234=1234--
```

## Legal and Ethical Considerations

⚠️ **IMPORTANT**: Only scan websites you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

- Always obtain proper authorization before testing
- Respect robots.txt and website terms of service
- Use the `--tor` option responsibly
- Never test production environments without explicit permission
- Delete scan results when they are no longer needed

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support or to report issues, please [open an issue](https://github.com/yourusername/sql-injection-scanner/issues) on GitHub.

---

**Disclaimer**: This tool is for educational and authorized testing purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any website.
