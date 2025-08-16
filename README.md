# HeaderGuard
HeaderGuard is a Python-based security tool that analyzes websites for essential HTTP security headers, SSL/TLS configuration, and cookie settings. It offers detailed insights and recommendations to assist developers, security testers, and ethical hackers in enhancing web application security and minimizing exposure to common threats.

# Features
- Scan for common HTTP security headers.
- Check SSL/TLS certificates.
- Inspect cookies for `HttpOnly`, `Secure`, and `SameSite` attributes.
- Multithreading support for bulk scans.
- Generate detailed TXT reports with findings and recommendations.

# Installation
⦁ Clone the respository:
```bash
git clone https://github.com/n1njag0g0/HeaderGuard.git

cd HeaderGuard
```

⦁ Installing dependencies:
```bash
pip install -r necessarylibraries.txt
```
# Usage
⦁ Scanning a URL:
```bash
python HeaderGuard.py -u https://github.com
```
⦁ Scanning bulk URL:
```bash
python HeaderGuard.py -i address.txt --threads 10
```
⦁ Saving output:
```bash
  python HeaderGuard.py -u https://github.com --save
```
# Options

⦁ -u, --url : Target URL

⦁ -i, --input : File containing list of URLs (one per line)

⦁ --threads : Number of threads for bulk scan (default 5)

⦁ --save : Save report to TXT file
