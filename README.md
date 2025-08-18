# HeaderGuard
HeaderGuard is a Python-based security tool that analyzes websites for essential HTTP security headers, SSL/TLS configuration, and cookie settings. It offers detailed insights and recommendations to assist developers, security testers, and ethical hackers in enhancing web application security and minimizing exposure to common threats.

<p align="center">
  <img width="572" height="389" alt="image" src="https://github.com/user-attachments/assets/69fccdfc-5230-478f-99b0-a06fcfce64dd">
</p>

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
<p>
  <img width="1002" height="478" alt="image" src="https://github.com/user-attachments/assets/8fc236e7-3b8a-4594-a4c8-4f16af7dc897" />
</p>

⦁ Installing dependencies:
```bash
pip install -r necessarylibraries.txt
```
# Usage
⦁ Scanning a URL:
```bash
python HeaderGuard.py
```
<p align="center">
  <img width="324" height="365" alt="image" src="https://github.com/user-attachments/assets/e1af9304-48a4-4663-9180-0039b275b2b8" />
</p>

⦁ Scanning bulk URL:
```bash
python HeaderGuard.py --threads 10
```
⦁ Saving output:
```bash
  python HeaderGuard.py --save
```
# Options

⦁ -u, --url : Target URL

⦁ -i, --input : File containing list of URLs (one per line)

⦁ --threads : Number of threads for bulk scan (default 5)

⦁ --save : Save report to TXT file

<p align="center">
  <img width="531" height="155" alt="image" src="https://github.com/user-attachments/assets/8f651f93-fcdf-4442-95f4-322e840dc95c">
</p>


