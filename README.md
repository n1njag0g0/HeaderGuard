# HeaderGuard
A useful tool that helps find missing or incorrectly set up security features on websites. These features, known as HTTP security headers, are important for keeping websites safe from various online threats, such as attacks that try to steal personal information or manipulate users.

# Features
⦁	Provides instructions to browsers about security policies.
⦁	Scans the website, checks headers, and updates the status to indicate whether the header is present or missing.
⦁	Allows scanning a single URL or multiple URLs
⦁	For the missing headers, recommendations are given on how to configure them properly.

# Installation
⦁ Clone the respository:
git clone https://github.com/n1njag0g0/HeaderGuard.git
cd HeaderGuard

⦁ Installing dependencies
pip install -r necessarylibraries.txt

# Usage
⦁ Scanning a URL:
python HeaderGuard.py -u https://example.com

⦁ Scanning bulk URL:
python HeaderGuard.py -i urls.txt --threads 10

⦁ Saving output:
python HeaderGuard.py -u https://example.com --save
