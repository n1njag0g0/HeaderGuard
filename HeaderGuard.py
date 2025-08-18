#!/usr/bin/env python3
import requests
import argparse
from colorama import Fore, Style, init
import ssl
import socket
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

# Security headers with explanations and recommended values
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps prevent XSS attacks by controlling resources the browser is allowed to load.",
        "recommendation": "Content-Security-Policy: default-src 'self';"
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections, protecting against protocol downgrade attacks.",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking by controlling if the site can be loaded in a frame or iframe.",
        "recommendation": "X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing and forces the declared content type.",
        "recommendation": "X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is shared in requests.",
        "recommendation": "Referrer-Policy: no-referrer"
    },
    "Permissions-Policy": {
        "description": "Gives control over powerful browser features like camera, microphone, geolocation.",
        "recommendation": "Permissions-Policy: geolocation=(), camera=()"
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Protects against cross-origin data leaks in embedded resources.",
        "recommendation": "Cross-Origin-Embedder-Policy: require-corp"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Ensures a top-level document does not share browsing context groups with cross-origin documents.",
        "recommendation": "Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents resources from being loaded from unauthorized origins.",
        "recommendation": "Cross-Origin-Resource-Policy: same-origin"
    }
}

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
 _   _   _____    ____    _____     _____   _____
| | | | |  ___|  / __ \  | ____ \  |  ___| |  ___ \
| | | | | |     | |  | | | |   | | | |     | |   | |
| |_| | | |___  | |__| | | |   | | | |___  | |___| /
|  _  | |  ___| | ____ | | |   | | |  ___| |  ____ \
| | | | | |     | |  | | | |   | | | |     | |   | |
| | | | | |___  | |  | | | |___| | | |___  | |   | |
|_| |_| |_____| |_|  |_| |______/  |_____| |_|   |_|
       ____   _    _   ____   _____    _____
     / ____| | |  | | / __ \ |  ___ \ | ____ \
     | |     | |  | || |  | || |   | || |   | |
     | |     | |  | || |__| || |___| /| |   | |
     | |   _ | |  | || ____ ||  ____ \| |   | |
     | |  | || |  | || |  | || |   | || |   | |
     | |__| || |__| || |  | || |   | || |___| |
      \____/  \____/ |_|  |_||_|   |_||______/
    """)
    print(Fore.CYAN + "="*50)
    print(Fore.CYAN + Style.BRIGHT + "          HEADER GUARD v2.0  ")
    print(Fore.CYAN + "="*50)
    print(Fore.GREEN + " A lightweight Website Security Header Scanner")
    print(Fore.YELLOW + " For ethical hacking, testing & learning only\n")
    print(Fore.CYAN + "-"*50)

def check_ssl(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, cert
    except Exception as e:
        return False, str(e)

def scan_headers(url, save_report=False):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        cookies = response.cookies

        print(Fore.CYAN + f"\nSecurity Headers Analysis for: {url}\n" + Style.RESET_ALL)

        present_count = 0
        missing_headers = []

        for header, info in SECURITY_HEADERS.items():
            display_name = header.replace("-", " ")
            if header in headers:
                present_count += 1
                print(Fore.GREEN + f"PRESENT - {display_name}" + Style.RESET_ALL)
                print(f"    Value: {headers[header]}\n")
            else:
                missing_headers.append(header)
                print(Fore.RED + f"MISSING - {display_name}" + Style.RESET_ALL)
                print(f"    Recommendation: {info['recommendation']}\n")

        ssl_status, ssl_info = check_ssl(url)
        if ssl_status:
            print(Fore.GREEN + f"[+] SSL/TLS is valid for {url}\n")
        else:
            print(Fore.RED + f"[-] SSL/TLS issue: {ssl_info}\n")

        total_headers = len(SECURITY_HEADERS)
        percentage = (present_count / total_headers) * 100
        if percentage == 100:
            grade = Fore.GREEN + "A+ (Excellent Security)"
        elif percentage >= 80:
            grade = Fore.GREEN + "A (Strong Security)"
        elif percentage >= 60:
            grade = Fore.YELLOW + "B (Moderate Security)"
        elif percentage >= 40:
            grade = Fore.YELLOW + "C (Weak Security)"
        else:
            grade = Fore.RED + "F (Poor Security)"

        print(Fore.YELLOW + "=" * 60 + Style.RESET_ALL)
        print(Fore.CYAN + "Summary Report" + Style.RESET_ALL)
        print(f"Headers Present: {present_count}/{total_headers}")
        print(f"Security Score: {percentage:.2f}%")
        print(f"Security Grade: {grade}")
        print(Fore.YELLOW + "=" * 60 + "\n")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error scanning {url}: {e}" + Style.RESET_ALL)

def main():
    banner()
    parser = argparse.ArgumentParser(description="HeaderGuard v2 - Website Security Header Scanner")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--save", action="store_true", help="Save report to TXT file")
    args = parser.parse_args()

    while True:
        url = args.url or input("Enter a website URL: ").strip()
        if not url:
            print(Fore.RED + "No URL provided. Try again..." + Style.RESET_ALL)
            continue

        scan_headers(url, args.save)

        # Ask user if they want to scan again
        choice = input(Fore.YELLOW + "\nDo you want to scan another URL? (y/n): " + Style.RESET_ALL).strip().lower()
        if choice != "y":
            print(Fore.CYAN + "\n[+] Exiting HeaderGuard. Goodbye!\n" + Style.RESET_ALL)
            break
        args.url = None  # reset so next loop asks again


if __name__ == "__main__":
    main()
