#!/usr/bin/env python3
import requests
import argparse
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
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
    print(Fore.CYAN + Style.BRIGHT + "          HEADER GUARD v1.0  ")
    print(Fore.CYAN + "="*50)
    print(Fore.GREEN + " A lightweight Website Security Header Scanner")
    print(Fore.YELLOW + " For ethical hacking, testing & learning only\n")
    print(Fore.CYAN + "-"*50)

# SSL/TLS Check
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

        report_data = {"url": url, "headers": {}, "cookies": {}, "ssl": {}}
        present_count = 0
        missing_headers = []

        # Header check
        for header, info in SECURITY_HEADERS.items():
            display_name = header.replace("-", " ")
            if header in headers:
                present_count += 1
                print(Fore.GREEN + f"PRESENT - {display_name}" + Style.RESET_ALL)
                print(f"    Description: {info['description']}")
                print(f"    Value: {headers[header]}\n")
                report_data["headers"][header] = {"status": "present", "value": headers[header], "description": info["description"]}
            else:
                missing_headers.append(header)
                print(Fore.RED + f"MISSING - {display_name}" + Style.RESET_ALL)
                print(f"    Description: {info['description']}\n")
                report_data["headers"][header] = {"status": "missing", "description": info["description"], "recommendation": info["recommendation"]}

        # Cookie inspection
        if cookies:
            print(Fore.CYAN + "Cookies:\n" + Style.RESET_ALL)
            for cookie in cookies:
                print(f"{cookie.name}: HttpOnly={cookie._rest.get('HttpOnly', False)}, Secure={cookie.secure}, SameSite={cookie._rest.get('SameSite', 'None')}")
                report_data["cookies"][cookie.name] = {"HttpOnly": cookie._rest.get("HttpOnly", False), "Secure": cookie.secure, "SameSite": cookie._rest.get("SameSite", "None")}
            print("\n")

        # SSL/TLS check
        ssl_status, ssl_info = check_ssl(url)
        if ssl_status:
            print(Fore.GREEN + f"[+] SSL/TLS is valid for {url}\n")
            report_data["ssl"] = {"status": "valid", "info": ssl_info}
        else:
            print(Fore.RED + f"[-] SSL/TLS issue: {ssl_info}\n")
            report_data["ssl"] = {"status": "invalid", "info": ssl_info}

        # Security score
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

        # Recommendations
        if missing_headers:
            print(Fore.MAGENTA + "Recommendations for Missing Headers:\n" + Style.RESET_ALL)
            for header in missing_headers:
                display_name = header.replace("-", " ")
                print(f"{display_name}: {SECURITY_HEADERS[header]['recommendation']}")
            print("\n")

        # Save report in TXT
        if save_report:
            filename = url.replace("https://", "").replace("http://", "").replace("/", "_") + "_report.txt"
            with open(filename, "w") as f:
                f.write(f"Security Headers Analysis for: {url}\n")
                f.write("="*60 + "\n\n")
                
                f.write("Headers:\n")
                for header, info in report_data["headers"].items():
                    status = info.get("status", "unknown").upper()
                    value = info.get("value", "N/A")
                    f.write(f"{header}: {status}\n")
                    f.write(f"    Description: {info.get('description','')}\n")
                    if status == "PRESENT":
                        f.write(f"    Value: {value}\n")
                    else:
                        f.write(f"    Recommendation: {info.get('recommendation','')}\n")
                f.write("\nCookies:\n")
                for name, cinfo in report_data["cookies"].items():
                    f.write(f"{name}: HttpOnly={cinfo['HttpOnly']}, Secure={cinfo['Secure']}, SameSite={cinfo['SameSite']}\n")
                f.write("\nSSL/TLS:\n")
                ssl_status = report_data["ssl"].get("status","N/A")
                f.write(f"Status: {ssl_status}\n")
                if ssl_status == "valid":
                    ssl_info = report_data["ssl"].get("info",{})
                    f.write(f"Issuer: {ssl_info.get('issuer','N/A')}\n")
                    f.write(f"Expiration: {ssl_info.get('notAfter','N/A')}\n")
                else:
                    f.write(f"Issue: {report_data['ssl'].get('info','')}\n")
                f.write("\nSummary:\n")
                f.write(f"Headers Present: {present_count}/{total_headers}\n")
                f.write(f"Security Score: {percentage:.2f}%\n")
                f.write("\nRecommendations for Missing Headers:\n")
                for header, info in report_data["headers"].items():
                    if info["status"] == "missing":
                        f.write(f"{header}: {info['recommendation']}\n")
            print(Fore.GREEN + f"[+] Report saved as {filename}\n")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error scanning {url}: {e}" + Style.RESET_ALL)

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="HeaderGuard v2 - Website Security Header Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Default target URL (e.g., https://example.com)")
    parser.add_argument("-i", "--input", help="File containing list of URLs (one per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for bulk scan")
    parser.add_argument("--save", action="store_true", help="Save report to TXT file")
    args = parser.parse_args()

    urls = []

    # Load URLs from input file if provided
    if args.input:
        try:
            with open(args.input, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"File not found: {args.input}" + Style.RESET_ALL)
            return

    # Interactive loop
    while True:
        print(Fore.CYAN + "\n--- HEADER GUARD INTERACTIVE MODE ---" + Style.RESET_ALL)

        # Ask for URL interactively, defaulting to -u if provided
        default_url = args.url if args.url else ""
        prompt = f"Enter a website URL{' (press Enter to use ' + default_url + ')' if default_url else ''}: "
        url = input(prompt).strip()
        if not url and default_url:
            url = default_url

        if not url:
            print(Fore.RED + "No URL provided. Try again..." + Style.RESET_ALL)
            continue

        urls.append(url)

        # Run scan
        if len(urls) > 1:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                for u in urls:
                    executor.submit(scan_headers, u, args.save)
        else:
            scan_headers(urls[0], args.save)

        # After scanning, ask if user wants to scan more URLs
        urls = []  # Clear URLs for next loop
        choice = input("\nDo you want to scan more URLs? (y/n): ").strip().lower()
        if choice != "y":
            print(Fore.YELLOW + "Exiting HeaderGuard. Goodbye!" + Style.RESET_ALL)
            break

if __name__ == "__main__":
    main()
