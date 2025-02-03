#!/usr/bin/env python3
import shodan
import sys
import json

# ======= CONFIGURATION =======
API_KEY = "your_shodan_api_key"  # Replace with your Shodan API key
shodan_api = shodan.Shodan(API_KEY)

def banner():
    print("""
 ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
 ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║
 ███████╗███████║██║   ██║██████╔╝███████║██╔██╗ ██║
 ╚════██║██╔══██║██║   ██║██╔═══╝ ██╔══██║██║╚██╗██║
 ███████║██║  ██║╚██████╔╝██║     ██║  ██║██║ ╚████║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝
    Shodan Hacking Toolkit - For Authorized Use Only
    """)

# ======= SUBDOMAIN ENUMERATION =======
def enumerate_subdomains(domain):
    print(f"[+] Searching Shodan for subdomains of: {domain}")
    try:
        results = shodan_api.search(f"hostname:{domain}")
        for result in results['matches']:
            print(f"  - {result['ip_str']} ({result['hostnames']})")
    except shodan.APIError as e:
        print(f"Error: {e}")

# ======= PORT SCANNING =======
def port_scan(ip):
    print(f"[+] Scanning open ports for: {ip}")
    try:
        host = shodan_api.host(ip)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        for item in host['data']:
            print(f"  Port: {item['port']} | Service: {item['product']} | Banner: {item.get('banner', 'N/A')}")
    except shodan.APIError as e:
        print(f"Error: {e}")

# ======= VULNERABILITY DETECTION =======
def detect_vulnerabilities(ip):
    print(f"[+] Detecting vulnerabilities for: {ip}")
    try:
        host = shodan_api.host(ip)
        for item in host['data']:
            vulns = item.get('vulns', [])
            if vulns:
                for vuln in vulns:
                    print(f"  - {vuln} ({shodan.helpers.exploitdb(vuln)})")
    except shodan.APIError as e:
        print(f"Error: {e}")

def search_rdp():
    print("[+] Searching for exposed RDP...")
    results = shodan_api.search('port:3389')
    for result in results['matches']:
        print(f"IP: {result['ip_str']} | Organization: {result.get('org', 'N/A')}")
        print(f"Hostnames: {result.get('hostnames', 'N/A')}")
        print(f"Data: {result['data']}")
        print("-" * 50)

def search_databases():
    print("[+] Searching for open databases...")
    results = shodan_api.search('port:27017')
    for result in results['matches']:
        print(f"IP: {result['ip_str']} | MongoDB Banner: {result['data']}")

def search_vulnerabilities():
    print("[+] Searching for vulnerable systems...")
    results = shodan_api.search('vuln:"CVE-2020-3452"')
    for result in results['matches']:
        print(f"IP: {result['ip_str']} | CVE: CVE-2020-3452")
        print(f"Data: {result['data']}")

# ======= SENSITIVE INFORMATION SEARCH =======
def sensitive_info_search(query):
    print(f"[+] Searching Shodan for sensitive information with query: {query}")
    try:
        results = shodan_api.search(query)
        for result in results['matches']:
            print(f"IP: {result['ip_str']} | Hostnames: {result.get('hostnames')}")
            print(f"Data: {result['data']}")
            print("-" * 50)
    except shodan.APIError as e:
        print(f"Error: {e}")

# ======= SSL/TLS CONFIGURATION =======
def analyze_ssl(ip):
    print(f"[+] Analyzing SSL/TLS configuration for: {ip}")
    try:
        host = shodan_api.host(ip)
        for item in host['data']:
            if 'ssl' in item:
                print(f"  Issuer: {item['ssl']['issuer']}")
                print(f"  Expiry: {item['ssl']['expires']}")
                print(f"  Versions: {item['ssl']['versions']}")
    except shodan.APIError as e:
        print(f"Error: {e}")

# ======= MAIN FUNCTION =======
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [mode] [target/query]")
        print("Modes:")
        print("  subdomains [domain]       - Enumerate subdomains")
        print("  ports [ip]                - Scan open ports")
        print("  vulns [ip]                - Detect vulnerabilities")
        print("  sensitive [query]         - Search for sensitive info")
        print("  ssl [ip]                  - Analyze SSL/TLS configuration")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]

    if mode == "subdomains":
        enumerate_subdomains(target)
    elif mode == "ports":
        port_scan(target)
    elif mode == "vulns":
        detect_vulnerabilities(target)
    elif mode == "sensitive":
        sensitive_info_search(target)
    elif mode == "ssl":
        analyze_ssl(target)
    else:
        print("Invalid mode. Use -h for help.")

if __name__ == "__main__":
    banner()
    main()
