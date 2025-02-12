<h1 align="center">🚀 FaultLine: Red-Team Hacking Suite 🔥</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue.svg" alt="Version 1.0">
  <img src="https://img.shields.io/badge/Made%20with-Bash-success.svg" alt="Made with Bash">
  <img src="https://img.shields.io/badge/License-Choose%20a%20license-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
  <br>
  <img src="https://img.shields.io/github/stars/your-username/FaultLine?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/your-username/FaultLine?style=social" alt="Forks">
</p>

<div align="center">
  
  <pre>
     ++----------------------------------------------------------------------------------++
    ++----------------------------------------------------------------------------------++
    ||                                                                                  ||
    ||                                                                                  ||
    ||   8888888888                888 888        888      d8b                   888    ||
    ||   888                       888 888        888      Y8P                   888    ||
    ||   888                       888 888        888                            888    ||
    ||   8888888  8888b.  888  888 888 888888     888      888 88888b.   .d88b.  888    ||
    ||   888         "88b 888  888 888 888        888      888 888 "88b d8P  Y8b 888    ||
    ||   888     .d888888 888  888 888 888        888      888 888  888 88888888 Y8P    ||
    ||   888     888  888 Y88b 888 888 Y88b.      888      888 888  888 Y8b.      "     ||
    ||   888     "Y888888  "Y88888 888  "Y888     88888888 888 888  888  "Y8888  888    ||
    ||                                                                                  ||
    ||                                                                                  ||
    ++----------------------------------------------------------------------------------++
    ++----------------------------------------------------------------------------------++
   ------------------------------------------------------------
            Developer: Austin Tatham       Version: 1.0.0
        ------------------------------------------------------------
  </pre>
  
  <strong>A comprehensive & advanced framework for recon, vulnerability discovery, and exploitation.</strong>

</div>

---
> [!IMPORTANT]
> There are two versions, both in Bash. The reason there are two is because im undecided which i want to continue with.

## ✨ Table of Contents

1. [🔑 Key Features](#-key-features)
2. [⚙️ Installation & Requirements](#️-installation--requirements)
3. [🚀 Usage](#-usage)
4. [🗂 Available Modes](#-available-modes)
   - [🔍 Recon Mode](#recon-mode)
   - [💣 Exploit Mode](#exploit-mode)
   - [🌐 All Mode](#all-mode)
5. [🔧 Modules & Capabilities](#-modules--capabilities)
6. [🎯 Example Workflows](#-example-workflows)
7. [⚠️ Disclaimer](#️-disclaimer)
8. [🤝 Contributing](#-contributing)
9. [📜 License](#-license)

---

## 🔑 Key Features

- **🕵️ Integrated Reconnaissance** – Automates subdomain enumeration, port scanning, directory fuzzing, and more.
- **🔒 Vulnerability Detection** – Tests for SQL injection, XSS, SSRF, IDOR, broken access control, and CVEs.
- **💥 Exploitation** – Attempts direct exploitation (command injection, brute-forcing, and known CVEs).
- **📁 Flexible Output** – Save scans to a specified directory for easy reporting (`-s` flag).
- **🐚 Bash-Driven** – Minimal overhead, combining tools like `subfinder`, `nmap`, `ffuf`, `sqlmap`, `hydra`, etc.
- **🕳️ Deep Vulnerability Crawling** – Integrates `nmapAutomator.sh` for deeper layered vulnerability detection.

---

## ⚙️ Installation & Requirements

1. **Clone this repository**:
   ```bash
   git clone https://github.com/your-user/FaultLine.git
   cd FaultLine

2. **Install the necessary tools** (**examples:** `apt install`, `brew install`, etc.):

  -subfinder, dmitry, finalrecon, nmap, sqlmap, ffuf, hydra, nmapAutomator.sh  
  -`Python 3` (for cve_exploit.py or similar scripts)

3. **Make the script executable (if needed):**

  ```bash
  chmod +x FaultLine.sh
  ```
4. (Optional) **Create a dedicated directory for saving output:**

  ```bash
  mkdir results
  ```
-------
 # 🚀 Usage
Run the script:
```bash
./FaultLine.sh -t <target> -m <mode> [options]
```
## **Basic Options:**  

| Flag | Long Option   | Description                                              | Required |
|------|--------------|---------------------------------------------------------|----------|
| `-t` | `--target`   | **Target** domain or file containing domains            | Yes      |
| `-m` | `--mode`     | **Mode**: `recon`, `exploit`, or `all`                  | Yes      |
| `-s` | `--save`     | Save mode: writes results to specified **directory**    | No       |
| `-h` | `--help`     | Show the **help** menu                                  | No       |

**Example**:  
```bash
./FaultLine.sh -t example.com -m recon -s ./results
```

<strong>Runs Recon on `example.com`, saving all data to `./results`.</strong>

---

# 📂 **Available Modes**  

## 🔍 Recon Mode
- Subdomain discovery, port scanning, directory fuzzing, JS endpoint extraction, and standard vulnerability checks **(SQLi, XSS, SSRF, IDOR)**.
## 💣 Exploit Mode
- Targets potential exploits discovered during recon.
- Attempts command injection, SQL injection, known CVE exploits, etc.
## 🌐 All Mode
- Runs both Recon **and** Exploit sequences end-to-end:
- Subdomain enumeration, scanning, vulnerability checks, and exploitation attempts all in one command.

---

# **🔧 Modules & Capabilities**
- **Subdomain Enumeration** – via [subfinder, dmitry].
- **Port & Service Discovery** – via [nmap].
- **Directory Fuzzing** – via [ffuf].
- **HTML/Comment Crawling & JS Parsing** – to reveal hidden links, endpoints, or credentials.
---
### **Vulnerability Testing:**
- **SQL Injection** – [sqlmap] + manual tests.
- **XSS** – scanning for **<script>** tags, reflection points.
- **SSRF** – parameter-based checks to internal endpoints.
- **IDOR / Broken Access Control** – checks for direct object references or missing ACLs.
- **Deep Vuln Scan** – using `nmapAutomator.sh -t Vulns.`
### **Exploitation:**
- **Command Injection** – tests with injected whoami, etc.
- **SSH Brute Force** – via [hydra].
- **Known CVE Exploits** – run `cve_exploit.py` or similar scripts.
- **Privilege Escalation Checks** – scanning for **admin endpoints**, **403 bypass**, etc.
### **Output Management:**
- `-s <dir>` – saves all logs and data to a chosen directory.
- **DEBUG=1 – set in script for verbose, debug-level logging.

---
### ⚠️ Disclaimer
  This project is for research, and educational purposes only.  
  Always ensure you have explicit permission before testing or attacking any systems.
  No liability is assumed by the author for misuse or damage caused by this software.  
    This _tool_ is only meant to demonstrate what a would be hacker would maybe use.  
    Use according to the law.
---
 I'm mainly focused on automating **_manual_ enumeration and exploitation**.  
 Currently this tool automates a bunch of tasks, but my goal is to make FaultLine think and behave/respond more like a human hacker rather than just running tools and spitting out results.  
 
 In other words, my focus is on expanding the manual side of the code.
So that when using this _tool_, you get more than just another mediocore scan with cluttered results that never lead to any type of result. 

Instead of just listing outputs, it should actually analyze what it finds and adapt—like if it discovers a certain tech stack.   
  It should immediately check for vulnerabilities related to it. If it finds an exposed API key, 
  it shouldn’t just save it to a file; it should actually try using it against the API and see what it can access.  
  
---------------------
# **I want FaultLine to act like a real pentester would:**  

   **1. Thoroughly map the attack surface, treating every little detail as a potential lead.**
  
   **2. Use recon data for smart exploitation, like chaining an exposed admin panel with a weak password into full access.**
  
   **3. Combine manual methods and automation to go deep and find things most automated tools would miss.**

---
## As of right now it's a multi-tool automater with some unique aspects that go along with them.  
-------  

## **Some** of the _"unique"_ aspects that I intend to implement,(some already have been).  

 ### **Manual API Testing**
  - Parse JavaScript files for API endpoints & secrets  
  - Send crafted API requests to test for IDOR, rate-limit bypass, etc.  

 ### **Fuzzing Based on Findings**  
  - Adjust wordlists based on discovered tech  
  - Focus on paths likely to contain juicy info (e.g., `/admin`, `/wp-json/`)  

 ### **Using Recon Data to Guide Attacks**
  - Extract leaked credentials, API keys, or tokens  
  - Test against discovered endpoints in real-time  
---
## **Exploitation Phase**

**Using What’s Found to Gain More Access**
  - Test SQL injection manually with crafted payloads  
  - Try XSS payloads across multiple contexts (reflected, stored, DOM)  
**Chaining Vulnerabilities**
  - **Example**: CORS misconfiguration + API Key Leakage → Full Account Takeover  
**Privilege Escalation**  
  - Switch cookies, headers, and user roles to escalate access  
  - Look for IDOR vulnerabilities in APIs
---
## Examples ##

### **Testing Authentication Bypass Without Tools**
  ``` bash
  curl -X POST "https://target.com/login" -d "username=admin'--&password="
  ```
  Instead of simply running `Hydra`, the script should recognize authentication weaknesses (e.g., SQL injection in login forms) and attempt them dynamically.

### **Manually Exploiting Open Directories**
``` bash
curl -s https://target.com/.git/config
```
  If directory listing is enabled, the tool should recognize this and automatically attempt to retrieve sensitive files (e.g., .git, .env, backup.sql).

### **Adaptive URL Fuzzing**

```bash
  for endpoint in "admin" "backup" "hidden" "old"; do
      curl -s -o /dev/null -w "%{http_code}" "https://target.com/$endpoint"
  done
```
Rather than blindly fuzzing, the tool should prioritize directories based on prior reconnaissance (e.g., tech stack hints, known CMS structures).

### **Checking for Misconfigured APIs**

``` bash
curl -s -H "Authorization: Bearer invalidtoken" "https://api.target.com/v1/users"
```
If an API responds with **"Invalid Token"** instead of **"Unauthorized"**, the script should recognize it as a potential IDOR or broken access control vulnerability.

The end goal is to make it not just another automated tool but one that actually learns, makes smart decisions, and finds bugs others won’t.
---
### 🤝 Contributing  
Fork this repo.  
- **Create a new branch:** git checkout -b feature/awesome-improvement.  
- **Commit your changes:** git commit -m 'Add a cool feature'.  
- **Push to your branch:** git push origin feature/awesome-improvement.  
- **Submit a Pull Request.**
---
  - **I'm far from a _seasoned_ hacker or an _experienced_ programmer.**
  - **Any contribution of any form, even if only words are appreciated.**  
---
# **🎯 Example Workflows**  

## - **Full Recon & Exploit:**

  ```bash
  ./FaultLine.sh -t target-example.com -m all -s output_results
  ```
  - **Performs subdomain enumeration, scanning, vuln detection, exploitation attempts – saves it all.
---  
  ## - **Recon Only:**
  
  ```bash
  ./FaultLine.sh -t target-example.com -m recon
  ```
  - **Gathers host intelligence, subdomains, open ports, and basic vulnerability insights.
---
  ## - **Focused Exploitation:**
  
  ```bash
  ./FaultLine.sh -t target-example.com -m exploit -s exploited_results
  ```
  - **Skips the broad recon steps and directly tries exploit modules, logging to exploited_results.
---
📜 License

mathematica
Copy
Edit
[Your License Text Here]
Happy hacking and stay authorized! Use responsibly to secure and strengthen systems, not harm them.

1. **Clone this repository**:
   ```bash
   git clone https://github.com/your-username/FaultLine.git
   cd FaultLine
