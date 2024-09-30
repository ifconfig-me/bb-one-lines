# Bash Onelines for recon

Here are some online liner bash script for recautomation. By using below scripts you can efficiently gather information during the reconnaissance phase, saving valuable time while automating the process.

> [!WARNING]
> WARNING: This script is for educational and ethical purposes only.
> Ensure you have permission to scan the target before running this script.
> Author is not responsible for any outcome. 

### Find As Much As Subdomains
```bash
mkdir -p output && amass enum -passive -norecursive -df target.txt | anew output/target-subs-001.txt && findomain -f target.txt -q | anew output/target-subs-002.txt && cat target.txt | subfinder -all -silent | anew output/target-subs-003.txt && cat target.txt | assetfinder --subs-only | anew output/target-subs-004.txt && cat output/target-subs-004.txt | cero | anew output/cero-subs.txt && cat output/cero-subs.txt | while read line; do grep -E "\.$line$" target.txt >> output/final-scope.txt; done && echo "Subdomain enumeration completed. Results are stored in the output folder."
```
### 1. **Subdomain Enumeration with Multiple Tools**
This one-liner combines subdomain enumeration from multiple tools (`amass`, `subfinder`, `assetfinder`) and outputs the unique results.

```bash
amass enum -d $1 -o amass.txt && subfinder -d $1 -silent -o subfinder.txt && assetfinder --subs-only $1 | tee assetfinder.txt && cat amass.txt subfinder.txt assetfinder.txt | sort -u > all_subdomains.txt
```

**Explanation:**
- This command runs `amass`, `subfinder`, and `assetfinder` to find subdomains and saves the results into `amass.txt`, `subfinder.txt`, and `assetfinder.txt` respectively.
- Then it merges the results, removes duplicates, and saves them in `all_subdomains.txt`.

### 2. **Find Open Ports with `nmap`**
This one-liner scans for open ports using `nmap` on the subdomains generated from the previous step.

```bash
nmap -iL all_subdomains.txt -T4 -p- -oN open_ports.txt
```

**Explanation:**
- `-iL all_subdomains.txt` tells `nmap` to read from the list of subdomains.
- `-T4` sets the timing template to make the scan faster.
- `-p-` scans all ports (1-65535).
- The results are saved in `open_ports.txt`.

### 3. **Screenshotting Web Applications**
This one-liner uses `gowitness` to take screenshots of all active web applications from the subdomains list.

```bash
gowitness file -f all_subdomains.txt --no-check-certificate
```

**Explanation:**
- `gowitness` reads the file `all_subdomains.txt` and captures screenshots of each live web application.

### 4. **Gathering HTTP Response Headers**
This one-liner uses `httpx` to fetch HTTP response headers and other details about the discovered subdomains.

```bash
httpx -l all_subdomains.txt -status-code -title -tech-detect -o http_headers.txt
```

**Explanation:**
- `httpx` checks the list of subdomains and retrieves HTTP response details, including status codes, titles, and technologies detected, saving them into `http_headers.txt`.

### 5. **Sensitive File Discovery**
This one-liner uses `gau` (GetAllURLs) and `grep` to find potentially sensitive files from a domain.

```bash
echo $1 | gau | grep -E "\.(xls|xml|json|pdf|sql|doc|docx|txt|zip|tar|gz|rar|log|db|bak|env|config|yml|ini|properties|sqlcipher|pem|crt|key)$" | tee sensitive_files.txt
```

**Explanation:**
- `gau` fetches URLs for the given domain.
- `grep` filters out sensitive file types such as `.xml`, `.json`, `.sql`, `.bak`, `.env`, etc.
- Results are saved in `sensitive_files.txt`.

### 6. **DNS Information Gathering**
This one-liner uses `dig` to gather DNS information for a domain.

```bash
dig $1 ANY +noall +answer > dns_info.txt
```

**Explanation:**
- `dig` performs DNS queries.
- `ANY` asks for all available DNS records.
- The result is saved in `dns_info.txt`.

### 7. **Checking for CORS Misconfigurations**
This one-liner uses `corscanner` to check for potential CORS misconfigurations.

```bash
cat all_subdomains.txt | xargs -I{} corscanner --url {}
```

**Explanation:**
- It pipes the subdomains into `corscanner`, checking each one for misconfigurations related to Cross-Origin Resource Sharing (CORS).

### 8. **Checking for Web Technologies**
This one-liner uses `whatweb` to identify technologies used on discovered subdomains.

```bash
cat all_subdomains.txt | xargs -I{} whatweb {} --log-json web_technologies.json
```

**Explanation:**
- `whatweb` scans each subdomain to identify the technologies in use and saves the results in JSON format.

### 9. **Gather WHOIS Information**
This one-liner retrieves WHOIS information for the domain to gather registration and ownership details.

```bash
whois $1 > whois_info.txt
```

**Explanation:**
- `whois` fetches domain registration information, and the result is saved in `whois_info.txt`.

### 10. **SSL Certificate Information**
This one-liner retrieves SSL certificate details for a domain, useful for identifying certificate expiration and misconfigurations.

```bash
echo | openssl s_client -connect $1:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer > ssl_info.txt
```

**Explanation:**
- `openssl s_client` connects to the server, and the SSL certificate is retrieved with details such as the subject, issuer, and expiration dates.
- Results are saved in `ssl_info.txt`.

### 11. **Checking for Open Redirects**
This one-liner uses `gau` and `gf` to search for URLs that might be vulnerable to open redirect attacks.

```bash
echo $1 | gau | gf redirect | tee open_redirects.txt
```

**Explanation:**
- `gau` retrieves URLs from the target, and `gf` (Go Find Patterns) looks for patterns indicative of open redirect vulnerabilities, saving them to `open_redirects.txt`.

### 12. **JavaScript File Extraction**
This one-liner fetches and downloads all JavaScript files from the URLs discovered during recon.

```bash
echo $1 | gau | grep "\.js$" | xargs -I{} wget -q {} -P js_files/
```

**Explanation:**
- `gau` retrieves all URLs, `grep` filters the ones ending with `.js`, and `wget` downloads these files into the `js_files/` directory for further inspection.

### 13. **Content Discovery with `ffuf`**
This one-liner uses `ffuf` to brute-force common directories and files on discovered subdomains.

```bash
ffuf -w /path/to/wordlist.txt -u https://$1/FUZZ -o content_discovery.txt
```

**Explanation:**
- `ffuf` is used for fuzzing the target domain (`$1`) with a wordlist of common files and directories.
- Results are saved in `content_discovery.txt`.

### 14. **CMS Detection**
This one-liner uses `whatweb` to detect which Content Management System (CMS) a website might be using.

```bash
whatweb -a 3 $1 > cms_detection.txt
```

**Explanation:**
- `whatweb -a 3` performs aggressive scanning to detect CMS details and saves the output to `cms_detection.txt`.

### 15. **Extract Endpoints from JavaScript Files**
This one-liner extracts potential API or sensitive endpoints from downloaded JavaScript files.

```bash
grep -oE "https?://[a-zA-Z0-9./?=_-]*" js_files/*.js | tee js_endpoints.txt
```

**Explanation:**
- This `grep` command searches the JavaScript files downloaded earlier for URLs (endpoints), saving the extracted URLs to `js_endpoints.txt`.

### 16. **Finding Potential Subdomain Takeovers**
This one-liner checks for potential subdomain takeovers by identifying unclaimed subdomains using `subjack`.

```bash
subjack -w all_subdomains.txt -t 100 -timeout 30 -o subdomain_takeovers.txt
```

**Explanation:**
- `subjack` checks subdomains for possible takeover vulnerabilities and writes the results to `subdomain_takeovers.txt`.

### 17. **DNS Zone Transfer Check**
This one-liner tests if DNS zone transfers are possible (a misconfiguration).

```bash
dig axfr @$1 $1 > dns_zone_transfer.txt
```

**Explanation:**
- `dig axfr` attempts a zone transfer, which should be restricted on properly configured DNS servers. If the zone transfer is successful, the DNS records are saved in `dns_zone_transfer.txt`.

### 18. **Check for HTTP Methods (e.g., PUT, DELETE)**
This one-liner checks for potentially dangerous HTTP methods on a domain.

```bash
curl -s -I -X OPTIONS https://$1 | grep "Allow" > http_methods.txt
```

**Explanation:**
- `curl` is used to send an `OPTIONS` request to check which HTTP methods are allowed on the server.
- The allowed methods are saved in `http_methods.txt`.

### 19. **Reverse DNS Lookup**
This one-liner performs a reverse DNS lookup for an IP range or domain.

```bash
for ip in $(seq 1 255); do host $1.$ip; done | grep -v "not found" > reverse_dns.txt
```

**Explanation:**
- This loop performs reverse DNS lookups on a range of IP addresses, saving valid results (excluding "not found") to `reverse_dns.txt`.

### 20. **Extract Comments from HTML**
This one-liner pulls out HTML comments from the page source of a given domain, which can sometimes contain sensitive information.

```bash
curl -s https://$1 | grep "<!--" | tee html_comments.txt
```

**Explanation:**
- `curl` fetches the HTML source of the target domain, and `grep` looks for HTML comments (`<!-- ... -->`), saving them in `html_comments.txt`.

### 21. **Extract Links from JavaScript Files**
This one-liner extracts all URLs from JavaScript files of a domain by fetching all JS files and searching for URLs within them.

```bash
echo $1 | gau | grep "\.js$" | xargs -I{} curl -s {} | grep -oE "https?://[a-zA-Z0-9./?=_-]*" | tee js_links.txt
```

**Explanation:**
- `gau` retrieves URLs for JavaScript files.
- `curl` fetches the contents of each JavaScript file.
- `grep` extracts all links (URLs) found within the files.
- The results are saved in `js_links.txt`.

---

### 22. **Subdomain Enumeration with DNS Bruteforce**
This one-liner uses `ffuf` to perform subdomain brute-forcing and `subfinder` to combine brute-force with passive enumeration.

```bash
ffuf -w /path/to/wordlist.txt -u https://FUZZ.$1 -H "Host: FUZZ.$1" -o ffuf_subdomains.txt && subfinder -d $1 -silent | tee combined_subdomains.txt
```

**Explanation:**
- `ffuf` performs subdomain brute-forcing using a wordlist.
- `subfinder` passively enumerates subdomains.
- Both outputs are combined in `combined_subdomains.txt`.

---

### 23. **GitHub Dorking for Sensitive Information**
This one-liner uses `github-endpoints.py` to fetch sensitive information such as API keys and tokens from GitHub repositories related to the domain.

```bash
python3 github-endpoints.py -d $1 -t <GITHUB_TOKEN> | tee github_sensitive.txt
```

**Explanation:**
- `github-endpoints.py` searches GitHub for sensitive information like API keys, tokens, and credentials.
- The results are stored in `github_sensitive.txt`.

---

### 24. **Find Endpoints via Wayback Machine with Specific Patterns**
This one-liner fetches URLs from the Wayback Machine that match specific patterns, such as `.php` files.

```bash
echo $1 | gau | grep -E "\.php|\.asp|\.aspx" | tee wayback_endpoints.txt
```

**Explanation:**
- `gau` pulls URLs from various archives, including the Wayback Machine.
- `grep` filters URLs for `.php`, `.asp`, or `.aspx` endpoints.
- The results are saved in `wayback_endpoints.txt`.

---

### 25. **Check for JavaScript Leaks in External JS Files**
This one-liner looks for hardcoded secrets like API keys in external JavaScript files.

```bash
echo $1 | gau | grep "\.js$" | xargs -I{} curl -s {} | grep -E "(api|key|secret|password|token)" | tee js_secrets.txt
```

**Explanation:**
- The script fetches all JavaScript files from the target and searches for potential hardcoded secrets such as API keys or tokens.
- Results are saved in `js_secrets.txt`.

---

### 26. **Check for SQL Injection in Parameters**
This one-liner uses `sqlmap` to automate the testing of SQL injection on URLs that contain parameters.

```bash
cat urls_with_params.txt | xargs -I{} sqlmap -u {} --batch --level=5 --risk=3 --random-agent --output-dir=sqlmap_results
```

**Explanation:**
- `sqlmap` is used to test SQL injection on URLs with parameters.
- `--level=5` and `--risk=3` ensure thorough testing.
- `--random-agent` randomizes the user agent for each request.
- The results are saved in the `sqlmap_results` directory.

---

### 27. **Automated Google Dorking**
This one-liner searches Google for publicly exposed sensitive information about a domain, such as passwords and configuration files.

```bash
dork="site:$1 ext:sql OR ext:db OR ext:bak OR ext:log OR ext:env OR ext:config" && curl -s "https://www.google.com/search?q=$dork" | tee google_dorks.txt
```

**Explanation:**
- This performs Google dorking to find database files, backups, logs, environment files, and configurations that might be exposed.
- The search results are saved in `google_dorks.txt`.

---

### 28. **Brute-Force Virtual Hosts**
This one-liner brute-forces virtual hosts using `ffuf` and a wordlist.

```bash
ffuf -w /path/to/vhosts.txt -u https://$1 -H "Host: FUZZ.$1" -o vhost_bruteforce.txt
```

**Explanation:**
- `ffuf` brute-forces subdomains (virtual hosts) by sending requests with different `Host` headers.
- The results are saved in `vhost_bruteforce.txt`.

---

### 29. **Check for CORS Misconfigurations**
This one-liner uses `curl` to check if a domain is vulnerable to CORS misconfigurations.

```bash
curl -s -I -X OPTIONS https://$1 -H "Origin: evil.com" -H "Access-Control-Request-Method: GET" | grep "Access-Control-Allow-Origin"
```

**Explanation:**
- `curl` sends an `OPTIONS` request with a malicious `Origin` header (`evil.com`) to check if the server allows cross-origin requests from untrusted domains.
- The response is checked for `Access-Control-Allow-Origin`.

---

### 30. **Extract Email Addresses from a Domain**
This one-liner fetches URLs related to a domain and extracts email addresses.

```bash
echo $1 | gau | xargs -I{} curl -s {} | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}" | tee emails.txt
```

**Explanation:**
- This script uses `gau` to gather URLs and then fetches the contents of each URL, searching for email addresses.
- Results are saved in `emails.txt`.

---

### 31. **XSS Payload Injection into Parameters**
This one-liner uses `ffuf` to inject XSS payloads into all parameters of a target URL.

```bash
ffuf -u https://$1/FUZZ -w /path/to/xss_payloads.txt -H "Host: $1" -o xss_injection.txt
```

**Explanation:**
- `ffuf` injects a list of XSS payloads into a parameterized URL.
- Results are saved in `xss_injection.txt`.

---

### 32. **Fuzzing for Parameter Pollution**
This one-liner fuzzes URLs to test for parameter pollution vulnerabilities.

```bash
ffuf -u https://$1?FUZZ=value -w /path/to/parameters.txt -o param_pollution.txt
```

**Explanation:**
- `ffuf` tests different parameters on a URL to check for parameter pollution, where duplicate parameters may bypass validation.
- Results are saved in `param_pollution.txt`.

### `recon.sh` Script:

```bash
#!/bin/bash

# Warning message for ethical use
echo "---------------------------------------------"
echo "WARNING: This script is for educational and ethical purposes only."
echo "Ensure you have permission to scan the target before running this script."
echo "Unauthorized use is illegal and may result in legal consequences."
echo "---------------------------------------------"

# Check if the domain is provided
if [ -z "$1" ]; then
    echo "Usage: ./recon.sh <domain>"
    exit 1
fi

DOMAIN=$1
echo "Starting reconnaissance for: $DOMAIN"

# 1. Subdomain Enumeration
echo "Running Subdomain Enumeration..."
amass enum -d $DOMAIN -o amass.txt && \
subfinder -d $DOMAIN -silent -o subfinder.txt && \
assetfinder --subs-only $DOMAIN > assetfinder.txt
cat amass.txt subfinder.txt assetfinder.txt | sort -u > all_subdomains.txt
echo "Subdomains saved to all_subdomains.txt"

# 2. Open Ports Scan
echo "Scanning for open ports..."
nmap -iL all_subdomains.txt -T4 -p- -oN open_ports.txt
echo "Open ports saved to open_ports.txt"

# 3. Screenshot Web Applications
echo "Capturing screenshots of web applications..."
gowitness file -f all_subdomains.txt --no-check-certificate
echo "Screenshots captured and saved."

# 4. HTTP Response Headers
echo "Gathering HTTP response headers..."
httpx -l all_subdomains.txt -status-code -title -tech-detect -o http_headers.txt
echo "HTTP headers saved to http_headers.txt"

# 5. Sensitive File Discovery
echo "Finding potentially sensitive files..."
echo $DOMAIN | gau | grep -E "\.(xls|xml|json|pdf|sql|doc|docx|txt|zip|tar|gz|rar|log|db|bak|env|config|yml|ini|properties|sqlcipher|pem|crt|key)$" | tee sensitive_files.txt
echo "Sensitive files saved to sensitive_files.txt"

# 6. DNS Information Gathering
echo "Gathering DNS information..."
dig $DOMAIN ANY +noall +answer > dns_info.txt
echo "DNS information saved to dns_info.txt"

# 7. SSL Certificate Information
echo "Fetching SSL certificate information..."
echo | openssl s_client -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer > ssl_info.txt
echo "SSL information saved to ssl_info.txt"

# 8. Open Redirect Vulnerabilities
echo "Checking for open redirects..."
echo $DOMAIN | gau | gf redirect | tee open_redirects.txt
echo "Open redirect vulnerabilities saved to open_redirects.txt"

# 9. Download JavaScript Files
echo "Downloading JavaScript files..."
mkdir -p js_files
echo $DOMAIN | gau | grep "\.js$" | xargs -I{} wget -q {} -P js_files/
echo "JavaScript files saved in js_files/ directory"

# 10. Content Discovery
echo "Running content discovery..."
ffuf -w /path/to/wordlist.txt -u https://$DOMAIN/FUZZ -o content_discovery.txt
echo "Content discovery saved to content_discovery.txt"

# 11. CMS Detection
echo "Detecting CMS technologies..."
whatweb -a 3 $DOMAIN > cms_detection.txt
echo "CMS detection results saved to cms_detection.txt"

# 12. Extract Endpoints from JavaScript Files
echo "Extracting endpoints from JavaScript files..."
grep -oE "https?://[a-zA-Z0-9./?=_-]*" js_files/*.js | tee js_endpoints.txt
echo "JavaScript endpoints saved to js_endpoints.txt"

# 13. Checking for Subdomain Takeovers
echo "Checking for subdomain takeovers..."
subjack -w all_subdomains.txt -t 100 -timeout 30 -o subdomain_takeovers.txt
echo "Subdomain takeover results saved to subdomain_takeovers.txt"

# 14. DNS Zone Transfer Check
echo "Checking for DNS zone transfers..."
dig axfr @$DOMAIN $DOMAIN > dns_zone_transfer.txt
echo "DNS zone transfer results saved to dns_zone_transfer.txt"

# 15. Check for HTTP Methods
echo "Checking for HTTP methods..."
curl -s -I -X OPTIONS https://$DOMAIN | grep "Allow" > http_methods.txt
echo "Allowed HTTP methods saved to http_methods.txt"

# 16. Reverse DNS Lookup
echo "Performing reverse DNS lookup..."
for ip in $(seq 1 255); do host $DOMAIN.$ip; done | grep -v "not found" > reverse_dns.txt
echo "Reverse DNS lookup results saved to reverse_dns.txt"

# 17. Extract HTML Comments
echo "Extracting HTML comments..."
curl -s https://$DOMAIN | grep "<!--" | tee html_comments.txt
echo "HTML comments saved to html_comments.txt"

echo "Reconnaissance completed for $DOMAIN"
```

### How to Use:

1. **Make the script executable**:
   - Run this command to give execute permissions to the script:
     ```bash
     chmod +x recon.sh
     ```

2. **Run the script**:
   - Execute the script by passing a domain as an argument:
     ```bash
     ./recon.sh <domain>
     ```

   Example:
   ```bash
   ./recon.sh example.com
   ```
