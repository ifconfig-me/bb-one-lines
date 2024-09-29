# Bash Onelines

Here are some online liner bash script for automation.

### Find As Much As Subdomains
```bash
mkdir -p output && amass enum -passive -norecursive -df target.txt | anew output/target-subs-001.txt && findomain -f target.txt -q | anew output/target-subs-002.txt && cat target.txt | subfinder -all -silent | anew output/target-subs-003.txt && cat target.txt | assetfinder --subs-only | anew output/target-subs-004.txt && cat output/target-subs-004.txt | cero | anew output/cero-subs.txt && cat output/cero-subs.txt | while read line; do grep -E "\.$line$" target.txt >> output/final-scope.txt; done && echo "Subdomain enumeration completed. Results are stored in the output folder."
```
