''' Log IP Extractor

This Python script extracts IP addresses from raw logs, removes duplicates, and counts frequency to assist in identifying suspicious activity such as brute-force attempts.

## Features
- Extracts IPv4 addresses
- Counts frequency of occurrences
- Helps identify suspicious IPs based on repeated activity

## Use Case : Used during investigation of brute-force attacks to quickly identify attacker IPs.'''

import re
from collections import defaultdict

with open("./auth.log", "r") as file:
    log_file = file.read()
    
ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

ips=re.findall(ip_regex,log_file)

uniq_ip = defaultdict(int)
for i in ips:
    if i not in uniq_ip:
        uniq_ip[i]
    uniq_ip[i]+=1
for key,value in uniq_ip.items():
    if uniq_ip[key]>5:
        print(f"IP Address : {key:<15} Number of Attempts made: {uniq_ip[key]}")

        print("Possible Brute force attack attempt")
