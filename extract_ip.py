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