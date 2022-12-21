# lazypinx
# DISCLAIMER: This script is intended for educational and testing purposes only. The author of this script is not responsible for any misuse or damage caused by this script.
A lazy Script to Automate network mapping and provide simple Vulnerability scanning

If you already using Kali Linux you won't need to install requirments.

Requirements are:
|----------------------------|
|`sudo apt-get install nuclei`|
|`sudo apt-get install nikto`|
|`pip install python-nmap`|
|`pip install argparse`|






Here are the command line arguments that the script accepts:

(REQUIRED) ip_address_or_subnet: The IP address or subnet to scan. This is a required argument.
* -o or --os: Perform an OS identification scan.
* -p or --ping: Perform a ping sweep.
* -s or --stealth: Perform a stealth nmap scan.
* -a or --arguments: Specify additional arguments to pass to nmap, enclosed in double quotes.
* -t or --timing: Set the timing template for the scan. Accepted values are slow, normal, and fast.
* -e or --evasion: Specify an IDS evasion technique. Accepted values are randomize_hosts, randomize_ports, frag, decoy, spoof, bad_ttl, tcp_timestamp, and ip_id.
* -w or --waf: Detect a web application firewall (WAF).
* -vv or --vuln: Search nmap NSE scripts for vulnerabilities.
* -m or --mysql: Check for empty MySQL passwords.
* -v or --nuclei: Use Nuclei for vulnerability scanning.
* -n or --nikto: Use Nikto for vulnerability scanning.
* -dos or --scriptdos: Use the http-slowloris script for a Denial of Service (DoS) attack.

Use Cases:
1. To perform a simple port scan of the IP address 192.168.1.1, you would run the following command:`python lazypinx.py 192.168.1.1`
2. To perform a ping sweep of the subnet 192.168.1.0/24, you would run the following command:`python lazypinx.py 192.168.1.0/24 -p`
3. To perform a vulnerability scan of the IP address 192.168.1.1 using Nuclei, you would run the following command:`python lazypinx.py 192.168.1.1 -v`
4. To perform a vulnerability scan of the IP address 192.168.1.1 using Nikto, you would run the following command:`python lazypinx.py 192.168.1.1 -n`
5. To perform a port scan of the IP address 192.168.1.1 with additional nmap arguments of -p 80,443 (to scan only ports 80 and 443), you would run the following command`python lazypinx.py 192.168.1.1 -a "-p 80,443"`
6. To perform a port scan with an IDS evasion technique and a (OPTIONAL) slower timing template:`python lazypinx.py 192.168.1.1 -e randomize_ports -t slow`
7. You can also use multiple IDS evasion techniques at the same time by specifying them as a comma-separated list:`python lazypinx.py 192.168.1.1 -e randomize_ports,decoy -t slow`
8. To perform a stealth scan with a slower timing template: `python lazypinx.py 192.168.1.1 -s -t slow`
