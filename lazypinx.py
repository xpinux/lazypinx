import nmap
import argparse
import subprocess

# Parse command line arguments
parser = argparse.ArgumentParser(description='Perform a simple or advanced nmap scan or run a Vulnerability Scan')
parser.add_argument('ip_address_or_subnet', help='IP address or subnet to scan')
parser.add_argument('-o', '--os', action='store_true', help='OS Identification')
parser.add_argument('-p', '--ping', action='store_true', help='Perform a ping sweep')
parser.add_argument('-s', '--stealth', action='store_true', help='Stealth Nmap scan')
parser.add_argument('-a', '--arguments', help='Additional nmap arguments | always with a space first and then argument inside DOUBLE QUOTES')
parser.add_argument('-t', '--timing', choices=['slow', 'normal', 'fast'], help='Timing template for the scan')
parser.add_argument('-e', '--evasion', choices=['randomize_hosts', 'randomize_ports', 'frag', 'decoy', 'spoof', 'bad_ttl', 'tcp_timestamp', 'ip_id'], help='IDS evasion technique')
parser.add_argument('-w', '--waf', action='store_true', help='Detect WAF')
parser.add_argument('-vv', '--vuln', action='store_true', help='Search  nse scripts for each servicve to use in your nmap ')
parser.add_argument('-m', '--mysql', action='store_true', help='Check for empty MySQL passwords')
parser.add_argument('-v', '--nuclei', action='store_true', help='Use Nuclei for vulnerability scanning')
parser.add_argument('-n', '--nikto', action='store_true', help='Use Nikto for vulnerability scanning')
parser.add_argument('-dos', '--scriptdos', action='store_true', help='Dos using Slowloris - Aggresive Use with CAUTION')
args = parser.parse_args()

# Initialize nmap scanner
scanner = nmap.PortScanner()

# Build the scan command with the specified arguments
command = f"-sV {args.ip_address_or_subnet}"
if args.timing:
  if args.timing == 'slow':
    command += " -T2"
  elif args.timing == 'normal':
    command += " -T3"
  elif args.timing == 'fast':
    command += " -T4"
if args.evasion:
  command += f" --packet-trace --data-length 24  '{args.evasion}'"
if args.arguments:
  command += f" {args.arguments}"
if args.waf:
  command += " --script=http-waf-detect"
if args.vuln:
  command += " --script=vuln"
if args.scriptdos:
 command += " --max-parallelism 1000 --script=http-slowloris -p80"
if args.mysql:
  command += " --script=mysql-empty-password"
if args.ping:
  command += " -sn"
if args.stealth:
 command += " -sS"
if args.os:
 command += " -O"
if args.nuclei:
 # Run the vulnerability scan using Nuclei
 subprocess.run(["nuclei","-u", args.ip_address_or_subnet,"rate-limit 80"])
if args.nikto:
  # Run the vulnerability scan using Nikto
 subprocess.run(["nikto","-h", args.ip_address_or_subnet])

else:
 # Run the vulnerability scan without Nuclei
 # Replace this with the command for your preferred vulnerability scanner
 print("Running ONLY nmap scan...")


# Run the scan
scan_results = scanner.scan(command)

# Print the results
for host in scan_results['scan']:
  print(f"Host: {host}")
  if 'osmatch' in scan_results['scan'][host]:
    osmatch = scan_results['scan'][host]['osmatch'][0]
    print(f"  OS: {osmatch['name']} ({osmatch['accuracy']}%)")
  if 'tcp' in scan_results['scan'][host]:
    for port in scan_results['scan'][host]['tcp']:
      print(f"  -> Port: {port}")
      print(f"  State: {scan_results['scan'][host]['tcp'][port]['state']}")
      print(f"  Service: {scan_results['scan'][host]['tcp'][port]['name']}")
      print(f"  Version: {scan_results['scan'][host]['tcp'][port]['product']} {scan_results['scan'][host]['tcp'][port]['version']}")
      if args.vuln:
        if 'script' in scan_results['scan'][host]['tcp'][port]:
          for script in scan_results['scan'][host]['tcp'][port]['script']:
            print(f"  Vulnerability: {script}")
  if args.vuln:
    if 'hostscript' in scan_results['scan'][host]:
      for script in scan_results['scan'][host]['hostscript']:
        print(f"  Vulnerability: {script}")
  if args.waf:
    if 'script' in scan_results['scan'][host]:
      for script in scan_results['scan'][host]['script']:
        if script['id'] == 'http-waf-detect':
          if 'WAF' in script['output']:
            print(f"  WAF detected: {script['output'].splitlines()[0]}")
  if args.mysql:
    if 'script' in scan_results['scan'][host]:
      for script in scan_results['scan'][host]['script']:
        if script['id'] == 'mysql-empty-password':
          if 'empty' in script['output']:
            print(f"  MySQL service with empty password detected: {script['output'].splitlines()[0]}")




