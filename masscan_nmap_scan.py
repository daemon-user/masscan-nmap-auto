#!/usr/bin/env python3
import argparse
import os
import sys
import json

def parse_targets(ip_arg, file_arg, output):
    targets = set()
    if ip_arg:
        targets.add(ip_arg.strip())
    if file_arg:
        if not os.path.isfile(file_arg):
            output(f"[-] Target file {file_arg} does not exist.")
            sys.exit(1)
        with open(file_arg, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.add(line)
    return targets

def run_command(cmd, output):
    output(f"[+] Running: {cmd}")
    result = os.system(cmd)
    if result != 0:
        output(f"[-] Command failed: {cmd}")
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Automate masscan + Nmap for fast service detection"
    )
    parser.add_argument('-i', help='Target IP Addresses or CIDR (e.g., 192.168.1.0/24)')
    parser.add_argument('-f', help='File with target IPs/hostnames, one per line')
    parser.add_argument('-p', help='Target Ports (e.g., 1-65535)', required=True)
    parser.add_argument('-r', help='Masscan rate (default: 1000)', default="1000")
    parser.add_argument('-o', '--output', help='Output file to write script output')
    args = parser.parse_args()

    # Output handler
    if args.output:
        out_fp = open(args.output, "w")
        def output(msg):
            print(msg)
            out_fp.write(msg + "\n")
    else:
        def output(msg):
            print(msg)

    # Parse targets from CLI and/or file
    targets = parse_targets(args.i, args.f, output)
    if not targets:
        output("[-] No targets specified. Use -i, -f, or both.")
        if args.output:
            out_fp.close()
        sys.exit(1)

    target_str = ",".join(targets)

    # Step 1: Run masscan
    masscan_cmd = f"sudo masscan {target_str} -p{args.p} --rate {args.r} -oJ mscan.json"
    run_command(masscan_cmd, output)

    # Step 2: Parse masscan output
    if not os.path.isfile("mscan.json") or os.path.getsize("mscan.json") == 0:
        output("[-] No open ports found or masscan output missing.")
        if args.output:
            out_fp.close()
        sys.exit(1)

    hosts = {}
    port_set = set()

    with open("mscan.json") as f:
        results = json.load(f)
        for entry in results:
            ip = entry.get("ip")
            for portinfo in entry.get("ports", []):
                if portinfo.get("status") == "open":
                    port = portinfo.get("port")
                    port_set.add(port)
                    hosts.setdefault(ip, set()).add(port)

    if not hosts:
        output("[-] No open ports found in masscan results.")
        if args.output:
            out_fp.close()
        sys.exit(1)

    # Step 3: Write hosts to file
    with open("hosts.txt", "w") as f:
        for ip in hosts.keys():
            f.write(f"{ip}\n")

    # Step 4: Build port list for Nmap
    port_list_str = ",".join(str(p) for p in sorted(port_set))

    # Step 5: Run Nmap
    nmap_cmd = f"sudo nmap -n -vvv -Pn -sV -sC -iL hosts.txt -p{port_list_str} -oA nmap_scan"
    run_command(nmap_cmd, output)

    output("[+] Script completed.")
    if args.output:
        out_fp.close()

if __name__ == "__main__":
    main()
