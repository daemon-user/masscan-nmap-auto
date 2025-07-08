#!/usr/bin/env python3
import argparse
import os
import sys
import json
import subprocess
import signal

STATE_FILE = "scan_state.json"

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

def run_command(cmd, output, suppress_output=False):
    output(f"[+] Running: {cmd}")
    try:
        if suppress_output:
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            if result.stderr:
                output(f"[-] Command error output: {result.stderr}")
            return 0
        else:
            result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output(result.stdout)
            return 0
    except subprocess.CalledProcessError as e:
        output(f"[-] Command failed: {cmd}")
        output(e.stdout if e.stdout else str(e))
        return e.returncode

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def load_state():
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}

def main():
    parser = argparse.ArgumentParser(
        description="Automate masscan + Nmap for fast service detection with pause/resume"
    )
    parser.add_argument('-i', help='Target IP Addresses or CIDR (e.g., 192.168.1.0/24)')
    parser.add_argument('-f', help='File with target IPs/hostnames, one per line')
    parser.add_argument('-p', help='Target Ports (e.g., 1-65535)', required=True)
    parser.add_argument('-r', help='Masscan rate (default: 1000)', default="1000")
    parser.add_argument('-o', '--output', help='Output file to write script output')
    args = parser.parse_args()

    # Output handler
    if args.output:
        out_fp = open(args.output, "a")
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

    # Step 1: Run masscan (suppress progress output)
    masscan_cmd = f"sudo masscan {target_str} -p{args.p} --rate {args.r} -oJ mscan.json"
    if not os.path.isfile("mscan.json") or os.path.getsize("mscan.json") == 0:
        run_command(masscan_cmd, output, suppress_output=True)
    else:
        output("[+] Using existing mscan.json file.")

    # Step 2: Parse masscan output
    if not os.path.isfile("mscan.json") or os.path.getsize("mscan.json") == 0:
        output("[-] No open ports found or masscan output missing.")
        if args.output:
            out_fp.close()
        sys.exit(1)

    hosts = {}
    with open("mscan.json") as f:
        try:
            results = json.load(f)
        except Exception as e:
            output(f"[-] Failed to parse masscan JSON output: {e}")
            if args.output:
                out_fp.close()
            sys.exit(1)
        for entry in results:
            ip = entry.get("ip")
            for portinfo in entry.get("ports", []):
                if portinfo.get("status") == "open":
                    port = portinfo.get("port")
                    hosts.setdefault(ip, set()).add(port)

    if not hosts:
        output("[-] No open ports found in masscan results.")
        if args.output:
            out_fp.close()
        sys.exit(1)

    # Print clean open port/IP details
    output("\n[+] Masscan Open Ports:")
    for host, ports in hosts.items():
        for port in ports:
            output(f"  {host}:{port}")

    # Load previous scan state if exists
    scan_state = load_state()
    if "scanned_hosts" not in scan_state:
        scan_state["scanned_hosts"] = []

    # Handle SIGINT for pause functionality
    def handle_sigint(signum, frame):
        output("\n[!] Pausing scan. Saving state to resume later...")
        save_state(scan_state)
        if args.output:
            out_fp.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    # Step 3: Run Nmap on each host with its specific open ports
    output("\n[+] Starting Nmap service detection on each host with its open ports...")
    try:
        for host, ports in hosts.items():
            if host in scan_state["scanned_hosts"]:
                output(f"[+] Skipping {host} (already scanned)")
                continue
            port_list_str = ",".join(str(p) for p in sorted(ports))
            output(f"\n[+] Scanning {host} on ports: {port_list_str}")
            nmap_cmd = f"sudo nmap -n -vvv -Pn -sV -sC -p{port_list_str} {host}"
            run_command(nmap_cmd, output)
            scan_state["scanned_hosts"].append(host)
            save_state(scan_state)
    except Exception as e:
        output(f"[-] Exception occurred: {e}")
        save_state(scan_state)
        if args.output:
            out_fp.close()
        sys.exit(1)

    output("\n[+] Script completed. All hosts scanned.")
    # Clean up state file after completion
    if os.path.isfile(STATE_FILE):
        os.remove(STATE_FILE)
    if args.output:
        out_fp.close()

if __name__ == "__main__":
    main()
