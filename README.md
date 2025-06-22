# masscan-nmap-auto

**masscan-nmap-auto** is an automated Python script that combines the speed of [masscan](https://github.com/robertdavidgraham/masscan) for rapid port discovery with the detailed service enumeration capabilities of [Nmap](https://nmap.org/).  
It efficiently scans large networks or lists of hosts, detects open ports, and performs targeted service/version detection only on those ports, saving time and bandwidth.
This script scans networks or host lists for open ports with masscan, then runs Nmap service detection **only on the specific open ports for each host**, saving time and bandwidth.

---

## Features

- 🚀 **Fast port discovery** with masscan
- 🎯 **Targeted Nmap scans**: Only open ports per host are scanned
- 📄 **Flexible input**: Single IP/CIDR or file with multiple targets
- 📝 **Clean output**: See exactly which ports are open on which hosts, and detailed Nmap results
- 📤 **Output to file**: All results and scan details can be saved to a text file

---

## Requirements

- Python 3.x
- [masscan](https://github.com/robertdavidgraham/masscan) (must be installed and in your PATH)
- [Nmap](https://nmap.org/) (must be installed and in your PATH)
- Root privileges (required by masscan and some Nmap options)

---

## Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/daemon-user/masscan-nmap-auto.git
   cd masscan-nmap-auto
   ```
2. **Make the script executable:**
   ```bash
   chmod +x masscan_nmap_auto.py
   ```

---

## Usage

```bash
sudo ./masscan_nmap_auto.py [options]
```

### **Options**

| Option               | Description                                                               |
|----------------------|---------------------------------------------------------------------------|
| `-i `        | Target IP address or CIDR (e.g., `192.168.1.0/24`)                        |
| `-f `          | File with target IPs/hostnames (one per line)                             |
| `-p `         | Ports to scan (e.g., `1-65535` or `22,80,443`) **[required]**             |
| `-r `          | masscan scan rate (default: 1000)                                         |
| `-o `   | Save script output (status, errors, commands) to a file                   |
| `-h`                 | Show help message                                                         |

**Note:** At least one of `-i` or `-f` must be specified.

---

### **Examples**

- Scan a single subnet for all ports, output to terminal:
  ```bash
  sudo ./masscan_nmap_auto.py -i 192.168.1.0/24 -p 1-1000
  ```

- Scan hosts from a file for common web ports, output to a file:
  ```bash
  sudo ./masscan_nmap_auto.py -f targets.txt -p 80,443 -o scan_report.txt
  ```

- Combine a single IP and a file of targets, scan top 1024 ports:
  ```bash
  sudo ./masscan_nmap_auto.py -i 10.0.0.1 -f targets.txt -p 1-1024
  ```

---

## Output

- **Script output:** Progress, errors, and commands are printed to the terminal and/or saved to the specified output file.
- **Scan results:**  
  - `mscan.json` — masscan JSON output  
  - `hosts.txt` — List of hosts with open ports  
  - `nmap_scan.*` — Nmap output files (XML, grepable, normal)
 

---

## Sample Output

```
[+] Running: sudo masscan 192.168.1.10,192.168.1.20 -p22,80,443 --rate 1000 -oJ mscan.json

[+] Masscan Open Ports:
  192.168.1.10:22
  192.168.1.10:80
  192.168.1.20:443

[+] Starting Nmap service detection on each host with its open ports...

[+] Scanning 192.168.1.10 on ports: 22,80
[+] Running: sudo nmap -n -vvv -Pn -sV -sC -p22,80 192.168.1.10
... (Nmap output here) ...

[+] Scanning 192.168.1.20 on ports: 443
[+] Running: sudo nmap -n -vvv -Pn -sV -sC -p443 192.168.1.20
... (Nmap output here) ...

[+] Script completed.
```

---

## Example `targets.txt` File

```
192.168.1.10
192.168.1.20
10.0.0.5
# This is a comment
```

---

## License

daemon-user

---

## Disclaimer

This tool is intended for authorized security testing and network auditing only.  
Unauthorized scanning may be illegal. Always obtain permission before scanning networks you do not own.

---
