#  Python Port Scanner using Nmap

This is a Python-based command-line tool that performs **TCP port scans** using the `nmap` library. It allows users to specify an IP address and a range of ports to scan, and saves the results to both `.txt` and `.csv` files.

##  Features

- IP address format validation.
- Port range format validation (e.g., `1-1000`).
- Uses `nmap` with service detection (`-sV`).
- Outputs results to:
  - `scan_results.txt`
  - `scan_results.csv`

##  Example Usage

```bash
$ python port_scanner.py
Enter the IP to scan: 192.167.1.1

Enter the port range to scan (e.g., 1-1000): 20-100
Scanning... This may take a few seconds.
Scan complete. Results saved in 'scan_results.txt' and 'scan_results.csv'.
