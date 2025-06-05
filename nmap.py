import nmap
import csv
import re

def validate_ip(ip):
    """Validate if the entered IP has a correct format."""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return re.match(ip_pattern, ip) is not None

def validate_ports(port_range):
    """Validate if the entered port range is correct (e.g., 1-1000)."""
    range_pattern = r"^\d{1,5}-\d{1,5}$"
    return re.match(range_pattern, port_range) is not None

def scan_ports(ip, port_range):
    """Perform a port scan on the given IP and save the results."""
    scanner = nmap.PortScanner()
    scanner.scan(ip, port_range, arguments='-sV')
    
    results = []
    
    for host in scanner.all_hosts():
        for port in scanner[host]['tcp']:
            port_info = scanner[host]['tcp'][port]
            results.append([
                host, port, port_info['state'], port_info.get('name', 'Unknown'), port_info.get('version', 'Not specified')
            ])
    
    save_results(results)
    
    return results

def save_results(results):
    """Save the scan results in .txt and .csv files."""
    with open("scan_results.txt", "w") as txt_file:
        for r in results:
            txt_file.write(f"IP: {r[0]} | Port: {r[1]} | State: {r[2]} | Service: {r[3]} | Version: {r[4]}\n")
    
    with open("scan_results.csv", "w", newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP", "Port", "State", "Service", "Version"])
        writer.writerows(results)

def main():
    ip = input("Enter the IP to scan: ")
    while not validate_ip(ip):
        print("Invalid IP. Please try again.")
        ip = input("Enter the IP to scan: ")
    
    port_range = input("Enter the port range to scan (e.g., 1-1000): ")
    while not validate_ports(port_range):
        print("Invalid port range. Please try again.")
        port_range = input("Enter the port range to scan: ")
    
    print("Scanning... This may take a few seconds.")
    results = scan_ports(ip, port_range)
    
    if results:
        print("Scan complete. Results saved in 'scan_results.txt' and 'scan_results.csv'.")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()

