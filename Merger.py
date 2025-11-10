import ipaddress
import pandas as pd
from pathlib import Path

def parse_dhcp_file(filename):
    """Parse DHCP reservations file with format: [ip] Name"""
    ip_name_dict = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    parts = line.split(None, 1)  # Split on whitespace, max 2 parts
                    if len(parts) >= 1:
                        ip = parts[0]
                        name = parts[1] if len(parts) == 2 else ip
                        ip_name_dict[ip] = name
    except FileNotFoundError:
        print(f"Warning: {filename} not found")
    return ip_name_dict

def parse_nmap_file(filename):
    """Parse nmap file with just IP addresses"""
    ip_list = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    ip_list.append(line)
    except FileNotFoundError:
        print(f"Warning: {filename} not found")
    return ip_list

def sort_ips(ip_list):
    """Sort IP addresses in ascending order"""
    try:
        return sorted(ip_list, key=lambda ip: ipaddress.ip_address(ip))
    except:
        # Fallback to string sorting if IP parsing fails
        return sorted(ip_list)

# Main script
def main():
    # Parse both files
    dhcp_data = parse_dhcp_file('DC_dhcp.txt')
    nmap_ips = parse_nmap_file('DC_nmap.txt')
    
    # Combine all IPs
    all_ips = {}
    
    # Add DHCP reservations
    all_ips.update(dhcp_data)
    
    # Add nmap IPs (use IP as name if not already in dict)
    for ip in nmap_ips:
        if ip not in all_ips:
            all_ips[ip] = ip
    
    # Sort IPs
    sorted_ips = sort_ips(list(all_ips.keys()))
    
    # Create DataFrame
    data = {
        'IP Address': sorted_ips,
        'Name': [all_ips[ip] for ip in sorted_ips]
    }
    df = pd.DataFrame(data)
    
    # Save to Excel
    output_file = 'merged_ip_list.xlsx'
    df.to_excel(output_file, index=False, sheet_name='IP List')
    
    print(f"Successfully created {output_file}")
    print(f"Total entries: {len(df)}")
    print(f"\nFirst few entries:")
    print(df.head(10))

if __name__ == "__main__":
    main()