import subprocess
import re
import platform

def get_mac_from_ip(ip_address):
    """Get MAC address for a given IP address using ARP"""
    try:
        # Determine the OS and use appropriate command
        system = platform.system().lower()
        
        if system == "windows":
            # Windows: arp -a
            command = ["arp", "-a", ip_address]
        else:
            # Linux/Mac: arp -n
            command = ["arp", "-n", ip_address]
        
        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        output = result.stdout
        
        # Extract MAC address from output
        # Pattern matches MAC addresses in various formats
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        match = re.search(mac_pattern, output)
        
        if match:
            mac = match.group(0).upper().replace('-', ':')
            return mac
        else:
            return None
            
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)}"

def ping_ip(ip_address):
    """Ping IP address to populate ARP cache"""
    try:
        system = platform.system().lower()
        
        if system == "windows":
            # Windows ping: -n 1 (count), -w 1000 (timeout in ms)
            command = ["ping", "-n", "1", "-w", "1000", ip_address]
        else:
            # Linux/Mac ping: -c 1 (count), -W 1 (timeout in seconds)
            command = ["ping", "-c", "1", "-W", "1", ip_address]
        
        subprocess.run(command, capture_output=True, timeout=2)
    except:
        pass

def read_ip_from_file(file_path):
    """Read IP addresses from text file"""
    ips = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            # Extract IP addresses using regex
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, content)
            # Remove duplicates while preserving order
            seen = set()
            unique_ips = []
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    unique_ips.append(ip)
            return unique_ips
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def get_macs_for_ips(ip_file):
    """Get MAC addresses for all IPs in the file"""
    
    # Read IP addresses from file
    print("Reading IP addresses from file...")
    ip_list = read_ip_from_file(ip_file)
    
    if not ip_list:
        print("No IP addresses found in the file.")
        return []
    
    print(f"Found {len(ip_list)} unique IP addresses.")
    print("\nPinging IPs to populate ARP cache...")
    
    # Ping all IPs first to populate ARP cache
    for i, ip in enumerate(ip_list, 1):
        print(f"  Pinging {i}/{len(ip_list)}: {ip}", end='\r')
        ping_ip(ip)
    
    print("\n\nRetrieving MAC addresses...\n")
    
    # Get MAC addresses
    results = []
    print(f"{'IP Address':<20} {'MAC Address':<20} {'Status'}")
    print("-" * 60)
    
    for ip in ip_list:
        mac = get_mac_from_ip(ip)
        status = "Found" if mac and mac != "Timeout" and not mac.startswith("Error") else "Not Found"
        
        if mac:
            print(f"{ip:<20} {mac:<20} {status}")
        else:
            print(f"{ip:<20} {'N/A':<20} {status}")
        
        results.append({
            'ip': ip,
            'mac': mac if mac else 'N/A',
            'status': status
        })
    
    return results

def save_results(results, output_file='ip_mac_mapping.txt'):
    """Save IP-MAC mapping to file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write("IP Address to MAC Address Mapping\n")
            file.write("="*60 + "\n\n")
            file.write(f"{'IP Address':<20} {'MAC Address':<20} {'Status'}\n")
            file.write("-"*60 + "\n")
            
            for result in results:
                file.write(f"{result['ip']:<20} {result['mac']:<20} {result['status']}\n")
            
            # Summary
            found_count = sum(1 for r in results if r['status'] == 'Found')
            file.write("\n" + "="*60 + "\n")
            file.write(f"Total IPs: {len(results)}\n")
            file.write(f"MACs Found: {found_count}\n")
            file.write(f"Not Found: {len(results) - found_count}\n")
        
        print(f"\n✓ Results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

def save_csv_results(results, output_file='ip_mac_mapping.csv'):
    """Save results in CSV format"""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write("IP Address,MAC Address,Status\n")
            for result in results:
                file.write(f"{result['ip']},{result['mac']},{result['status']}\n")
        
        print(f"✓ CSV results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving CSV: {e}")

# Main execution
if __name__ == "__main__":
    # Specify your IP list file
    ip_file = "ip_list.txt"  # Replace with your file path
    
    print("="*60)
    print("IP to MAC Address Resolver")
    print("="*60 + "\n")
    
    # Get MAC addresses for all IPs
    results = get_macs_for_ips(ip_file)
    
    if results:
        # Save results
        save_results(results)
        save_csv_results(results)
        
        # Summary
        found_count = sum(1 for r in results if r['status'] == 'Found')
        print(f"\n{'='*60}")
        print(f"Summary: {found_count}/{len(results)} MAC addresses found")
        print(f"{'='*60}")