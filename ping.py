import subprocess
import platform
import concurrent.futures
from datetime import datetime
import time
import re

class IPPinger:
    def __init__(self, ip_file, timeout=2, count=4, max_workers=10):
        """
        Initialize IP Pinger
        
        Args:
            ip_file: Path to text file containing IPs (one per line)
            timeout: Timeout in seconds for each ping attempt
            count: Number of ping packets to send
            max_workers: Number of concurrent ping operations
        """
        self.ip_file = ip_file
        self.timeout = timeout
        self.count = count
        self.max_workers = max_workers
        self.results = {
            'online': [],
            'dead': [],
            'partial': []
        }
        self.scan_start_time = None
        self.scan_end_time = None
    
    def load_ips(self):
        """Load IP addresses from file"""
        try:
            with open(self.ip_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            print(f"[INFO] Loaded {len(ips)} IP addresses from {self.ip_file}")
            return ips
        except FileNotFoundError:
            print(f"[ERROR] File {self.ip_file} not found!")
            return []
    
    def ping_ip(self, ip):
        """
        Ping a single IP address
        
        Returns:
            dict: Status information for the IP
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        # Build ping command
        command = ['ping', param, str(self.count), timeout_param, str(self.timeout * 1000 if platform.system().lower() == 'windows' else self.timeout), ip]
        
        try:
            # Execute ping
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout * self.count + 5
            )
            
            # Check for "Destination host unreachable" or similar error messages
            output_lower = output.stdout.lower()
            if any(error in output_lower for error in [
                'destination host unreachable',
                'destination net unreachable',
                'destination protocol unreachable',
                'destination port unreachable',
                'host unreachable',
                'network unreachable',
                'request timed out',
                '100% packet loss',
                '100% loss'
            ]):
                print(f"[✗] {ip:20s} - DEAD (Host Unreachable)")
                return {
                    'ip': ip,
                    'status': 'dead',
                    'packets_sent': self.count,
                    'packets_received': 0,
                    'packet_success_rate': 0.0,
                    'response_time': None,
                    'raw_output': output.stdout
                }
            
            # Parse results
            response_time = None
            packets_received = 0
            
            if platform.system().lower() == 'windows':
                # Windows parsing
                received_match = re.search(r'Received = (\d+)', output.stdout)
                time_match = re.search(r'Average = (\d+)ms', output.stdout)
                if received_match:
                    packets_received = int(received_match.group(1))
                if time_match:
                    response_time = int(time_match.group(1))
            else:
                # Linux/Mac parsing
                received_match = re.search(r'(\d+) received', output.stdout)
                time_match = re.search(r'avg/[^=]+=\s*([\d.]+)', output.stdout)
                if received_match:
                    packets_received = int(received_match.group(1))
                if time_match:
                    response_time = float(time_match.group(1))
            
            # Determine status based on percentage of packets received
            packet_success_rate = (packets_received / self.count) * 100

            if packet_success_rate >= 80:
                status = 'online'
                status_symbol = '✓'
                status_color = 'ONLINE'
            elif packet_success_rate > 0:
                status = 'partial'
                status_symbol = '~'
                status_color = 'PARTIAL'
            else:
                status = 'dead'
                status_symbol = '✗'
                status_color = 'DEAD'

            result = {
                'ip': ip,
                'status': status,
                'packets_sent': self.count,
                'packets_received': packets_received,
                'packet_success_rate': packet_success_rate,
                'response_time': response_time,
                'raw_output': output.stdout
            }

            # Print to console
            if status == 'online':
                print(f"[{status_symbol}] {ip:20s} - {status_color:10s} | Recv: {packets_received}/{self.count} ({packet_success_rate:.0f}%) | Avg Time: {response_time}ms")
            elif status == 'partial':
                print(f"[{status_symbol}] {ip:20s} - {status_color:10s} | Recv: {packets_received}/{self.count} ({packet_success_rate:.0f}%) | Avg Time: {response_time if response_time else 'N/A'}ms")
            else:
                print(f"[{status_symbol}] {ip:20s} - {status_color:10s} | Recv: {packets_received}/{self.count} ({packet_success_rate:.0f}%)")
            
            return result
            
        except subprocess.TimeoutExpired:
            print(f"[✗] {ip:20s} - TIMEOUT")
            return {
                'ip': ip,
                'status': 'dead',
                'packets_sent': self.count,
                'packets_received': 0,
                'packet_success_rate': 0.0,
                'response_time': None,
                'raw_output': 'Timeout'
            }
        except Exception as e:
            print(f"[!] {ip:20s} - ERROR: {str(e)}")
            return {
                'ip': ip,
                'status': 'dead',
                'packets_sent': self.count,
                'packets_received': 0,
                'packet_success_rate': 0.0,
                'response_time': None,
                'raw_output': f'Error: {str(e)}'
            }
    
    def scan(self):
        """Scan all IPs with concurrent execution"""
        ips = self.load_ips()
        if not ips:
            return
        
        print("\n" + "="*80)
        print(f"Starting ping scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Parameters: Timeout={self.timeout}s, Count={self.count}, Workers={self.max_workers}")
        print("="*80 + "\n")
        
        self.scan_start_time = datetime.now()
        
        # Ping IPs concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.ping_ip, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result['status'] == 'online':
                    self.results['online'].append(result)
                elif result['status'] == 'partial':
                    self.results['partial'].append(result)
                else:
                    self.results['dead'].append(result)
        
        self.scan_end_time = datetime.now()
        
        # Display summary
        self.display_summary()
        
        # Save report
        self.save_report()
    
    def display_summary(self):
        """Display summary in console"""
        total = len(self.results['online']) + len(self.results['dead']) + len(self.results['partial'])
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        print(f"Scan Duration: {duration:.2f} seconds")
        print(f"Total IPs Scanned: {total}")
        print(f"Online: {len(self.results['online'])} ({len(self.results['online'])/total*100:.1f}%)")
        print(f"Partial Response: {len(self.results['partial'])} ({len(self.results['partial'])/total*100:.1f}%)")
        print(f"Dead: {len(self.results['dead'])} ({len(self.results['dead'])/total*100:.1f}%)")
        print("="*80)
        
        if self.results['dead']:
            print("\nDEAD IPs:")
            for result in sorted(self.results['dead'], key=lambda x: x['ip']):
                print(f"  - {result['ip']}")
        
        if self.results['partial']:
            print("\nPARTIAL RESPONSE IPs:")
            for result in sorted(self.results['partial'], key=lambda x: x['ip']):
                print(f"  - {result['ip']} (Received {result['packets_received']}/{result['packets_sent']})")
        
        print("\n")
    
    def save_report(self):
        """Save detailed report to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'ping_report_{timestamp}.txt'
        
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("PING SCAN REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Scan Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan End Time: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {(self.scan_end_time - self.scan_start_time).total_seconds():.2f} seconds\n")
            f.write(f"Source File: {self.ip_file}\n\n")
            
            f.write("SCAN PARAMETERS:\n")
            f.write(f"  - Timeout per ping: {self.timeout} seconds\n")
            f.write(f"  - Ping count: {self.count}\n")
            f.write(f"  - Concurrent workers: {self.max_workers}\n")
            f.write(f"  - Online threshold: >= 80% packet success rate\n\n")
            
            total = len(self.results['online']) + len(self.results['dead']) + len(self.results['partial'])
            
            f.write("="*80 + "\n")
            f.write("SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(f"Total IPs Scanned: {total}\n")
            f.write(f"Online: {len(self.results['online'])} ({len(self.results['online'])/total*100:.1f}%)\n")
            f.write(f"Partial Response: {len(self.results['partial'])} ({len(self.results['partial'])/total*100:.1f}%)\n")
            f.write(f"Dead: {len(self.results['dead'])} ({len(self.results['dead'])/total*100:.1f}%)\n\n")
            
            # Online IPs
            f.write("="*80 + "\n")
            f.write(f"ONLINE IPs ({len(self.results['online'])})\n")
            f.write("="*80 + "\n")
            for result in sorted(self.results['online'], key=lambda x: x['ip']):
                f.write(f"{result['ip']:20s} | Packets: {result['packets_received']}/{result['packets_sent']} ({result['packet_success_rate']:.0f}%) | Avg Time: {result['response_time']}ms\n")
            
            # Partial IPs
            if self.results['partial']:
                f.write("\n" + "="*80 + "\n")
                f.write(f"PARTIAL RESPONSE IPs ({len(self.results['partial'])})\n")
                f.write("="*80 + "\n")
                for result in sorted(self.results['partial'], key=lambda x: x['ip']):
                    f.write(f"{result['ip']:20s} | Packets: {result['packets_received']}/{result['packets_sent']} ({result['packet_success_rate']:.0f}%) | Avg Time: {result['response_time'] if result['response_time'] else 'N/A'}ms\n")
            
            # Dead IPs
            f.write("\n" + "="*80 + "\n")
            f.write(f"DEAD IPs ({len(self.results['dead'])})\n")
            f.write("="*80 + "\n")
            for result in sorted(self.results['dead'], key=lambda x: x['ip']):
                f.write(f"{result['ip']}\n")
            
            # Detailed results
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED RESULTS\n")
            f.write("="*80 + "\n\n")
            
            all_results = self.results['online'] + self.results['partial'] + self.results['dead']
            for result in sorted(all_results, key=lambda x: x['ip']):
                f.write(f"\nIP: {result['ip']}\n")
                f.write(f"Status: {result['status'].upper()}\n")
                f.write(f"Packets Sent: {result['packets_sent']}\n")
                f.write(f"Packets Received: {result['packets_received']}\n")
                f.write(f"Success Rate: {result['packet_success_rate']:.1f}%\n")
                f.write(f"Response Time: {result['response_time']}ms\n" if result['response_time'] else "Response Time: N/A\n")
                f.write("-"*80 + "\n")
        
        print(f"[INFO] Detailed report saved to: {report_file}")


# Main execution
if __name__ == "__main__":
    # Configuration
    IP_FILE = 'deadv1.txt'  # Change this to your file name
    TIMEOUT = 2              # Timeout in seconds for each ping
    PING_COUNT = 60           # Number of pings per IP
    MAX_WORKERS = 10      # Number of concurrent ping operations
    
    # Create and run scanner
    scanner = IPPinger(
        ip_file=IP_FILE,
        timeout=TIMEOUT,
        count=PING_COUNT,
        max_workers=MAX_WORKERS
    )
    
    scanner.scan()