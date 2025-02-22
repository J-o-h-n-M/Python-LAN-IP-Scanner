import socket
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
import ipaddress

# Define well-known ports (1-1023, includes HTTP, FTP, etc.) and additional common ports
WELL_KNOWN_PORTS = list(range(1, 1024))  # Includes HTTP (80), FTP (21), SSH (22), etc.
COMMON_PORTS = [
    8080,  # HTTP Alternate
    3306,  # MySQL
    1433,  # SQL Server
    3389,  # RDP
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP Alternate
    8443,  # HTTPS Alternate
    9000,  # HTTP Alternate
    9090,  # HTTP Alternate
    5432,  # PostgreSQL
    27017, # MongoDB
    11211, # Memcached
    5672,  # RabbitMQ
    9200,  # Elasticsearch
    5044,  # Logstash
    5601,  # Kibana
    2181,  # ZooKeeper
    9092,  # Kafka
    10000, # Webmin
    1723,  # PPTP
    1194,  # OpenVPN
    5060,  # SIP
    3478,  # STUN
    6881   # BitTorrent
]
PORTS_TO_SCAN = WELL_KNOWN_PORTS + COMMON_PORTS

def get_local_ip():
    """
    Get the local IP address of the machine.
    Returns:
        str: The local IP address, or '127.0.0.1' if unable to determine.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def scan_network(ip_range):
    """
    Scan the network using ARP requests to find active devices.
    Args:
        ip_range (str): The network range to scan (e.g., '192.168.1.0/24').
    Returns:
        list: List of dictionaries containing IP and MAC addresses of active devices.
    """
    print("Scanning the network for active devices...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print(f"Network scan complete. Found {len(devices)} devices.")
    return devices

def get_hostname(ip):
    """
    Get the hostname of the device based on its IP address using reverse DNS lookup.
    Args:
        ip (str): IP address of the device.
    Returns:
        str: Hostname or 'Unknown' if not found or on error.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"
    except:
        return "Unknown"

def is_port_open(ip, port, timeout=1):
    """
    Check if a specific port is open on the given IP.
    Args:
        ip (str): IP address to scan.
        port (int): Port number to check.
        timeout (float): Timeout for connection attempt in seconds.
    Returns:
        bool: True if the port is open, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def scan_ports(ip, ports, max_workers=100):
    """
    Scan the list of specified ports on the given IP using multi-threading.
    Args:
        ip (str): IP address to scan.
        ports (list): List of port numbers to scan.
        max_workers (int): Maximum number of concurrent threads.
    Returns:
        list: List of open port numbers.
    """
    print(f"Starting port scan for IP: {ip}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(is_port_open, ip, port) for port in ports]
        results = [future.result() for future in futures]
    open_ports = [port for port, is_open in zip(ports, results) if is_open]
    print(f"Completed port scan for IP: {ip} - Found {len(open_ports)} open ports")
    return open_ports

if __name__ == "__main__":
    # Get the local IP address
    local_ip = get_local_ip()
    
    # Determine the network range (assuming /24 subnet)
    network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
    
    # Scan the network to find active devices
    devices = scan_network(network)
    
    if not devices:
        print("No active devices found on the network.")
    else:
        print(f"Found {len(devices)} devices. Starting hostname lookups and port scans...")
        
        # Start hostname lookups concurrently
        with ThreadPoolExecutor(max_workers=10) as hostname_executor:
            hostname_futures = {device['ip']: hostname_executor.submit(get_hostname, device['ip']) for device in devices}
        
        # Sort devices by IP address for better readability
        devices.sort(key=lambda x: ipaddress.ip_address(x['ip']))
        
        # Use a ThreadPoolExecutor to scan multiple IPs concurrently
        max_ip_workers = 3  # Adjust based on your system's capabilities
        with ThreadPoolExecutor(max_workers=max_ip_workers) as ip_executor:
            port_futures = {device['ip']: ip_executor.submit(scan_ports, device['ip'], PORTS_TO_SCAN) for device in devices}
        
        # Collect the results
        table = []
        for device in devices:
            open_ports = port_futures[device['ip']].result()
            open_ports_str = ', '.join(map(str, open_ports)) if open_ports else 'None'
            hostname = hostname_futures[device['ip']].result()
            table.append([device['ip'], device['mac'], hostname, open_ports_str])
        
        # Print the results table
        print("All scans complete. Displaying results...")
        headers = ['IP Address', 'MAC Address', 'Hostname', 'Open Ports']
        print(tabulate(table, headers, tablefmt='grid'))