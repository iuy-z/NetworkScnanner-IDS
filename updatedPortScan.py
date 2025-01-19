import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from collections import defaultdict
import time
import threading

# Initialize global variables
arp_cache = defaultdict(set)  # To store ARP IP-MAC mappings
traffic_count = defaultdict(int)  # To monitor traffic rate per IP
port_scan_attempts = defaultdict(set)  # To track port scans
last_reset_time = time.time()  # To periodically reset counters
vulnerable_ports = [21, 22, 23, 80, 443]  # Common ports for analysis
alerted_ports = set()  # To suppress duplicate port alerts

# Thresholds
DOS_THRESHOLD = 100  # Packets per 5 seconds
PORT_SCAN_THRESHOLD = 10  # Ports accessed rapidly
HALF_OPEN_THRESHOLD = 50  # Half-open connections for DDoS detection
SYN_THRESHOLD = 200  # SYN packets for DDoS detection

# Function to detect ARP Spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc
        
        if source_ip in arp_cache and source_mac not in arp_cache[source_ip]:
            print(f"[ALERT] ARP Spoofing detected! IP: {source_ip} is resolving to multiple MACs.")
        
        arp_cache[source_ip].add(source_mac)

# # Function to detect DoS and DDoS attacks
# def detect_dos():
#     global last_reset_time
#     current_time = time.time()
#     if current_time - last_reset_time > 5:  # Check every 5 seconds
#         for source_ip, count in traffic_count.items():
#             if count > DOS_THRESHOLD:
#                 print(f"[ALERT] Potential DoS attack from IP: {source_ip} with {count} packets in 5 seconds.")
#         traffic_count.clear()
#         last_reset_time = current_time


# def detect_ddos(packet):
#     if packet.haslayer(TCP):
#         tcp_layer = packet[TCP]
#         source_ip = packet[IP].src

#         if tcp_layer.flags == "S":  # SYN packet
#             traffic_count[source_ip] += 1
#         elif tcp_layer.flags == "SA":  # SYN-ACK packet
#             traffic_count[source_ip] -= 1

#         # Check thresholds
#         if traffic_count[source_ip] > HALF_OPEN_THRESHOLD:
#             print(f"[ALERT] Potential DDoS attack from IP: {source_ip}! Half-open connections: {traffic_count[source_ip]}.")

# Function to detect DoS attacks with optimized logic
def detect_dos(packet):
    global last_reset_time

    # Process only IP packets
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        traffic_count[source_ip] += 1

    # Periodic check for DoS attack
    current_time = time.time()
    if current_time - last_reset_time > 10:  # Check every 10 seconds
        for ip, count in traffic_count.items():
            if count > DOS_THRESHOLD:
                print(f"[ALERT] DoS attack detected! Source IP: {ip}, Packets: {count} in 10 seconds.")
        # Reset counters
        traffic_count.clear()
        last_reset_time = current_time

# Function to detect DDoS attacks (SYN flood)
def detect_ddos(packet):
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        tcp_layer = packet[TCP]

        # Count SYN packets
        if tcp_layer.flags == "S":
            traffic_count[source_ip] += 1

        # Detect half-open connections
        if traffic_count[source_ip] > HALF_OPEN_THRESHOLD:
            print(f"[ALERT] Potential DDoS detected! Source IP: {source_ip}, SYN packets: {traffic_count[source_ip]}.")

# Process packets and call detection functions
def process_packet(packet):
    try:
        detect_arp_spoof(packet)
        detect_dos(packet)
        detect_ddos(packet)
        detect_port_scanning(packet)
        detect_dns_spoof(packet)
    except Exception as e:
        print(f"[ERROR] An exception occurred: {e}")


# Function to detect Port Scanning
def detect_port_scanning(packet):
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport

        port_scan_attempts[source_ip].add(dest_port)

        # Detect excessive port scans
        if len(port_scan_attempts[source_ip]) > PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Port scanning detected from IP: {source_ip}. Ports scanned: {list(port_scan_attempts[source_ip])}")
            port_scan_attempts[source_ip].clear()

        # Detect vulnerable ports
        if dest_port in vulnerable_ports and (source_ip, dest_port) not in alerted_ports:
            print(f"[ALERT] Vulnerable Port Detected! Source IP: {source_ip} Port: {dest_port}")
            alerted_ports.add((source_ip, dest_port))

# # Function to detect DNS Spoofing
# def detect_dns_spoof(packet):
#     if packet.haslayer(DNS) and packet.haslayer(DNSRR):
#         dns_query = packet[DNSQR].qname.decode('utf-8') if packet[DNSQR] else "Unknown"
#         dns_response = packet[DNSRR].rdata if packet[DNSRR] else "Unknown"

#         # Simulate a simple malicious DNS detection
#         trusted_ips = ["8.8.8.8", "8.8.4.4"]  # Example of trusted DNS servers
#         if dns_response not in trusted_ips:
#             print(f"[ALERT] DNS Spoofing detected for query: {dns_query} -> Response: {dns_response}")

# Function to detect DNS Spoofing with error handling
def detect_dns_spoof(packet):
    if packet.haslayer(DNS):  # Check if the packet has a DNS layer
        dns_query = "Unknown"
        dns_response = "Unknown"

        # Safely handle DNSQR and DNSRR layers
        if packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8') if packet[DNSQR].qname else "Unknown"
        if packet.haslayer(DNSRR):
            dns_response = packet[DNSRR].rdata if packet[DNSRR].rdata else "Unknown"

        # Simulate a simple malicious DNS detection
        trusted_ips = ["8.8.8.8", "8.8.4.4"]  # Example of trusted DNS servers
        if dns_response not in trusted_ips and dns_response != "Unknown":
            print(f"[ALERT] DNS Spoofing detected for query: {dns_query} -> Response: {dns_response}")




# Main sniffer function
def start_sniffer(interface):
    print("[INFO] Starting packet sniffer...")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# Process packets and call respective detection functions
# def process_packet(packet):
#     try:
#         detect_arp_spoof(packet)
#         detect_ddos(packet)
#         detect_port_scanning(packet)
#         detect_dns_spoof(packet)
#     except Exception as e:
#         print(f"[ERROR] An exception occurred: {e}")

def reset_trackers():
    global traffic_count, port_scan_attempts, alerted_ports
    while True:
        time.sleep(60)  # Reset every 60 seconds
        traffic_count.clear()
        port_scan_attempts.clear()
        alerted_ports.clear()

if __name__ == "__main__":
    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    reset_thread = threading.Thread(target=reset_trackers, daemon=True)
    reset_thread.start()
    start_sniffer(interface)
