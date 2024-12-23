from collections import defaultdict
import argparse
import subprocess
import sys
import logging
from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr, IP, TCP, UDP, Ether, ARP, DNS, HTTPRequest
import time
import matplotlib.pyplot as plt

IP_REQUEST_THRESHOLD = 100
PORT_REQUEST_THRESHOLD = 50
ARP_SPOOF_THRESHOLD = 5
DNS_REQUEST_THRESHOLD = 50
HTTP_REQUEST_THRESHOLD = 20

ip_activity = defaultdict(int)
port_activity = defaultdict(int)
arp_activity = defaultdict(int)
dns_activity = defaultdict(int)
http_activity = defaultdict(int)

packet_counts = []
timestamps = []

def install_requirements():
    """Ensure all required packages are installed."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except subprocess.CalledProcessError:
        logging.error("Failed to install required packages.")
        sys.exit(1)

def print_welcome_message():
    welcome_message = """
    █████████████████████████████████████████████████████████████████████                    
      
      |                         TailTrace                               |
      |                         /\_____/\                               |
      |                        /  o   o  \  < Meow! Network sniffed!    |
      |                       ( ==  ^  == )                             |
      |                        )         (                              |
      |                       (           )                             |
      |                      ( (  )   (  ) )                            |
      |                     (__(__)___(__)__)                           |
      |                                                                 |
      █████████████████████████████████████████████████████████████████████

      --=[ TailTrace v1.0.0 ]=--

      TailTrace tip: Never underestimate a cat's curiosity or a network packet.
    **************************************************************
    * TailTrace v1.0.0                                            *
    * License: MIT                                               *
    * Author: Andrii Tyshkevych                                  *
    * Description: A network traffic analyzer and capture tool. *
    **************************************************************
    """
    print(welcome_message)

def detect_anomalies(packet):
    """Check the packet for anomalies."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_activity[src_ip] += 1

        if ip_activity[src_ip] > IP_REQUEST_THRESHOLD:
            print(f"[ALERT] Abnormal activity from IP: {src_ip} (requests: {ip_activity[src_ip]})")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            port_activity[port] += 1
            if port_activity[port] > PORT_REQUEST_THRESHOLD:
                print(f"[ALERT] Abnormal activity on the port: {port} (requests: {port_activity[port]})")

    if packet.haslayer(ARP):
        arp_src = packet[ARP].psrc
        arp_activity[arp_src] += 1
        if arp_activity[arp_src] > ARP_SPOOF_THRESHOLD:
            print(f"[ALERT] Potential ARP spoofing detected from IP: {arp_src}")

    if packet.haslayer(DNS):
        dns_query = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else "Unknown"
        dns_activity[dns_query] += 1
        if dns_activity[dns_query] > DNS_REQUEST_THRESHOLD:
            print(f"[ALERT] High DNS activity for domain: {dns_query} (requests: {dns_activity[dns_query]})")

    if packet.haslayer(HTTPRequest):
        http_host = packet[HTTPRequest].Host.decode('utf-8') if packet[HTTPRequest].Host else "Unknown"
        http_activity[http_host] += 1
        if http_activity[http_host] > HTTP_REQUEST_THRESHOLD:
            print(f"[ALERT] High HTTP activity for host: {http_host} (requests: {http_activity[http_host]})")

def is_own_packet(packet, own_mac):
    """Check if the packet is from our own interface."""
    return packet.haslayer(Ether) and packet[Ether].src.lower() == own_mac.lower()

def packet_callback(packet, analyze=False, own_mac=None):
    """Callback function to process each captured packet."""
    if own_mac and is_own_packet(packet, own_mac):
        return

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
    else:
        ip_src = ip_dst = "N/A"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        src_port = dst_port = "N/A"

    packet_counts.append(1)
    timestamps.append(time.time())

    packet_info = f"Source: {ip_src} | Destination: {ip_dst} | Src Port: {src_port} | Dst Port: {dst_port}"
    print(packet_info)

    if analyze:
        detect_anomalies(packet)
        plot_traffic()


def capture_traffic(analyze=False, only_external=False):
    """Capture network traffic from a specified interface."""
    interfaces = get_if_list()
    if not interfaces:
        print("No network interfaces found.")
        sys.exit(1)

    print("Available network interfaces:")
    interface_names = {}
    for idx, iface in enumerate(interfaces, 1):
        try:
            ip_addr = get_if_addr(iface)
            if ip_addr == "0.0.0.0":
                ip_addr = "No IP assigned"
            interface_names[idx] = (iface, ip_addr)
            print(f"{idx}. {iface} ({ip_addr})")
        except Exception as e:
            logging.warning(f"Could not get IP for interface {iface}: {e}")
            interface_names[idx] = (iface, 'Unknown')

    try:
        selected_idx = int(input("Select an interface by number: ")) - 1
        if selected_idx < 0 or selected_idx >= len(interface_names):
            raise ValueError("Invalid selection.")
        interface, iface_name = interface_names[selected_idx + 1]
        own_mac = get_if_hwaddr(interface)
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        sys.exit(1)

    print(f"Capturing traffic on interface {interface} ({iface_name})...")

    try:
        if only_external:
            sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, analyze=False, own_mac=own_mac), store=0)
        else:
            sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, analyze=analyze), store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        
def plot_traffic():
    """Plot live traffic on a graph."""
    plt.clf()
    plt.plot(timestamps, packet_counts, label="Packets per second", color='blue')
    plt.xlabel("Time")
    plt.ylabel("Packet count")
    plt.title("Network Traffic (Packets per second)")
    plt.draw()
    plt.pause(0.1)

def main():
    install_requirements()
    print_welcome_message()

    parser = argparse.ArgumentParser(description="TailTrace - Network Traffic Analyzer.")
    parser.add_argument("-c", "--capture", help="Capture network traffic without analysis.", action="store_true")
    parser.add_argument("-a", "--analyze", help="Capture and analyze network traffic for anomalies.", action="store_true")
    parser.add_argument("-o", "--only-external", help="Analyze or capture traffic excluding own packets.", action="store_true")
    args = parser.parse_args()

    if args.capture:
        capture_traffic(analyze=False)
    elif args.analyze:
        capture_traffic(analyze=True)
    else:
        logging.error("Please choose either capture (-c) or analyze (-a) mode.")

if __name__ == "__main__":
    main()
