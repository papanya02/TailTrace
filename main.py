from collections import defaultdict
import argparse
import subprocess
import sys
import logging
from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr, IP, TCP, UDP

IP_REQUEST_THRESHOLD = 100
PORT_REQUEST_THRESHOLD = 50

ip_activity = defaultdict(int)
port_activity = defaultdict(int)

def install_package(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError:
        logging.error(f"Failed to install package {package}")
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
    """Checking the package for anomalies."""
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

def packet_callback(packet, analyze=False):
    """Callback function to process each captured packet."""
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

    packet_info = f"Source: {ip_src} | Destination: {ip_dst} | Src Port: {src_port} | Dst Port: {dst_port}"
    print(packet_info)

    if analyze:
        detect_anomalies(packet)

def capture_traffic(analyze=False):
    """Capture network traffic from a specified interface."""
    interfaces = get_if_list()
    if not interfaces:
        print("No network interfaces found.")
        sys.exit(1)

    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        try:
            ip_addr = get_if_addr(iface)
            if ip_addr == "0.0.0.0":
                ip_addr = "No IP assigned"
            print(f"{idx}. {iface} ({ip_addr})")
        except Exception as e:
            logging.warning(f"Could not get IP for interface {iface}: {e}")

    try:
        selected_idx = int(input("Select an interface by number: ")) - 1
        if selected_idx < 0 or selected_idx >= len(interfaces):
            raise ValueError("Invalid selection.")
        interface = interfaces[selected_idx]
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        sys.exit(1)

    print(f"Capturing traffic on interface {interface}...")
    try:
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, analyze), store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

def main():
    print_welcome_message()

    parser = argparse.ArgumentParser(description="TailTrace - Network Traffic Analyzer.")
    parser.add_argument("-c", "--capture", help="Capture network traffic without analysis.", action="store_true")
    parser.add_argument("-a", "--analyze", help="Capture and analyze network traffic for anomalies.", action="store_true")
    args = parser.parse_args()

    if args.capture:
        capture_traffic(analyze=False)
    elif args.analyze:
        capture_traffic(analyze=True)
    else:
        logging.error("Please choose either capture (-c) or analyze (-a) mode.")

if __name__ == "__main__":
    main()

