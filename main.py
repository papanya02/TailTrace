import argparse
import socket
import subprocess
import sys
import logging
from scapy.all import sniff, get_if_list, get_if_hwaddr, get_if_addr, IP, TCP, UDP

def install_package(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError:
        logging.error(f"Failed to install package {package}")
        sys.exit(1)

try:
    from scapy.all import sniff
except ImportError:
    logging.info("Scapy is not installed. Installing...")
    install_package("scapy")
    from scapy.all import sniff

def print_welcome_message():
    welcome_message = """
   
       █████████████████████████████████████████████████████████████████████
      |         ,     ,                                            ,  ,     |
      |        /(     )\\         Welcome to TailTrace!            (\\ _ )_  |
      |       (  \\___/  )       The Purr-fect Network Tool!       ( _'_)    |
      |       (   >  <   )                                       (        ) |
      |        \\_________/                                        '-------'  |
      |         /       \\                                                    |
      |        (         )           Cat powered analysis engine             |
      |         \\_______/                                                    |
      █████████████████████████████████████████████████████████████████████
    
    **************************************************************
    * TailTrace v1.0.0                                            *
    * License: MIT                                               *
    * Author: Andriy Tyshkevych                                  *
    * Description: A network traffic analyzer and capture tool. *
    **************************************************************
    """

    print(welcome_message)

print_welcome_message()



def packet_callback(packet):
    """Callback function to process each captured packet."""
    
    proto_info = f"Protocol: {packet.proto}" if hasattr(packet, "proto") else "Protocol: Unknown"
    
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

    packet_info = f"Source: {ip_src} | Destination: {ip_dst} | Protocol: {proto_info} | Src Port: {src_port} | Dst Port: {dst_port}"
    print(packet_info)

def capture_traffic(interface=None):
    """Capture network traffic from a specified interface."""
    if not interface:
        interfaces = get_if_list()
        if not interfaces:
            print("No network interfaces found.")
            sys.exit(1)

        print("Available network interfaces:")
        interface_names = {}
        for idx, iface in enumerate(interfaces, 1):
          try:
                iface_name = get_if_addr(iface) or get_if_hwaddr(iface)
                interface_names[idx] = (iface, iface_name)
                print(f"{idx}. {iface_name} ({iface})")
          except Exception as e:
                logging.warning(f"Could not get name for interface {iface}: {e}")
        
        try:
            selected_idx = int(input("Select an interface by number: ")) - 1
            if selected_idx < 0 or selected_idx >= len(interface_names):
                raise ValueError("Invalid selection.")
            interface, iface_name = interface_names[selected_idx + 1]
        except (ValueError, IndexError):
            print("Invalid selection. Exiting.")
            sys.exit(1)

    print(f"Capturing traffic on interface {iface_name} ({interface})...")

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

def analyze_traffic(target: str):
    """Analyze the traffic to/from a specified target domain."""
    try:
        print(f"Connecting to {target}...")
        ip = socket.gethostbyname(target)
        print(f"IP address of {target}: {ip}")
        print("Analysis complete.")
    except socket.gaierror:
        logging.error(f"Unable to resolve {target}")
    except Exception as e:
        logging.error(f"Error: {e}")

def main():
    print_welcome_message()  

    parser = argparse.ArgumentParser(description="TailTrace - Network Traffic Analyzer.")
    parser.add_argument("-t", "--target", help="Target domain for traffic analysis.", required=False)
    parser.add_argument("-c", "--capture", help="Capture network traffic.", action="store_true")
    parser.add_argument("-i", "--interface", help="Specify network interface (e.g., eth0, Wi-Fi).", required=False)
    args = parser.parse_args()

    if args.capture:
       
        capture_traffic(interface=args.interface)
    elif args.target:
       
        analyze_traffic(args.target)
    else:
        logging.error("Please specify a target for analysis or choose the capture option.")

if __name__ == "__main__":
    main()
