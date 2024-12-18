
import argparse
import scapy.all as scapy
import time

def sniffer(target):
    print(f"Monitoring network activity for {target}...")
    while True:
        # Тут буде ваш код для моніторингу пакунків
        # Наприклад, перехоплення пакунків для конкретної IP-адреси
        packets = scapy.sniff(count=10, filter=f"host {target}")
        for packet in packets:
            print(packet.summary())
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="TailTrace - Network Activity Monitoring")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target IP or URL")
    args = parser.parse_args()
    
    sniffer(args.target)

if __name__ == "__main__":
    main()
