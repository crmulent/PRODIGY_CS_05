from scapy.all import *
from tabulate import tabulate

output_data = []

def packet_sniff(packet):
    global header_printed, output_data
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        payload = str(packet[TCP].payload)[:50] + "..." if len(str(packet[TCP].payload)) > 50 else str(packet[TCP].payload)

        output_data.append([src_ip, dst_ip, src_port, dst_port, protocol, payload])

        print(tabulate(output_data))


def main():
    output_path = "packet_sniffer_results.txt"

    try:
        headers = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Payload"]

        sniff(filter="tcp", prn=packet_sniff, store=0)

    except KeyboardInterrupt:
        pass

    with open(output_path, 'w') as f:
        f.write(tabulate(output_data, headers=headers, tablefmt="plain"))

    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()