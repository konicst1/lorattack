from scapy.all import rdpcap, hexdump

from layer.lorawan_phy import LoRa
from scapy.layers.inet import *


# Load the pcap file
pcap_file = "/home/pentester/Documents/gnuradio/pcaps/PHYcap.pcap"


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    print(f"Total packets in pcap: {len(packets)}")

    # Iterate through each packet and print a summary
    for packet in packets:
        print(packet.summary())

        if packet.haslayer(UDP):
            try:
                decoded = LoRa(packet[UDP].load)
                print(repr(decoded))
            except:
                print("Packet could not be decoded")

if __name__ == "__main__":
    analyze_pcap(pcap_file)
