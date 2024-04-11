from scapy.all import rdpcap, sniff, wrpcap

from layer.lorawan_phy import LoRa
from scapy.layers.inet import *
from src.command_handler import CommandHandler

# Load the pcap file
pcap_file = "/home/pentester/Documents/gnuradio/pcaps/PHYcap.pcap"


class Analyzer(CommandHandler):

    def __init__(self):
        self.packets = []
    def analyze_pcap(self, file_path):
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

    def packet_callback(self, packet):
        self.packets.append(packet)
        if packet.haslayer(UDP):
            try:
                decoded = LoRa(packet[UDP].load)
                print(repr(decoded))
            except:
                print("Packet could not be decoded")

    def live_sniffing(self):
        packets=[]
        sniff(filter="udp port 40868", prn=self.packet_callback)
