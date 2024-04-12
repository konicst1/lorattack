from scapy.all import rdpcap, sniff, wrpcap, hexdump
from threading import Event
from layer.lorawan_phy import LoRa, MTypesEnum
from scapy.layers.inet import *

from src.command_handler import CommandHandler
from src.session_manager import SessionManager, SessionParams
from datetime import datetime

# Load the pcap file
pcap_file = "/home/pentester/Documents/gnuradio/pcaps/PHYcap.pcap"


class Analyzer(CommandHandler):

    def __init__(self):
        self.packets = []
        self.stop_event = Event()
        self.session_manager = SessionManager()
    def analyze_pcap(self, file_path):
        packets = rdpcap(file_path)

        print(f"Total packets in pcap: {len(packets)}")

        # Iterate through each packet and print a summary
        for packet in packets:
            print(packet.summary())

            if packet.haslayer(UDP):
                try:
                    decoded = LoRa(packet[UDP].load)
                    if decoded.MType == MTypesEnum.join_request.bit_value:
                        print('Found Join Request')
                        print(decoded.Join_Request_Field[0].AppEUI.hex())
                        self.session_manager.update_session_value(SessionParams.JoinRequest)

                    print(repr(decoded))
                except:
                    print("Packet could not be decoded")

    def packet_callback(self, packet):

        print('got packet')
        if packet.haslayer(UDP) and packet[UDP].dport == 40868:
            try:
                self.packets.append(packet)
                decoded = LoRa(packet[UDP].load)
                print(repr(decoded))
            except:
                print("Packet could not be decoded")

    def stop_filter_func(self, packet):
        return self.stop_event.is_set()


    def live_sniffing(self):
        print('sniffing...')
        sniff(iface="lo", prn=self.packet_callback, stop_filter=self.stop_filter_func)
        print('Storing pcap to file')
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{current_time}.pcap"
        path = self.session_manager.sessions_dir + '/'+ self.session_manager.get_current_session_name() + '/'
        wrpcap(path + filename, self.packets)
        print(f"Saved {len(self.packets)} packets to {filename}")
        command = ['bittwiste', '-I', path + filename , '-O', path + 'edited_' + filename, '-M', '147', '-D', '1-42']
        self.execute_command(command)

    def terminate_sniffer(self):
        self.stop_event.set()


if __name__ == "__main__":
    a = Analyzer()
    a.analyze_pcap(pcap_file)
