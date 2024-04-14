from scapy.all import rdpcap, sniff, wrpcap, hexdump
from threading import Event
from layer.lorawan_phy import LoRa, MTypesEnum
from scapy.layers.inet import *

from src.crypto_tools import CryptoTool
from src.command_handler import CommandHandler
from src.session_manager import SessionManager, SessionParams
from datetime import datetime

pcap_file = "/home/pentester/lorattack/session/data/clean/2024-04-14_14-03-10.pcap"


class Analyzer(CommandHandler):

    def __init__(self):
        self.packets = []
        self.stop_event = Event()
        self.session_manager = SessionManager()
        self.crypto_tool = CryptoTool()

    def analyze_pcap(self, file_path):
        packets = rdpcap(file_path)

        print(f"Total packets in pcap: {len(packets)}")

        # Iterate through each packet and print a summary
        for packet in packets:
            print(packet.summary())

            if packet.haslayer(UDP):
                try:
                    decoded = LoRa(packet[UDP].load)
                    self.analyze_lora_packet(decoded, packet)

                    print(repr(decoded))
                except:
                    print("Packet could not be decoded")

    def analyze_lora_packet(self, packet, raw_packet):
        if packet.MType == MTypesEnum.join_request.bit_value:
            print('Found Join Request')
            self.session_manager.update_session_value(SessionParams.JoinRequest_AppEUI,
                                                      packet.Join_Request_Field[0].AppEUI.hex())
            self.session_manager.update_session_value(SessionParams.JoinRequest_DevEUI,
                                                      packet.Join_Request_Field[0].DevEUI.hex())
            self.session_manager.update_session_value(SessionParams.JoinRequest_JoinEUI,
                                                      packet.Join_Request_Field[0].AppEUI.hex())
            self.session_manager.update_session_value(SessionParams.JoinRequest_DevNonce,
                                                      format(packet.Join_Request_Field[0].DevNonce, '02x'))
        elif packet.MType == MTypesEnum.join_accept.bit_value:
            print('Found Join Accept')
            if self.session_manager.get_session_value(SessionParams.AppKey) is not None:
                decrypted_join_accept = CryptoTool.decrypt_join_accept(packet[UDP].load, bytes(
                    self.session_manager.get_session_value(SessionParams.AppKey)))
                decoded_join_accept = LoRa(decrypted_join_accept)
                print('Successfuly decrypted Join Accept messages')
                print('Computing session keys')
                self.session_manager.update_session_value(SessionParams.JoinAccept_AppNonce,
                                                          format(decoded_join_accept.Join_Accept_Field[0].JoinAppNonce, '02x'))
                self.session_manager.update_session_value(SessionParams.JoinAccept_JoinNonce,
                                                          format(decoded_join_accept.Join_Accept_Field[0].JoinAppNonce, '02x'))
                self.session_manager.update_session_value(SessionParams.JoinAccept_DevAddr,
                                                          decoded_join_accept.Join_Request_Field[0].DevAddr.hex())
                self.session_manager.update_session_value(SessionParams.JoinAccept_NetID,
                                                          decoded_join_accept.Join_Request_Field[0].NetID.hex())

                nwk_skey, app_skey, FNwkSIntKey, SNwkSIntKey, NwkSEncKey = CryptoTool.derive_session_keys(
                    self.session_manager.get_session_value(SessionParams.AppKey),
                    self.session_manager.get_session_value(SessionParams.NwkKey),
                    self.session_manager.get_session_value(SessionParams.JoinRequest_JoinEUI),
                    self.session_manager.get_session_value(SessionParams.JoinAccept_AppNonce),
                    self.session_manager.get_session_value(SessionParams.JoinAccept_NetID),
                    self.session_manager.get_session_value(SessionParams.JoinRequest_DevNonce))

                self.session_manager.update_session_value(SessionParams.NwkSKey, nwk_skey)
                self.session_manager.update_session_value(SessionParams.AppSKey, app_skey)
                self.session_manager.update_session_value(SessionParams.FNwkSIntKey, FNwkSIntKey)
                self.session_manager.update_session_value(SessionParams.SNwkSIntKey, SNwkSIntKey)
                self.session_manager.update_session_value(SessionParams.NwkSEncKey, NwkSEncKey)
        elif packet.MType == MTypesEnum.unconfirmed_data_up.bit_value:
            print('Found Unconfirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.ULDataPayload.hex(), packet.FCnt, session_key, self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.confirmed_data_up.bit_value:
            print('Found Confirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.ULDataPayload.hex(), packet.FCnt, session_key, self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.unconfirmed_data_down.bit_value:
            print('Found Unconfirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.DLDataPayload.hex(), packet.FCnt, session_key, self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.confirmed_data_down.bit_value:
            print('Found Confirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.DLDataPayload.hex(), packet.FCnt, session_key, self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))


    def packet_callback(self, packet):
        if packet.haslayer(UDP) and packet[UDP].dport == 40868:
            try:
                self.packets.append(packet)
                decoded = LoRa(packet[UDP].load)
                print(repr(decoded))
                self.analyze_lora_packet(decoded, packet)
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
        path = self.session_manager.sessions_dir + '/' + self.session_manager.get_current_session_name() + '/'
        wrpcap(path + filename, self.packets)
        print(f"Saved {len(self.packets)} packets to {filename}")
        command = ['bittwiste', '-I', path + filename, '-O', path + 'wireshark_' + filename, '-M', '147', '-D', '1-42']
        self.execute_command(command)

    def terminate_sniffer(self):
        self.stop_event.set()


if __name__ == "__main__":
    a = Analyzer()
    a.analyze_pcap(pcap_file)
