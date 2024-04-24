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
    """Analyzer class for processing LoRaWAN data..

    This class provides functionalities to extract LoRaWAN messages from PCAP files and potentially perform further analysis on the captured data.
    """

    def __init__(self):
        self.packets = []
        self.stop_event = Event()
        self.session_manager = SessionManager()
        self.crypto_tool = CryptoTool()

    def analyze_pcap(self, file_path):

        """Analyzes a LoRaWAN PCAP file for LoRaWAN messages and performs basic analysis.

        This function reads a PCAP file containing captured network traffic and extracts packets containing LoRaWAN messages. It iterates through each packet, printing a summary and attempting to decode it using the LoRa layer. Decoded LoRaWAN messages are analyzed based on their message type (Join Request, Join Accept, etc.). If session keys are available in the `SessionManager`, the function attempts to decrypt the payload of uplink messages.

        Args:
            file_path (str): The path to the PCAP file containing LoRaWAN messages.

        Returns:
            None
        """
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

    def get_packet_sequence_from_pcap(self, path):
        """Extracts a sequence of LoRaWAN packets from a PCAP file.

         Parses the provided PCAP file and extracts packets containing LoRaWAN messages. It returns a list of the extracted LoRaWAN message payloads in hexadecimal format.

         Args:
             pcap_path (str): The path to the PCAP file containing LoRaWAN messages.

         Returns:
             list[str]: A list of LoRaWAN message payloads extracted from the PCAP file, or an empty list if no LoRaWAN messages are found.

         Raises:
             ValueError: If the PCAP file cannot be opened or processed.
         """
        packets = rdpcap(path)
        indexes = self.session_manager.read_sequence_file()
        payloads = []
        for i in indexes:
            payloads.append(packets[i][UDP].load.hex())

        return payloads

    def analyze_lora_packet(self, packet, raw_packet):
        """Analyzes a decoded LoRaWAN message based on its message type.

        This function takes a decoded LoRaWAN message object and the raw packet containing the message. It analyzes the message type (Join Request, Join Accept, etc.) and performs actions based on the type:

        - For Join Request messages, it updates session parameters in the `SessionManager` with extracted values.
        - For Join Accept messages, it attempts to decrypt the message if the AppKey is available. If successful, it derives session keys and updates the `SessionManager` with them.
        - For uplink data messages (confirmed or unconfirmed), it attempts to decrypt the payload if the AppSKey is available. The decrypted payload is printed in hexadecimal and ASCII format.

        Args:
            packet (LoRa): The decoded LoRaWAN message object.
            raw_packet (Packet): The raw packet containing the LoRaWAN message.

        Returns:
            None
        """
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
                decrypted_join_accept = CryptoTool.decrypt_join_accept(raw_packet[UDP].load, bytes(
                    self.session_manager.get_session_value(SessionParams.AppKey)))
                decoded_join_accept = LoRa(decrypted_join_accept)
                print('Successfuly decrypted Join Accept messages')
                print('Computing session keys')
                self.session_manager.update_session_value(SessionParams.JoinAccept_AppNonce,
                                                          format(decoded_join_accept.Join_Accept_Field[0].JoinAppNonce,
                                                                 '02x'))
                self.session_manager.update_session_value(SessionParams.JoinAccept_JoinNonce,
                                                          format(decoded_join_accept.Join_Accept_Field[0].JoinAppNonce,
                                                                 '02x'))
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
                pt = self.crypto_tool.FRMPayload_decrypt(packet.ULDataPayload.hex(), packet.FCnt, session_key,
                                                         self.session_manager.get_session_value(
                                                             SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.confirmed_data_up.bit_value:
            print('Found Confirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.ULDataPayload.hex(), packet.FCnt, session_key,
                                                         self.session_manager.get_session_value(
                                                             SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.unconfirmed_data_down.bit_value:
            print('Found Unconfirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.DLDataPayload.hex(), packet.FCnt, session_key,
                                                         self.session_manager.get_session_value(
                                                             SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))
        elif packet.MType == MTypesEnum.confirmed_data_down.bit_value:
            print('Found Confirmed Data Up')
            if self.session_manager.get_session_value(SessionParams.AppSKey) is not None:
                print('Decrypting payload')
                session_key = self.session_manager.get_session_value(SessionParams.AppSKey)
                pt = self.crypto_tool.FRMPayload_decrypt(packet.DLDataPayload.hex(), packet.FCnt, session_key,
                                                         self.session_manager.get_session_value(
                                                             SessionParams.JoinAccept_DevAddr), 0)
                print(bytes(pt).hex(), bytes(pt).decode('iso-8859-1'))

    def packet_callback(self, packet):
        """Callback function for live sniffing of packets.

        This function is called for each captured packet during live sniffing with `sniff`. It checks if the packet is a UDP packet with the LoRaWAN port (40868) and attempts to:

        - Append the packet to the internal list (`packets`).
        - Decode the LoRaWAN message within the packet.
        - Analyze the decoded message using `analyze_lora_packet`.

        If the decoding fails, a message is printed.

        Args:
            packet (Packet): The captured network packet.

        Returns:
            None
        """
        if packet.haslayer(UDP) and packet[UDP].dport == 40868:
            try:
                self.packets.append(packet)
                decoded = LoRa(packet[UDP].load)
                print(repr(decoded))
                self.analyze_lora_packet(decoded, packet)
            except:
                print("Packet could not be decoded")

    def stop_filter_func(self, packet):
        """Filter function used during live sniffing to stop capturing packets.

        This function is used as a filter with `sniff` during live sniffing. It simply checks if the `stop_event` flag is set, indicating the user wants to stop capturing packets.

        Args:
            packet (Packet): The captured network packet (ignored).

        Returns:
            bool: True if the `stop_event` is set, False otherwise.
        """
        return self.stop_event.is_set()

    def live_sniffing(self):
        """Starts live sniffing for LoRaWAN packets on the loopback interface.

        This function starts capturing packets on the loopback interface (lo) using `sniff` and the `packet_callback` function. Once capturing is stopped (using `stop_event`), it stores the captured packets to a PCAP file and optionally converts it to a Wireshark-readable format using the `bittwiste` tool.

        Returns:
            None
        """
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
        """Sets a flag to stop live sniffing.

        This function sets the `stop_event` flag, which is used by the `stop_filter_func` to terminate live sniffing with `sniff`.

        Returns: None

        self.stop_event.set()
        """


if __name__ == "__main__":
    a = Analyzer()
    a.analyze_pcap(pcap_file)
