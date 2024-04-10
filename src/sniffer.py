import json

from src.command_handler import CommandHandler

class Sniffer(CommandHandler):
    def sniff_traffic(self):
        script_path = './sniffers/sniffer_bidirectional.py'
        with open('./config/sniffer.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate', sample_rate, '--spreading_factor', spreading_factor]
        self.execute_command(command)
