import json

import threading
from src.command_handler import CommandHandler
from src.analyzer import Analyzer

class Sniffer(CommandHandler):


    def sniff_traffic(self):
        script_path = './sniffers/sniffer_bidirectional.py'
        with open('./config/sniffer.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])

        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate', sample_rate, '--spreading-factor', spreading_factor]
        self.execute_command(command)


    def run_sniffer_thread(self, direction='bidirectional'):
        thread = threading.Thread(target=self.sniff_traffic)
        thread.start()
        analyzer = Analyzer()
        analyzer.live_sniffing()
        thread.join()


    def configure_sniffer(self):
        config_path = './config/sniffer.config'
        command = ['gedit', config_path]
        self.execute_command(command)
