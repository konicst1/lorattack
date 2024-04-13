import json

import threading
from src.command_handler import CommandHandler
from src.analyzer import Analyzer


class Sniffer(CommandHandler):

    def __init__(self):
        self.bisniff = './sniffers/sniffer_bidirectional.py'
        self.upsniff = './sniffers/sniffer_uplink.py'
        self.downsniff = './sniffers/sniffer_downlink.py'


    def sniff_traffic(self, script_path):
        #script_path = './sniffers/sniffer_bidirectional.py'
        with open('./config/sniffer.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        gain = str(parameters['gain_db'])

        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate', sample_rate, '--spreading-factor', spreading_factor, '--gain-db', gain]
        self.execute_command(command)


    def run_sniffer_thread(self, direction):
        sniffer_thread = threading.Thread(target=self.sniff_traffic, args=(direction,))
        sniffer_thread.start()
        analyzer = Analyzer()
        analyzer_thread = threading.Thread(target=analyzer.live_sniffing)
        analyzer_thread.start()
        sniffer_thread.join()
        print('Killing analyzer thread')
        analyzer.terminate_sniffer()
        analyzer_thread.join()
        print('Killed analyzer thread')


    def configure_sniffer(self):
        config_path = './config/sniffer.config'
        command = ['gedit', config_path]
        self.execute_command(command)
