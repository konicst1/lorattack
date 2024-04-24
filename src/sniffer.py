import json

import threading
from src.command_handler import CommandHandler
from src.analyzer import Analyzer


class Sniffer(CommandHandler):
    """Sniffer class for capturing LoRaWAN traffic.

    This class provides functionalities to capture LoRaWAN traffic using external sniffer scripts and analyze the captured data using the Analyzer class. It supports bidirectional, uplink-only, and downlink-only sniffing configurations.
    """

    def __init__(self):
        """Initializes the Sniffer instance.

         Sets the paths to the sniffer scripts for bidirectional, uplink, and downlink sniffing.
         """
        self.bisniff = './sniffers/sniffer_bidirectional.py'
        self.upsniff = './sniffers/sniffer_uplink.py'
        self.downsniff = './sniffers/sniffer_downlink.py'

    def sniff_traffic(self, script_path):
        """Starts a sniffer script to capture LoRaWAN traffic.

        This function takes the path to a sniffer script (bidirectional, uplink, or downlink) and executes it with the specified parameters loaded from the sniffer configuration file.

        Args:
            script_path (str): The path to the sniffer script to execute.

        Returns:
            None
        """
        # script_path = './sniffers/sniffer_bidirectional.py'
        with open('./config/sniffer.config', 'r') as file:
            parameters = json.load(file)
        sample_rate = parameters['sample_rate']
        bandwidth = parameters['bandwidth']
        frequency = str(parameters['frequency'])
        spreading_factor = str(parameters['spreading_factor'])
        gain = str(parameters['gain_db'])

        command = ['python3', script_path, '--frequency', frequency, '--bandwidth', bandwidth, '--samp-rate',
                   sample_rate, '--spreading-factor', spreading_factor, '--gain-db', gain]
        self.execute_command(command)

    def run_sniffer_thread(self, direction):
        """Starts a sniffer thread and an analyzer thread to capture and analyze traffic.

        This function takes a direction (bidirectional, uplink, or downlink) and starts a sniffer thread using the appropriate script. It then starts a separate thread to run the Analyzer class for live sniffing. The sniffer thread is terminated after capturing is complete, and the analyzer thread is stopped gracefully.

        Args:
            direction (str): The direction of traffic to capture (e.g., "bidirectional", "uplink", "downlink").

        Returns:
            None
        """
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
        """Opens the sniffer configuration file for editing using the default text editor.

        This function allows users to modify the sniffer configuration parameters (e.g., sample rate, frequency) via a text editor.

        Raises:
            FileNotFoundError: If the default text editor cannot be found.
        """

        config_path = './config/sniffer.config'
        command = ['gedit', config_path]
        self.execute_command(command)
