from src.command_handler import CommandHandler

class Sniffer(CommandHandler):
    def sniff_traffic(self):
        script_path = './sniffers/sniffer_bidirectional.py'
        # with open('./config/kr00k_attack.config', 'r') as file:
        #     parameters = json.load(file)
        # bssid = parameters['bssid']
        # client_mac = parameters['mac_client']
        # num_packets = str(parameters['num_packets'])
        # reason_id = str(parameters['reason_id'])
        # wifi_channel = str(parameters['wifi_channel'])
        # delay = str(parameters['delay'])

        command = ['python3', script_path]
        self.execute_command(command)
