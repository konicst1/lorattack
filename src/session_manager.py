import os
import json
from enum import Enum, auto
from typing import Dict, Any
from src.command_handler import CommandHandler


class SessionParams(Enum):
    AppKey = auto()
    NwkKey = auto()
    JoinRequest_DevEUI = auto()
    JoinRequest_AppEUI = auto()
    JoinRequest_JoinEUI = auto()
    JoinRequest_DevNonce = auto()
    JoinAccept_AppNonce = auto()
    JoinAccept_JoinNonce = auto()
    JoinAccept_NetID = auto()
    JoinAccept_DevAddr = auto()
    AppSKey = auto()
    NwkSKey = auto()
    NwkSEncKey = auto()
    SNwkSIntKey = auto()
    FNwkSIntKey = auto()


class SessionManager(CommandHandler):
    def __init__(self):
        """Initializes the SessionManager instance.
        Creates the sessions directory if it doesn't exist.
        """
        self.sessions_dir = 'session/data'
        self.current_session_file = 'session/current_session'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)

    def get_current_session_name(self):
        """Retrieves the name of the currently active session.

        Loads the current session data and returns the session name.

        Returns:
          str: The name of the currently active session, or None if no session is active.
        """
        name, data = self.load_current_session()
        return name

    def create_session(self, session_name: str):
        """Creates a new LoRaWAN session with the specified name.

        Initializes a new session directory with a data.json file to store session parameters.

        Args:
          session_name (str): The name to assign to the new session.
        """
        session_data = {param.name: None for param in SessionParams}
        session_dir = os.path.join(self.sessions_dir, session_name)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data, f, indent=4)
        with open(self.current_session_file, 'w') as f:
            f.write(session_name)

    def activate_session(self, name):
        """Activates the specified session as the current session.

        Updates the current_session_file to reflect the newly active session.

        Args:
          name (str): The name of the session to activate.
        """
        with open(self.current_session_file, 'w') as f:
            f.write(name)

    def load_current_session(self):
        """Loads data from the currently active session.

        Reads the session name and data from the corresponding files.

        Returns:
          tuple: A tuple containing the session name (str) and a dictionary of session data.
        """
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'r') as f:
            session_data_str = json.load(f)
        session_data = {SessionParams[k]: v for k, v in session_data_str.items()}
        return current_session_name, session_data

    def update_session_value(self, param: SessionParams, value: Any):
        """Updates the specified session parameter with the provided value.

        Loads the current session data, updates the specified parameter, and saves the data back to the session file.

        Args:
          param (SessionParams): The session parameter to update.
          value (Any): The new value to assign to the parameter.
        """
        name, session_data = self.load_current_session()
        session_data[param] = value
        self.save_session_data(session_data)

    def get_session_value(self, param: SessionParams):
        """Retrieves the value of the specified session parameter.

        Loads the current session data and returns the value associated with the given parameter. If the parameter is not set, it returns None.

        Args:
          param (SessionParams): The session parameter to retrieve the value for.

        Returns:
          Any: The value of the parameter in the current session, or None if the parameter is not set.
        """
        _, session_data = self.load_current_session()
        return session_data.get(param, None)

    def save_session_data(self, session_data):
        """Saves the provided session data to the current session file.

        Serializes the session data dictionary to JSON format and writes it to the data.json file in the current session directory.

        Args:
          session_data (dict): A dictionary containing the session parameters and their values.
        """
        session_data_str = {k.name: v for k, v in session_data.items()}
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data_str, f, indent=4)

    def manage_sequence_file(self):
        """Opens the sequence file for editing in the default text editor.

        If the sequence file doesn't exist, it creates an empty file.

        Raises:
          FileNotFoundError: If the default text editor cannot be found.
        """
        current_session_name, _ = self.load_current_session()
        sequence_file_path = os.path.join(self.sessions_dir, current_session_name, 'sequence')
        if not os.path.exists(sequence_file_path):
            with open(sequence_file_path, 'w') as f:
                f.write('')
        command = ['gedit', sequence_file_path]
        self.execute_command(command)

    def read_sequence_file(self):
        """Reads the contents of the sequence file for the current session.

         Attempts to parse the contents of the sequence file as comma-separated integers.

         Returns:
           list[int]: A list of integers parsed from the sequence file, or an empty list if the file is missing or contains invalid data.

         Raises:
           FileNotFoundError: If the sequence file is not found.
           ValueError: If the sequence file contains non-integer values.
         """
        current_session_name, _ = self.load_current_session()
        sequence_file_path = os.path.join(self.sessions_dir, current_session_name, 'sequence')

        try:
            with open(sequence_file_path, 'r') as file:
                contents = file.read().strip()
                # Split the string by commas and convert each part to an integer
                return [int(num) for num in contents.split(',') if num.strip().isdigit()]
        except FileNotFoundError:
            print(f"No sequence file found in the session directory: {sequence_file_path}")
            return []
        except ValueError:
            print("Error processing the sequence file. Ensure the file contains only integers separated by commas.")
            return []

    def list_sessions(self):
        """Returns a list of available session names.

        Scans the sessions directory and returns a list of subdirectory names, which represent the available sessions.

        Returns:
          list[str]: A list of session names (subdirectory names within the sessions_dir).
        """
        return [d for d in os.listdir(self.sessions_dir) if os.path.isdir(os.path.join(self.sessions_dir, d))]

    def list_pcap_files(self):
        """Returns a list of PCAP files in the current session directory.

        Retrieves the name of the current session and searches for files with the .pcap extension (excluding 'wireshark' prefixed files).

        Returns:
          list[str]: A list of PCAP file names found in the current session directory, or an empty list if no PCAP files are found.
        """
        _, session_data = self.load_current_session()
        current_session_name, _ = self.load_current_session()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        pcap_files = [f for f in os.listdir(session_dir) if f.endswith('.pcap') and not f.startswith('wireshark')]
        return pcap_files


if __name__ == "__main__":
    sm = SessionManager()
    s = sm.list_sessions()
    sm.create_session('1131')
    sm.update_session_value(SessionParams.JoinAccept_NetID, 'bleeeee')
    print(s)
