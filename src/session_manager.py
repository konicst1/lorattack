import os
import json
from enum import Enum, auto
from typing import Dict, Any
from datetime import datetime


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


class SessionManager:
    def __init__(self):
        self.sessions_dir = 'session/data'
        self.current_session_file = 'session/current_session'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)

    def get_current_session_name(self):
        name, data = self.load_current_session()
        return name

    def create_session(self, session_name: str):
        session_data = {param.name: None for param in SessionParams}
        session_dir = os.path.join(self.sessions_dir, session_name)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data, f, indent=4)
        with open(self.current_session_file, 'w') as f:
            f.write(session_name)

    def activate_session(self, name):
        with open(self.current_session_file, 'w') as f:
            f.write(name)

    def load_current_session(self):
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'r') as f:
            session_data_str = json.load(f)
        session_data = {SessionParams[k]: v for k, v in session_data_str.items()}
        return current_session_name, session_data

    def update_session_value(self, param: SessionParams, value: Any):
        name, session_data = self.load_current_session()
        session_data[param] = value
        self.save_session_data(session_data)

    def get_session_value(self, param: SessionParams):
        _, session_data = self.load_current_session()
        return session_data.get(param, None)

    def save_session_data(self, session_data):
        session_data_str = {k.name: v for k, v in session_data.items()}
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data_str, f, indent=4)

    def list_sessions(self):
        return [d for d in os.listdir(self.sessions_dir) if os.path.isdir(os.path.join(self.sessions_dir, d))]

    def list_pcap_files(self):
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
