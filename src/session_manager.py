import os
import json
from enum import Enum, auto
from typing import Dict, Any


class SessionParams(Enum):
    AppKey = auto()
    JoinRequest = auto()
    JoinAccept = auto()
    AppSKey = auto()
    NwkSKey = auto()
    NwkSEncKey = auto()
    SNwkSIntKey = auto()
    FNwkSIntKey = auto()
    DevAddr = auto()


class SessionManager:
    def __init__(self):
        self.sessions_dir = 'session/data'
        self.current_session_file = 'session/current_session'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)

    def create_session(self, session_name: str):
        session_data = {
            SessionParams.AppKey: "Your_App_Key_Value",
            SessionParams.JoinRequest: {
                "DevEUI": "Your_DevEUI_Value",
                "AppEUI": "Your_AppEUI_Value",
                "JoinEUI": "Your_JoinEUI_Value",
                "DevNonce": "Your_DevNonce_Value"
            },
            SessionParams.JoinAccept: {
                "AppNonce": "Your_AppNonce_Value",
                "JoinNonce": "Your_JoinNonce_Value",
                "NetID": "Your_NetID_Value",
                "DevAddr": "Your_DevAddr_Value_in_JoinAccept"
            },
            SessionParams.AppSKey: "Your_AppSKey_Value",
            SessionParams.NwkSKey: "Your_NwkSKey_Value",
            SessionParams.NwkSEncKey: "Your_NwkSEncKey_Value",
            SessionParams.SNwkSIntKey: "Your_SNwkSIntKey_Value",
            SessionParams.FNwkSIntKey: "Your_FNwkSIntKey_Value",
            SessionParams.DevAddr: "Your_DevAddr_Value"
        }
        session_dir = os.path.join(self.sessions_dir, session_name)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)

        # Convert ENUMs to strings for JSON storage
        session_data_str = {k.name: v for k, v in session_data.items()}

        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data_str, f)

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

        # Convert strings back to ENUMs
        session_data = {SessionParams[k]: v for k, v in session_data_str.items()}
        return current_session_name, session_data

    def update_session_value(self, param: SessionParams, value: Any):
        # Load the current session data
        _, session_data = self.load_current_session()
        # Update the value for the given parameter
        session_data[param] = value
        # Save the updated session data
        self.save_session_data(session_data)

    def get_session_value(self, param: SessionParams):
        _, session_data = self.load_current_session()
        return session_data.get(param, None)

    def save_session_data(self, session_data: Dict[SessionParams, Any]):
        session_data_str = {k.name: v for k, v in session_data.items()}
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()
        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data_str, f)

    def list_sessions(self):
        return [d for d in os.listdir(self.sessions_dir) if os.path.isdir(os.path.join(self.sessions_dir, d))]

if __name__ == "__main__":
    sm = SessionManager()
    s= sm.list_sessions()
    print(s)
