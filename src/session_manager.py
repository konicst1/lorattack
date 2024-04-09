import os
import json
from enum import Enum, auto
from typing import Dict


class SessionParams(Enum):
    APP_KEY = auto()
    NWK_KEY = auto()
    # Add other parameters here as needed


class SessionManager:
    def __init__(self):
        self.sessions_dir = 'session/data'
        self.current_session_file = 'session/current_session'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)

    def create_session(self, session_name: str, session_data: Dict[SessionParams, str]):
        session_dir = os.path.join(self.sessions_dir, session_name)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)

        # Convert ENUMs to strings for JSON storage
        session_data_str = {k.name: v for k, v in session_data.items()}

        with open(os.path.join(session_dir, 'data.json'), 'w') as f:
            json.dump(session_data_str, f)

        with open(self.current_session_file, 'w') as f:
            f.write(session_name)

    def load_current_session(self):
        with open(self.current_session_file, 'r') as f:
            current_session_name = f.read().strip()

        session_dir = os.path.join(self.sessions_dir, current_session_name)
        with open(os.path.join(session_dir, 'data.json'), 'r') as f:
            session_data_str = json.load(f)

        # Convert strings back to ENUMs
        session_data = {SessionParams[k]: v for k, v in session_data_str.items()}
        return current_session_name, session_data


# Example of how to use the SessionManager
if __name__ == "__main__":
    sm = SessionManager()
    session_data = {
        SessionParams.APP_KEY: "YourAppKeyHere",
        SessionParams.NWK_KEY: "YourNwkKeyHere"
    }
    sm.create_session("session1", session_data)
    current_session_name, current_session_data = sm.load_current_session()
    print(f"Current Session: {current_session_name}")
    for key, value in current_session_data.items():
        print(f"{key.name}: {value}")
