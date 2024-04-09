import subprocess

class CommandHandler:

    def execute_command(self, command):
        try:
            process = subprocess.Popen(command)
            process.wait()
        except KeyboardInterrupt:
            process.terminate()