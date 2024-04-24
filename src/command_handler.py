import subprocess

class CommandHandler:
    """Base class for handling command execution.

    This class provides a basic mechanism to execute external commands using the `subprocess` module.
    """

    def execute_command(self, command):
        """Executes an external command with error handling and termination on keyboard interrupt.

        This function takes a list of arguments representing the command and its options to execute. It uses the `subprocess.Popen` function to launch the command as a separate process. The function waits for the process to finish (`process.wait()`) and raises an exception if the process fails.

        Keyboard interrupts (Ctrl+C) are handled by terminating the running process using `process.terminate()`.

        Args:
            command (list): A list of strings representing the command and its arguments to execute.

        Raises:
            subprocess.CalledProcessError: If the command execution fails.
            KeyboardInterrupt: If the command execution is interrupted by the user using Ctrl+C.
        """
        try:
            process = subprocess.Popen(command)
            process.wait()
        except KeyboardInterrupt:
            process.terminate()