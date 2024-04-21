import threading
import json
import time
import socket
from functions import peer_discovery


broadcast_ip = "192.168.1.255"

# Create a new thread
my_thread = threading.Thread(target=peer_discovery, args=(broadcast_ip))

# Start the thread
my_thread.start()


# Continue with the rest of your code