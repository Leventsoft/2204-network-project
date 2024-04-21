import threading
import json
import time
import socket
from functions import peer_discovery
from variables import broadcast_ip_address


# Create a new thread
my_thread = threading.Thread(target=peer_discovery, args=(broadcast_ip_address))

# Start the thread
my_thread.start()


# Continue with the rest of your code