import threading
import json
import time
import socket
from functions import peer_discovery



# Create a new thread
my_thread = threading.Thread(target=peer_discovery)

# Start the thread
my_thread.start()



# Continue with the rest of your code