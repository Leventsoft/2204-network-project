import threading
from functions import Service_Announcer


broadcast_ip = "192.168.30.255"

# Create a new thread
my_thread = threading.Thread(target=Service_Announcer, args=(broadcast_ip,))

# Start the thread
my_thread.start()


# Continue with the rest of your code