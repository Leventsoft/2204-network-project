import threading
from functions import Service_Announcer


broadcast_ip = "192.168.30.255"

# Create a new thread
Announcer_Thread = threading.Thread(target=Service_Announcer, args=(broadcast_ip,))

# Start the thread
Announcer_Thread.start()


# Continue with the rest of your code