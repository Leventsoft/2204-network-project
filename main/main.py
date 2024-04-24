import threading
from functions import Service_Announcer, Peer_Discovery, Chat_Initiator, Chat_Responder


broadcast_ip = "192.168.194.255"

# Create a new thread
Announcer_Thread = threading.Thread(target=Service_Announcer, args=(broadcast_ip,))

# Start the thread
Announcer_Thread.start()


# Continue with the rest of your code