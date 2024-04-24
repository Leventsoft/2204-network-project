import threading
from functions import Service_Announcer, Peer_Discovery, Chat_Initiator, Chat_Responder


broadcast_ip = "192.168.194.255"

# Create a new thread
Announcer_Thread = threading.Thread(target=Service_Announcer, args=(broadcast_ip,))
Discovery_Thread = threading.Thread(target=Peer_Discovery)
Chat_Initiation_Thread = threading.Thread(target=Chat_Initiator)
# Start the thread
Announcer_Thread.start()
Discovery_Thread.start()
Chat_Initiation_Thread.start()


# Wait for the threads to finish
Announcer_Thread.join()
Discovery_Thread.join()
Chat_Initiation_Thread.join()