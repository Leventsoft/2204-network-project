import threading
from functions import Service_Announcer, Peer_Discovery, Chat_Initiator, Chat_Responder, signal_handler
import signal
import time

  
broadcast_ip = "192.168.194.255"
# broadcast_ip = "10.0.0.255"

# Make sure all sockets are closed when the program is terminated
signal.signal(signal.SIGINT, signal_handler)

# Create a new thread
Announcer_Thread = threading.Thread(target=Service_Announcer, args=(broadcast_ip,))
Discovery_Thread = threading.Thread(target=Peer_Discovery)
Chat_Initiator_Thread = threading.Thread(target=Chat_Initiator)
Chat_Responder_Thread = threading.Thread(target=Chat_Responder)

# Start the thread

Announcer_Thread.start()
time.sleep(0.001)
Discovery_Thread.start()
time.sleep(0.001)
Chat_Initiator_Thread.start()
time.sleep(0.001)
Chat_Responder_Thread.start()

# Wait for the threads to finish


Announcer_Thread.join()
Discovery_Thread.join()
Chat_Initiator_Thread.join()
Chat_Responder_Thread.join()