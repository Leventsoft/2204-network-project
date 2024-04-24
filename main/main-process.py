import multiprocessing
from functions import Service_Announcer, Peer_Discovery, Chat_Initiator, Chat_Responder

broadcast_ip = "192.168.194.255"

# Create new processes
Announcer_Process = multiprocessing.Process(target=Service_Announcer, args=(broadcast_ip,))
Discovery_Process = multiprocessing.Process(target=Peer_Discovery)
Chat_Initiation_Process = multiprocessing.Process(target=Chat_Initiator)

# Start the processes
Announcer_Process.start()
Discovery_Process.start()
Chat_Initiation_Process.start()

# Wait for the processes to finish
Announcer_Process.join()
Discovery_Process.join()
Chat_Initiation_Process.join()