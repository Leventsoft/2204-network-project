import json
import time
import socket

def peer_discovery(ip_address):
    #This functions requires the username of the user as an input
 
    # Set the IP address and port of the receiver
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    username = input("Enter a username: ")

    while True:
        # Create the JSON message
        message = json.dumps({"username": username})

        # Send the message to the receiver
        broadcast_socket.sendto(message.encode(), (ip_address, port))

        print("Username is broadcasted!")

        # Wait for 8 seconds before sending the next message
        time.sleep(8)

