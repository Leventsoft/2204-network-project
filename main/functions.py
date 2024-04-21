import json
import os
import time
import socket
import sys

def Service_Announcer(ip_address):
    #This functions requires the username of the user as an input
 
    # Set the IP address and port of the receiver
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Program does not run on linux unless the socket is set up for broadcasting
    # Meanwhile, it does not run on Windows if the following line is included

    if os.name == 'posix':
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    username = input("Enter a username: ")

    while True:
        # Create the JSON message
        message = json.dumps({"username": username})

        # Send the message to the receiver
        broadcast_socket.sendto(message.encode(), (ip_address, port))

        print("Username is broadcasted!")

        # Wait for 8 seconds before sending the next message
        time.sleep(8)

def Peer_Discovery():
    pass

def Chat_Initiator():
    pass

def Chat_Responder():
    pass