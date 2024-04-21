import json
import time
import socket

def peer_discovery():
    #This functions requires the username of the user as an input
 
    # Set the IP address and port of the receiver
    ip_address = "192.168.30.255"
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    username = input("Enter a string: ")

    while True:
        # Create the JSON message
        message = json.dumps({"username": username})

        # Send the message to the receiver
        broadcast_socket.sendto(message.encode(), (ip_address, port))

        # Wait for 8 seconds before sending the next message
        time.sleep(8)
        print("Username is broadcasted!")
