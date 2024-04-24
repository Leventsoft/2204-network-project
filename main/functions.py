import json
import os
import time
import socket

ip_username_dict = {}

def Service_Announcer(ip_address):
    #This functions requires the username of the user as an input
 
    # Set the IP address and port of the receiver
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Program does not run on linux unless the socket is set up for broadcasting
    # Meanwhile, it does not run on Windows if it is set up for broadcasting

    if os.name == 'posix':
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    username = input("Enter a username: ")

    while True:
        # Create the JSON message
        message = json.dumps({"username": username})

        # Send the message to the receiver
        broadcast_socket.sendto(message.encode(), (ip_address, port))

        #print(username,"is broadcasted!")

        # Wait for 8 seconds before sending the next message
        time.sleep(8)

def Peer_Discovery():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('0.0.0.0', 6000))

    print('Server listening on port 6000...')

    # Define the dictionary as global to store the IP addresses, usernames, and timestamps
    global ip_username_dict

    while True:
        # Receive data from the client
        data, client_address = server_socket.recvfrom(1024)

        # Convert the received data to JSON
        json_data = json.loads(data.decode())

        # Extract the username from the JSON data
        username = json_data['username']

        # Store the IP address and username in the dictionary
        ip_username_dict[client_address[0]] = {'username': username}

        # Update the timestamp for the sender's IP address
        ip_username_dict[client_address[0]]['timestamp'] = time.time()

        # Display the detected user on the console
        print(username, "is online")

        #print('Username:', username)
        #print([ip_username_dict])
        #print('Client IP Address:', client_address[0])

def check_user_status():
    # Define the dictionary as global to access the IP addresses and usernames
    global ip_username_dict
    # Get the current time
   

def Chat_Initiator():
    # Define the dictionary as global to access the IP addresses and usernames
    global ip_username_dict

    # Prompt the user to specify the action
    action = input("Specify action (Users/Chat/History): ")

    if action == "Users":
        # View online users
        current_time = time.time()
        # Iterate over the IP addresses and usernames in the dictionary
        for ip, user_info in ip_username_dict.items():
            # Check if the user's timestamp is within the last 15 minutes
            if current_time - user_info['timestamp'] <= 900:
                # Check if the user's timestamp is within the last 10 seconds
                if current_time - user_info['timestamp'] <= 10:
                    # Display the username as (Online)
                    print(user_info['username'], "(Online)")
                else:
                    # Display the username as (Away)
                    print(user_info['username'], "(Away)")

    elif action == "Chat":
        # Initiate chat
        print("Chat initiated!")

    elif action == "History":
        # View chat history
        print("Chat history:")
        # Add your code to display chat history here

    else:
        print("Invalid action specified!")

    # TCP 6001

def Chat_Responder():
    pass