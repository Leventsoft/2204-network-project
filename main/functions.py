import json
import os
import time
import socket
import threading
import pyDes
import base64



ip_username_dict = {}
incoming_key = 0

INPUT_LOCK = threading.Lock()

def locked_input(prompt):
    with INPUT_LOCK:
        return input(prompt)

def get_ip_address(username, dictionary):
    # This function is used for finding the IP address of a user in the dictionary
    for ip_address, user_info in dictionary.items():
        if user_info['username'] == username:
            return ip_address
    return None  # If username is not found in the dictionary


def Service_Announcer(ip_address):
    #This functions requires the broadcast address as an input
 
    # Set the IP address and port of the receiver
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Program does not run on linux unless the socket is set up for broadcasting
    # Meanwhile, it does not run on Windows if it is set up for broadcasting

    if os.name == 'posix':
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    username = locked_input("Enter a username: ")

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

        #print('Username:', username)wowkey
        #print([ip_username_dict])
        #print('Client IP Address:', client_address[0])

def dh_generate_public_key(private_key, g=5, p=23):
    """ Generate private and public keys """
    public_key = pow(g, private_key, p)     # public_key = g^private_key % p
    return public_key

def dh_compute_shared_secret(other_public_key, my_private_key, p=23):
    """ Compute the shared secret """
    shared_secret = pow(other_public_key, my_private_key, p)  # shared_secret = other_public_key^my_private_key % p
    return shared_secret


def Chat_Initiator():
    # Define the dictionary as global to access the IP addresses and usernames
    global ip_username_dict
    global incoming_key

    while True:

        action = locked_input("Enter an action (Users, Chat, History): ")


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

            chat_username = locked_input("Enter a username to chat with: ")

            security = locked_input("Please specify [S]ecure or [U]nsecure chat:")
            
            if security == "S" or security == "s":
                print("Secure chat initiated!")

                # User need to enter the key
                private_key =  locked_input("Enter a private key: ") # Create the JSON message with the key
                
                public_key = dh_generate_public_key(int(private_key))
                
                json_message = json.dumps({"key": str(public_key)})
                # Send the message to the end user
                # Get the IP address from the dictionary
                ip_address = get_ip_address(chat_username, ip_username_dict)
                # Create a TCP socket object
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Connect to the IP address and port 6001
                tcp_socket.connect((ip_address, 6001))
                # Send the JSON message over the TCP connection
                tcp_socket.send(json_message.encode())

                # Receive the public key from the end user
                # tcp_socket.send(str(public_key).encode())
                incoming_key = tcp_socket.recv(1024).decode()

                if incoming_key:  # Check if incoming_key is not empty
                    wowkey = dh_compute_shared_secret(int(incoming_key), int(private_key))

                encrypted_msg = locked_input('Input lowercase sentence:')

                encrypted_msg = pyDes.triple_des(str(wowkey).ljust(24)).encrypt(encrypted_msg, padmode=2)
                
                encrypted_msg = base64.b64encode(encrypted_msg).decode('utf-8')

                encrypted_msg = json.dumps({"encrypted_message": encrypted_msg})


                tcp_socket.send(encrypted_msg.encode())

                tcp_socket.close()
                # Close the TCP connection
            
            else:
                print("Unsecure chat initiated!")
                message = locked_input("Enter your message: ")
                # Create the JSON message with unencrypted message
                json_message = json.dumps({"unencrypted_message": message})
                # Send the message to the end user
                # Get the IP address from the dictionary
                ip_address = get_ip_address(chat_username, ip_username_dict)
                #print(ip_address)
                # Create a TCP socket object
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Connect to the IP address and port 6001
                tcp_socket.connect((ip_address, 6001))
                # Send the JSON message over the TCP connection
                tcp_socket.send(json_message.encode())
                # Close the TCP connection
                tcp_socket.close()
               

        elif action == "History":
            # View chat history
            print("Chat history:")
            # Add your code to display chat history here

        else:
            print("Invalid action specified!")

    # TCP 6001

def Chat_Responder():
    
    global ip_username_dict
    global incoming_key

    # Create a TCP socket object
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to a specific address and port
    tcp_socket.bind(('0.0.0.0', 6001))
    # Listen for incoming connections
    tcp_socket.listen(1)
    print('Chat responder listening on port 6001...')
    
    while True:
        # Accept a connection from a client
        client_socket, client_address = tcp_socket.accept()
        print('Received connection from:', client_address, "Username:", ip_username_dict[client_address[0]]['username'])
        
        # Receive data from the client
        data = client_socket.recv(1024)
        # Decode the received data
        json_data = data.decode()
        # Print the received message
        print('Received message:', json_data)

        # Check if the received message contains the key
        if 'key' in json_data:
            # Extract the key from the JSON data
            incoming_key = json.loads(json_data)['key']
            # Print the key
            print('Incoming public key:', incoming_key)

            # Send the public key to the end user
            private_key = locked_input("Please enter a private key for the secure chat:")

            public_key = dh_generate_public_key(int(private_key))

            client_socket.send(str(public_key).encode())

            wowkey = dh_compute_shared_secret(int(incoming_key), int(private_key))

            # Receive the encrypted message
            message = client_socket.recv(1024)
            json_data_encrypted = message.decode()
            print('Received encrypted message:', json_data_encrypted)
            message = json.loads(json_data_encrypted)['encrypted_message']
            message2 = base64.b64decode(message)
            print('Decryption key:', wowkey)
            print('Encrypted message:', message)
            message = pyDes.triple_des(str(wowkey).ljust(24)).decrypt(message2, padmode=2)
            


            print('Decrypted message:', message.decode("utf-8"))


        elif 'unencrypted_message' in json_data:
            # Extract the unencrypted message from the JSON data
            unencrypted_message = json.loads(json_data)['unencrypted_message']
            # Print the unencrypted message
            print('Received unencrypted message:', unencrypted_message)
        else:
            print('Invalid message received!')
        
        # Close the client socket
        client_socket.close()