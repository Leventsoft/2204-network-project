import json
import os
import time
import socket
import threading
import pyDes
import base64
import sys
from pynput.keyboard import Controller,Key
import logging

# Set up logging
logging.basicConfig(filename='chat_log.txt', level=logging.INFO, 
                    format='%(message)s %(asctime)s', datefmt='%m/%d/%Y %I:%M:%S %p')

def log_message(username, message, sent=True):
    # Log the message with a 'SENT' or 'RECEIVED' stamp, a username, and a timestamp
    stamp = 'SENT' if sent else 'RECEIVED'
    logging.info(f'{stamp} {username}: {message}')

ip_username_dict = {}
incoming_key = 0
sockets = []
inputflag = True


INPUT_LOCK = threading.Lock()

def signal_handler():
    # Close all open sockets

    global sockets

    for sock in sockets:
        sock.close()
    
    # Exit the program
    sys.exit(0)

    

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

    username = locked_input("Enter a username: \n")

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

        # Check if the user is already in the dictionary or if the user's timestamp is more than 15 minutes ago
        if client_address[0] not in ip_username_dict or time.time() - ip_username_dict[client_address[0]]['timestamp'] > 900:
            # Store the IP address and username in the dictionary
            ip_username_dict[client_address[0]] = {'username': username}
            # Display the detected user on the console
            print(username +'\033[92m' +  " is online" + '\033[0m')
            

        # Update the timestamp for the sender's IP address
        ip_username_dict[client_address[0]]['timestamp'] = time.time()

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
    global inputflag


    while True:
        

        if inputflag:
            action = locked_input("Enter an action ([U]sers, [C]hat, [H]istory): \n").lower()


            if action == "users" or action == "u":
                # View online users
                current_time = time.time()
                # Iterate over the IP addresses and usernames in the dictionary
                for ip, user_info in ip_username_dict.items():
                    # Check if the user's timestamp is within the last 15 minutes
                    if current_time - user_info['timestamp'] <= 900:
                        # Check if the user's timestamp is within the last 10 seconds
                        if current_time - user_info['timestamp'] <= 10:
                            # Display the username as (Online) in green
                            print('\033[1m' + user_info['username'] + '\033[0m' + '\033[92m' + ' (Online)' + '\033[0m')
                        else:
                            # Display the username as (Away) in yellow
                            print('\033[1m' + user_info['username'] + '\033[0m' +'\033[93m' + ' (Away)' + '\033[0m')

            elif action == "chat" or action == "c":
                # Initiate chat
                print("Chat initiated!")

                chat_username = locked_input("Enter a username to chat with: \n")
                if chat_username not in [user_info['username'] for user_info in ip_username_dict.values()]:
                    print("User not found!")
                    continue
                security = locked_input("Please specify [S]ecure or [U]nsecure chat: ").lower()
                
                if security == "s" or security == "secure":
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

                    log_message(chat_username, encrypted_msg, sent=True)

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
                    log_message(chat_username, message, sent=True)
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
                

            elif action == "history" or action == "h":
                # View chat history
                print("Chat history: \n")
                
                # Add your code to display chat history here

                with open('chat_log.txt', 'r') as file:
                    lines = file.readlines()
                    last_10_lines = lines[-10:]
                    reversed_lines = reversed(last_10_lines)
                    for line in reversed_lines:
                        print(line.strip())

                
            elif action == "\n" or action.strip() == "":
                if inputflag:
                    continue
                print("Secure chat initiated!")
                continue

            else:
                print("Invalid action specified!")
        else:
            time.sleep(1) # Wait a bit before checking if secure chat is activated again

def Chat_Responder():
    
    global inputflag
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
            inputflag = False
            keyboard = Controller()
            time.sleep(0.01)
            # Press and release the 'Enter' key
            keyboard.press(Key.enter)
            keyboard.release(Key.enter)

            private_key = locked_input("Please enter a private key for the secure chat: ")
            

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
            
            log_message(ip_username_dict[client_address[0]]['username'], message.decode('utf-8'), sent=False)

            print('Decrypted message from', ip_username_dict[client_address[0]]['username'], ':', message.decode('utf-8'))

            inputflag = True # Secure chat is done, so the user can initiate another secure chat


        elif 'unencrypted_message' in json_data:
            # Extract the unencrypted message from the JSON data
            unencrypted_message = json.loads(json_data)['unencrypted_message']
            # Print the unencrypted message
            log_message(ip_username_dict[client_address[0]]['username'], unencrypted_message, sent=False)
            print('Received unencrypted message:', unencrypted_message)
        else:
            print('Invalid message received!')
        
        # Close the client socket
        client_socket.close()