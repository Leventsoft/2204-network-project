import json
import os
import time
import socket
import threading
import pyDes
import base64
from pynput.keyboard import Controller,Key
import logging
import signal

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
local_ip = ''
local_username = ''

INPUT_LOCK = threading.Lock()

def signal_handler():
    # Close all open sockets

    global sockets

    for sock in sockets:
        sock.close()
    
    # Exit the program
    os.kill(os.getpid(), signal.SIGTERM)

    

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
    global local_username
 
    # Set the IP address and port of the receiver
    port = 6000

    # Create a socket object
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Program does not run on linux unless the socket is set up for broadcasting
    # Meanwhile, it does not run on Windows if it is set up for broadcasting

    if os.name == 'posix':
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    time.sleep(0.03)
    username = locked_input("\033[94;1mEnter a username: \n\033[0m")
    local_username = username

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
    global local_ip

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
            if not local_ip and local_username == ip_username_dict[client_address[0]]['username']:
                local_ip = client_address[0]
                print('Local IP:', local_ip)

        # Update the timestamp for the sender's IP address
        ip_username_dict[client_address[0]]['timestamp'] = time.time()

        #print('Username:', username)wowkey
        #print([ip_username_dict])
        #print('Client IP Address:', client_address[0])

def dh_generate_public_key(private_key, g=5, p=23):
    """ Generate private and public keys """
    public_key = pow(g, private_key, p)     # public_key = g^private_key % p
    time.sleep(0.1)
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
    global chat_username


    while True:
        

        if inputflag:
            time.sleep(0.1) # Wait a bit before checking if secure chat is activated again
            action = locked_input("\033[94;1mEnter an action \033[0m([U]sers, [C]hat, [H]istory, [E]xit): \n").lower()


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

                chat_username = locked_input("\033[94;1mEnter a username to chat with: \n\033[0m")
                if chat_username not in [user_info['username'] for user_info in ip_username_dict.values()]:
                    print("User not found!")
                    continue
                security = locked_input("\033[94;1mPlease specify [S]ecure or [U]nsecure chat: \033[0m").lower()
                
                if security == "s" or security == "secure":
                    print("\033[91mSecure chat initiated!\033[0m")

                    # User need to enter the key
                    private_key = ''
                    while not private_key:
                        private_key = locked_input("\033[91mEnter a private key: \033[0m") # Create the JSON message with the key
                        if not private_key:
                            print("Private key cannot be empty. Please try again.")
                    
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
                    print("\033[3mWaiting for the recipient's public key. \033[0m")

                    incoming_key = tcp_socket.recv(1024).decode()
                    print('Incoming public key:', incoming_key)

                    if incoming_key:  # Check if incoming_key is not empty
                        wowkey = dh_compute_shared_secret(int(incoming_key), int(private_key))

                    encrypted_msg = locked_input('Enter a message to encrypt: ')

                    log_message(chat_username, encrypted_msg, sent=True)
                    print('\033[1m[SENT]\033[0m' + f' {chat_username}: {encrypted_msg}')

                    encrypted_msg = encrypted_msg.encode('utf-8')

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
                    print('\033[1m[SENT]\033[0m' + f' {chat_username}: {message}')
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
						
            elif action == "exit" or action == "e":
                print("Exiting the program...")
                time.sleep(0.05)
                signal_handler()
                
            elif action == "\n" or action.strip() == "":
                if inputflag:
                    continue
                print("\033[91mSecure chat initiated!\033[0m")
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
        # print('Received message:', json_data)
        # Decode the received message
        decoded_message = json.loads(json_data)
        # Print the decoded message
        print('\033[1m[RECEIVED]\033[0m', ip_username_dict[client_address[0]]['username'], ':', decoded_message)
        # Debug line to see the IP address of the client
        # print(client_address[0])

        # Check if the received message contains the key
        if 'key' in json_data:
            # Extract the key from the JSON data
            incoming_key = json.loads(json_data)['key']
            # Print the key

            print('Incoming public key:', incoming_key)
            # Send the public key to the end user
            inputflag = False
            keyboard = Controller()
            time.sleep(0.1)
            
            # Check if the user is chatting with the same user
            # Debug line to see the local IP address and the client's IP address
            # print('Local IP:', local_ip, 'Client IP:', client_address[0], 'Local username:', local_username, 'Client username:', ip_username_dict[client_address[0]]['username'])
            if local_username != ip_username_dict[client_address[0]]['username'] or local_ip != client_address[0]:
                # Press and release the 'Enter' key
                # Need to press Enter if the user is not chatting the same user
                keyboard.press(Key.enter)
                time.sleep(0.01)
                keyboard.release(Key.enter)
            
            print("\033[3mYou need to enter a private key...\033[0m")
            private_key = ''
            while not private_key:
                private_key = locked_input("\033[91mPlease enter a private key for the secure chat: \033[0m")
                if not private_key:
                    print("Private key cannot be empty. Please try again.")
            
            print("\033[3mWaiting for the message...\033[0m")

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
            time.sleep(0.01)
            message = pyDes.triple_des(str(wowkey).ljust(24)).decrypt(message2, padmode=2)
            time.sleep(0.1)

            log_message(ip_username_dict[client_address[0]]['username'], message.decode('utf-8'), sent=False)

            print('\033[1mDecrypted message from', ip_username_dict[client_address[0]]['username'], ':', message.decode('utf-8'), '\033[0m')

            inputflag = True # Secure chat is done, so the user can initiate another secure chat


        elif 'unencrypted_message' in json_data:
            # Extract the unencrypted message from the JSON data
            unencrypted_message = json.loads(json_data)['unencrypted_message']
            # Print the unencrypted message
            log_message(ip_username_dict[client_address[0]]['username'], unencrypted_message, sent=False)
            print('\033[1mReceived unencrypted message from', ip_username_dict[client_address[0]]['username'], ':', unencrypted_message, '\033[0m')
        else:
            print('Invalid message received!')
        
        # Close the client socket
        client_socket.close()