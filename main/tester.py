import socket
import json


# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific address and port
server_socket.bind(('0.0.0.0', 6000))

print('Server listening on port 6000...')

while True:
    # Receive data from the client
    data, client_address = server_socket.recvfrom(1024)

    # Convert the received data to JSON
    json_data = json.loads(data.decode())

    print('Username:', json_data['username'])
    print('Client IP Address:', client_address[0])