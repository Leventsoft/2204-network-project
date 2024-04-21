import socket

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set the socket option to allow broadcasting
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# Bind the socket to a specific address and port
server_socket.bind(('0.0.0.0', 6000))

# Listen for incoming connections
server_socket.listen(1)

print('Server listening on port 6000...')

while True:
    # Accept a connection from a client
    client_socket, client_address = server_socket.accept()
    print('Connected to', client_address)

    # Receive data from the client
    data = client_socket.recv(1024)
    print('Received:', data.decode())

    # Send a response back to the client
    response = 'Hello from the server!'
    client_socket.send(response.encode())

    # Close the connection
    client_socket.close()