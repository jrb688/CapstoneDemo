# server.py

import socket                   # Import socket module

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
s.bind((host, port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.

print 'Server listening....'

while True:
    conn, addr = s.accept()     # Establish connection with client.
    print 'Got connection from', addr
    data = conn.recv(1024)
    print('Server received', repr(data))

    with open('received_file.py', 'wb') as f:
        print 'file opened'
        while True:
            print('receiving data...')
            data = conn.recv(1024)
            if not data:
                break
            # write data to a file
            f.write(data)
    
    f.close()
    print('Successfully got the python file')

    filename='results.html'
    f = open(filename,'rb')
    l = f.read(1024)
    while (l):
        conn.send(l)
        print('Sent ',repr(l))
        l = f.read(1024)
    f.close()

    print ('Done Sending')

    conn.close()
    print('connection closed')
