import socket


def server_program():
    # get the hostname
    print("Hello")
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    print(host)
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    data = int(conn.recv(1024).decode())
    print("from connected user: " + str(data))
    conn1, address1 = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    data1 = int(conn1.recv(1024).decode())
    print("from connected user: " + str(data1))    

    conn.send(str(data+data1).encode())  # send data to the client
    conn1.send(str(data+data1).encode())  # send data to the client

    conn.close()  # close the connection
    conn1.close()  # close the connection



if __name__ == '__main__':
    server_program()