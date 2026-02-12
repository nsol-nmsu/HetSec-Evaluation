import socket
import pickle
import time

class Network:
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = "127.0.0.1"
        self.port = 5555
        #self.client_port = 5553
        self.addr = (self.server, self.port)
        #self.global_model = self.connect()
        #self.client.bind((server,port))

    def getGlobal(self):
        return self.global_model

    def connect(self):
        try:
            print("in here")
            self.client.connect(self.addr)
            prin("now here")
            data = b""
            while True:
                data_chunk =pickle.loads(self.client.recv(40960))
                if not data_chunk:
                    print("no data")
                    break
                else:
                    print(data_chunk)
                    data += data_chunk
            return data
        except:
            pass

    def send(self, data):
        try:
            self.client.send(pickle.dumps(data))
            return pickle.loads(self.client.recv(2048))
        except socket.error as e:
            print(e)

