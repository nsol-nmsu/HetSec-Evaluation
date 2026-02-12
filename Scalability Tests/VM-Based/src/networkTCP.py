import socket
import pickle
import time
import select
chunkSize=1368
class NetworkTCP:
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
            print("now here")
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


    def RUDPsend(socket, packets):
        totalPackets = len(packets)
        x = 0
        print(f"starting indx {x},  {totalPackets} packets left")
        totalPackets = totalPackets.to_bytes(2, byteorder="big")

        for packet in packets:
            p_num = x.to_bytes(2, byteorder="big")
            packet = p_num + totalPackets + packet
            socket.send(packet)
            x+=1

        #check for the server receiving what we send
        data = b''
        while data !=  b'ack':
            data = socket.recv(chunkSize)
            print(data[:7])
            if(data[:7] == b'missing'):
                #NOTE: Assumes all missing packets are listed in the message
                print("resending missing packets")
                data_request = data[7:]
                nums_to_send = set()

                while len(data_request) > 0:
                    nums_to_send.add(int.from_bytes(data_request[:2], byteorder="big" ))
                    data_request = data_request[2:]

                x = 0
                for packet in packets:
                    p_num = x.to_bytes(2, byteorder="big")
                    packet = p_num + totalPackets + packet
                    if x in nums_to_send:
                        socket.send(packet)
                    x+=1

            #if they were turned away wait for our turn, start again
            elif(data == b'turn'):
                return False

        if(data == b'ack'):
            print(f"{len(packets)} sent properly")
        else:
            print("server did not ack and we broke")
        return True

    def break_data(socket, data_pickle):
        chunk_size = chunkSize-4  # Adjust the buffer size
        packets = []
            
        for i in range(0, len(data_pickle), chunk_size):
            packets.append(data_pickle[i:i+chunk_size])

        #print("sending weights")
        done = False
        while not done:
            done = NetworkTCP.RUDPsend(socket, packets)

    def RUDPrecv(socket):
        recv_bytes = b""
        awaiting_response = set() #Check if any others want to send something
        data_byte = socket.recv(chunkSize)
        #print("I am here")
        ###check if they are sending their wieghts
        #print("Why am I here")
        #for confirming total number
        packet_list = {}
        n = int.from_bytes(data_byte[:2], byteorder='big')
        packet_num = int.from_bytes(data_byte[2:4], byteorder='big') -1
        #print(f"{n} packet recieved", data_byte[:2])
        recv_bytes = data_byte[4:]
        print("Total ", packet_num)
        while True:
            try:         
                if(len(packet_list)) == packet_num:
                    print("received all")
                    socket.send(b'ack')
                    return recv_bytes, awaiting_response
                
                #Add newest packet
                else:
                    data_byte = socket.recv(chunkSize)
                    n = int.from_bytes(data_byte[:2], byteorder='big')
                    #print(f"{n} packet recieved",data_byte[:5] )
                    recv_bytes += data_byte[4:]
                    packet_num -= 1

            except:
                print("done in except block")
                return b'', set()
