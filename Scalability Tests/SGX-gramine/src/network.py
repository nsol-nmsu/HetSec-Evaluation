import socket
import pickle
import time
import select
chunkSize=1000
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


    def RUDPsend(socket, server_addr, packets):
        totalPackets = len(packets)
        x = 0
        print(f"starting indx {x},  {totalPackets} packets left")
        totalPackets = totalPackets.to_bytes(2, byteorder="big")

        for packet in packets:
            p_num = x.to_bytes(2, byteorder="big")
            packet = p_num + totalPackets + packet
            socket.sendto(packet,server_addr)
            x+=1

        #check for the server receiving what we send
        data = b''
        while data !=  b'ack':
            data, _ = socket.recvfrom(chunkSize)
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
                        socket.sendto(packet,server_addr)
                    x+=1

            #if they were turned away wait for our turn, start again
            elif(data == b'turn'):
                return False

        if(data == b'ack'):
            print(f"{len(packets)} sent properly")
        else:
            print("server did not ack and we broke")
        return True

    def break_data(socket, server_addr, data_pickle):
        chunk_size = chunkSize-4  # Adjust the buffer size
        packets = []
            
        for i in range(0, len(data_pickle), chunk_size):
            packets.append(data_pickle[i:i+chunk_size])

        #print("sending weights")
        done = False
        while not done:
            done = Network.RUDPsend(socket, server_addr, packets)

    def RUDPrecv(socket):
        recv_bytes = b""
        awaiting_response = set() #Check if any others want to send something
        data_byte, current_addr = socket.recvfrom(chunkSize)
        #print("I am here")
        ###check if they are sending their wieghts
        #print("Why am I here")
        #for confirming total number
        packet_list = {}
        n = int.from_bytes(data_byte[:2], byteorder='big')
        packet_num = int.from_bytes(data_byte[2:4], byteorder='big')
        print(f"{n} packet recieved", data_byte[:2])
        if n not in packet_list:
            packet_list[n] = data_byte[4:]
        print("Total ", packet_num)
        while True:
            try:
                ready_to_read, _, _ = select.select([socket], [], [], 0.5)  # Wait up to 1 second for data
                if not ready_to_read and (len(packet_list)) != packet_num:
                    #print(packet_num, len(packet_list))
                    data_request = b'missing'
                    for num in range(packet_num):
                        if num not in packet_list:
                            data_request += (num).to_bytes(2, byteorder="big")
                    socket.sendto(data_request,current_addr)
                    continue                            
                
                if(len(packet_list)) == packet_num:
                    print("received all")
                    socket.sendto(b'ack',current_addr)
                    for num in range(len(packet_list)):
                        recv_bytes += packet_list[num]
                    return recv_bytes, current_addr, awaiting_response
                
                #Add newest packet
                else:
                    data_byte , addr = socket.recvfrom(chunkSize)
                    while addr != current_addr:
                        awaiting_response.add(addr)
                        data_byte = socket.recvfrom(chunkSize)           
                    n = int.from_bytes(data_byte[:2], byteorder='big')
                    #print(f"{n} packet recieved",data_byte[:5] )
                    if n not in packet_list:
                        packet_list[n] = data_byte[4:]

            except:
                print("done in except block")
                return b'', None, set()
