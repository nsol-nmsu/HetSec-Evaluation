import os
import copy
import time
import pickle
import numpy as np
import random
import select
from tqdm import tqdm
import socket
import torch
from network import Network
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import json
##Our clients Id, and backoff for denial
my_id =1000
backoff = 2
# remove all the hard wiring and fix import export stuff
key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
padder = padding.PKCS7(128).padder()
encrypted_key_f = open('encrypt.json')
encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
print(iv)
#ALMOST DO A COPY AND PASTE OF THE SERVER VERSION OF THIS TO DO RUDP ON CLIENT SIDE
encryptor = cipher.encryptor()

def process_recieved(x=0):
    server_byte = b""

    data_byte, addr = server.recvfrom(1000)
    current_addr = addr
    print("I am here")
    ###check if they are sending their wieghts
    if data_byte == b'packet':
        server.sendto(b'ack',server_addr)
        print("Why am I here")
        #for confirming total number
        data_byte , _=server.recvfrom(1000)
        packet_num = int.from_bytes(data_byte, byteorder='big')
        print(packet_num)
        server.sendto(b'ack',server_addr)
        packet_list = {}
        while True:
            try:
                data_byte , _= server.recvfrom(1000)
                print("Loop", len(packet_list))
                if(len(packet_list) == packet_num and (data_byte[-18:] == b'complete file sent')):
                    server_byte += data_byte[2:-18]
                    message = pickle.loads(server_byte)
                    #if it is a valid sting move on
                    if(isinstance(message,list)):
                        print("received all")
                        server.sendto(b'ack',server_addr)
                        return message                
                    server.sendto(b'missing',server_addr)
                    server.sendto((x).to_bytes(),server_addr)
                    return  process_recieved(x)                
                
                elif(len(packet_list)) == packet_num:
                    #server_byte += data_byte[2:]
                    if n not in packet_list:
                        packet_list[n] = data_byte[2:]
                        x+=1
                    print("received all")
                    for num in range(len(packet_list)):
                        server_byte += packet_list[num]
                    message = pickle.loads(server_byte)
                    #if it is a valid sting move on
                    if(isinstance(message,list)):
                        print("received all")
                        server.sendto(b'ack',server_addr)
                        return message                
                    server.sendto(b'missing',server_addr)
                    server.sendto((x).to_bytes(),server_addr)
                    return  process_recieved(x)      

                elif(data_byte == b'deny'):
                    return b'deny'
                
                #if client is turned away due to another client being worked with first, it sends turn when it is their turn to start
                elif(data_byte == b'turn'):
                    return b'turn'
                
                #check if the newest packet is in order
                else:
                    n = int.from_bytes(data_byte[:2], byteorder='big')
                    print(f"{n} packet recieved")
                    if n not in packet_list:
                        packet_list[n] = data_byte[2:]
                        x+=1
                    #server_byte += data_byte[2:]

                #if the packet number is missing, or if things are out of order, ask for a resend at the previous valid spot
                '''else:
                    #make sure they acknowledge the resending
                    print(f"missing at {x}")
                    print( int.from_bytes(data_byte[:2], byteorder='big'), data_byte)
                    while(data_byte != b'ack'):
                        server.sendto(b'missing',server_addr)
                        #some sort of wait to break up the packets
                        time.sleep(.000001)
                        server.sendto((x).to_bytes(2, byteorder='big'),server_addr)
                        #data_byte = same_client(server_addr)

                    print("got ack")
                    #now they resend 
                        ########THERE IS A CHANCE THE CLIENT MISSES THEIR FIRST PACKET HERE< CHECK HERE FOR THIS ISSUE
                    
                    return process_recieved(x)
                '''

            except:
                print("done in except block")
                #iif not data_byte :
                break
                #else:
                #client_byte += data_byte
    

#bind at an adress, grab each packet, accept our ID as a client
#set up udp
def first_bind():
    server.bind(our_addr)
    while(True):
        #print("send")
        send_package = b'no id' + encrypted_key_bytes + iv
        server.sendto(send_package,server_addr)
        ready_to_read, _, _ = select.select([server], [], [], 1)  # Wait up to 1 second for data
        if not ready_to_read:        
            continue
        data = process_recieved()
        print("turned away")
        if(data != b'turn'):
            break
    return data

## break down the pickle file and send to server

def break_pickle_file(data_pickle):
    chunk_size = 998  # Adjust the buffer size
    #data_pickle = pickle.dumps(range())
    #server.sendto()
    packets = []

    for i in range(0, len(data_pickle), chunk_size):
        packets.append(data_pickle[i:i+chunk_size])

    print("sending weights")
    reliable_packets(0,packets)
   
    print(f"{len(packets)} packets sent")
    
#assures that packets are not dropping, if they are we begin to resend the ones that dropped
def reliable_packets(last_num,packets):
    chunk_size = 1000

    server.sendto(b'packet',server_addr)
    data, _ = server.recvfrom(1000)  
    while data != b'ack':
        data, _ = server.recvfrom(1000) 
    data = 0
    x = last_num
    left = (len(packets)) 
    print(f"starting indx {x},  {left} packets left")
    ####not accurate if things are borked
    server.sendto(left.to_bytes(2, byteorder="big"),server_addr)
    while data != b'ack':
        data, _ = server.recvfrom(1000) 
    for packet in packets[last_num:]:
        p_num = x.to_bytes(2, byteorder="big")
        packet = p_num + packet
        x+=1
        server.sendto(packet,server_addr)

    #server.sendto(b'complete file sent',server_addr)
    #check for the server receiving what we send
    data, _ = server.recvfrom(1000)

    while data !=  b'ack':
        
        print(data)

        if(data == b'missing'):
            
            #keep waiting till server tells the last secure packet

            #while(data == b'missing'):
            #    print("waiting on missing")
            #    data, _ = server.recvfrom(1000)

            #tell them help is on the way, and resend packets from last valid adress
            print("resending missing packets")
            server.sendto(b'ack',server_addr)
            data_request, _ = server.recvfrom(1000)
            nums_to_send = set()
            while len(data_request) > 0:
                nums_to_send.add(int.from_bytes(data_request[:2], byteorder="big" ))
                data_request = data_request[2:]
            print("send", nums_to_send)
            #reliable_packets(int.from_bytes(data, byteorder="big" ),packets)
            x = 0
            for packet in packets[last_num:]:
                p_num = x.to_bytes(2, byteorder="big")
                packet = p_num + packet
                if x in nums_to_send:
                    server.sendto(packet,server_addr)
                x+=1

        #if they were turned away wait for our turn, start again
        elif(data == b'turn'):
            reliable_packets(last_num,packets)
        data, _ = server.recvfrom(1000)

    if(data == b'ack'):
        print(f"{len(packets)} sent properly")
    else:
        print("server did not ack and we broke")




    
#bind to server, send them our weights, wait for our turn to receive data in aggregation q
def send(data):
    ##set up udp
    global our_addr
    break_pickle_file(pickle.dumps(data)) 
    print("I have sent the entire update")

def ask_for_weights():
    ##set up udp
    global backoff
    while(True):
        print(my_id.to_bytes(2, byteorder="big"))
        #print(int.from_bytes(my_id.to_bytes()))
        server.sendto(my_id.to_bytes(2, byteorder="big"),server_addr)

        data = process_recieved()
        print("turned away")
        if(data != b'turn'):
            break

    if data == b'deny':
        print("I was denied")
        return deny_send()
    
    print("got my things back from server")
    backoff = 2
    return data

def deny_send():
    global backoff
    time.sleep(1*backoff)
    backoff = backoff**2
    return ask_for_weights()


if __name__ == '__main__':
    start_time = time.time()

    # define paths
    args = args_parser()
    exp_details(args)
    device = 'cpu'

    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = "127.0.0.1"
    port = random.randrange(2550,5000)

    our_addr = (addr, port)
    server_addr = (addr,5050)
    print("bind") 
    global_info = first_bind()

    print("bound") 
    #n = Network()
    #global_info = n.bind()
    my_id = global_info[2]
    global_model = global_info[0]
    global_model.train()
    # copy weights
    global_model.to(device)
    global_weights = global_model.state_dict()

    #self.server_port = 5553
    #self.global_model = self.bind()
    #self.server.bind((addr,port))
    time.sleep(1)
    # Training
    train_loss, train_accuracy = [], []
    val_acc_list, net_list = [], []
    cv_loss, cv_acc = [], []
    print_every = 2
    val_loss_pre, counter = 0, 0
    idx = 0
    global_epoch = global_info[1]
    for epoch in tqdm(range(args.epochs)):
        local_weights, local_losses = [], []
        print(f'\n | Local Training Round : {epoch+1} |\n')
        local_model = LocalUpdate(args=args, dataset=train_dataset, idxs=user_groups[idx])
        w, loss = local_model.update_weights(model=copy.deepcopy(global_model), global_round=global_epoch)
        updated_weights = w
        padded_updated_weights = padder.update(pickle.dumps(w)) + padder.finalize()
        encrypted_updated_weights = encryptor.update(padded_updated_weights) + encryptor.finalize()
        send([encrypted_updated_weights, my_id])
        print("asking for them back")
        global_info = ask_for_weights()
        print("we are here")
        global_weights = global_info[0]
        global_model.to(device)
        global_epoch = global_info[1]

        
        #server_model.load_state_dict(w)
        
