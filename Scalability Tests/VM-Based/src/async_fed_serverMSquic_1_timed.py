import os
import copy
import time
import pickle
import numpy as np
from tqdm import tqdm
import socket
import torch
import threading
import queue
from networkTCP import NetworkTCP
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details
import select
import secrets
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import msquic
from multiprocessing import Pool
import subprocess
import json
import random
import asyncio

pending1 = {}
pending2 = {}

idx_rounds = {}
idx_weights = [0]*10
id1 = 0
to_be_processed = queue.Queue()
processed = []
prev_clients = set()
awaiting_response = set()
chunkSize = 1000
client_keys = {}

chunkSize = 1368
agent_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
padder = padding.PKCS7(128).padder()
encrypted_key_f = open('encrypt1.json')
subprocess.run("./MABE-encrypt")
encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
agent_cipher = Cipher(algorithms.AES(agent_key), modes.CBC(iv))
#ALMOST DO A COPY AND PASTE OF THE SERVER VERSION OF THIS TO DO RUDP ON CLIENT SIDE
encryptor = agent_cipher.encryptor()
encrypted_updated_weights = ''
#ReqID to Time sent
server1_req_time = {}
server2_req_time = {}
server1 = None
server2 = None

#ReqID to streamID
req_map = {}
data_map = {}
socket1_map = {}
socket2_map = {}

currentReqID = 1
read_delay = 0.001
time_start_global = None
#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client():   
    global my_id1
    global my_id2
    global server1_req  
    global server2_req    
    global currentReqID    
    global global_weights
    global encrypted_updated_weights
    global time_start_global

    server = "127.0.0.1"
    #server = socket.gethostname()
    por = 5006

    s = msquic.MSQuicSocket()
    s.CreateServerSocket(por)

    print("in the Handle")
    while True:
        #wait here for some data to be recieved and processed
        try:
            client_data, streamID = await asyncio.to_thread(s.RecvAny)
        except:           
            continue
        if client_data == "" or client_data == b'':
            continue
        message = 0
        print(len(client_data))
        try:
            message = pickle.loads(client_data)
        except:
            message = 0
            print("Not a message")
        #process_recieved()
        to_remove = []

        print("in the Handle")
        print()

        flag = True
        #check if client is wanting their waits and is a valid client

        #if our client had no ID get them set up
        try:  
            if client_data[:5] == b'no id':
                global id1
                global client_keys

                print(f"New Client joins Id:{id1}")
                
                encrypted_key_string = client_data[5:37].decode()

                #keyBytes = subprocess.run("./src/MABE-decrypt", capture_output=True, text=True).stdout
                decrypted_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
        
                #print(keyBytes)
                #decrypted_key = bytes.fromhex(keyBytes)
                print(decrypted_key)
                client_keys[id1] = [decrypted_key, client_data[-16:]]
                print(client_data[-16:])

                prev_clients.add(id1)
                global_pickle = pickle.dumps([global_model, 0, id1])
                id1 = id1 + 1
                print(len(global_pickle), streamID) 
                s.ServerSend(streamID, bytes(global_pickle))#, len(global_pickle))
                print("Sent")



            # if the client is not asking for an id, nor is it asking for its data, we can assume it has just sent its weights,so we add them to the line            
            else:
                if time_start_global == None:
                    time_start_global = time.perf_counter()

                print(f"Returning Client {message[1]}")
                #trainerOnce(message[1], message[0])
                mes = pickle.dumps([message[0], message[2]])

                print("Encrypting", my_id1)
                if(encrypted_updated_weights == ''):
                    padded_updated_weights = padder.update(pickle.dumps(global_weights)) + padder.finalize()
                    encrypted_updated_weights = encryptor.update(padded_updated_weights) + encryptor.finalize()     

                mes = pickle.dumps([global_model, message[2]])

                print("Sending 1", my_id1)
                server1_req_time[currentReqID] = time.time()

                asyncio.create_task( send([encrypted_updated_weights, my_id1, currentReqID], 5007, 0.002, s) )

                req_map[currentReqID] = streamID
                data_map[currentReqID] = mes
                currentReqID+=1
                
        except: 
            print("Hello.")
        #after resolving client, check if any clients tried to contact us during the loop

async def send(data, port, delay, host_server):
    #nserver.CreateClientSocket("localhost", 5006, 100000)
    if delay != 0:
        await asyncio.sleep(delay)        

    ##set up udp
    global our_addr
    global server1
    not_done = True
    send_package = pickle.dumps(data)
    reqID = data[2]
    print("sending", len(send_package))


    nserver = server1
    
    await asyncio.sleep(.2)

    #while not_done:
    #await asyncio.sleep(read_delay)
    #data = nserver.RecvFromNow()
    
    fut = asyncio.get_running_loop().create_future()
    pending1[reqID] = fut

    mean = 0.016304035605
    std_dev = 0.000184003982
    MABE_wait = random.gauss(mean, std_dev)



    mean = 0.016153517920
    std_dev = 0.000201593520
    MABE_wait += random.gauss(mean, std_dev)

    mean = 0.000011554021
    std_dev = 0.000002528596
    time_wait = random.gauss(mean, std_dev)

    mean = 0.000012840250
    std_dev = 0.000005130293
    time_wait += random.gauss(mean, std_dev)   

    time_wait += MABE_wait
    #Simulated LLM task
    time_wait += 5.0

    await asyncio.sleep(time_wait)

    #data, _ = await asyncio.to_thread(nserver.RecvFrom) 
    server1.ClientSend(send_package)

    message = await fut
    #message = fut.get_result()
    #message = pickle.loads(data)
    end_time = time.time()

    print(f"Recvived data from previous request 1")
    #Message data, requestID
    total_time = end_time - server1_req_time[reqID]

    #del(socket1_map[reqID])
    print("Sending 2", my_id2)
    server2_req_time[reqID] = time.time()

    asyncio.create_task( send2([encrypted_updated_weights, my_id2, reqID], 5008, 0, host_server) )                
 

async def send2(data, port, delay, host_server):
    #nserver.CreateClientSocket("localhost", 5006, 100000)
    if delay != 0:
        await asyncio.sleep(delay)        
    await asyncio.sleep(.2)

    ##set up udp
    global our_addr
    global server2
    global time_start_global

    not_done = True
    send_package = pickle.dumps(data)
    print("sending", len(send_package))

    reqID = data[2]

    nserver = server2

    #data = nserver.RecvFromNow()

    fut = asyncio.get_running_loop().create_future()
    pending2[reqID] = fut

    mean = 0.016153517920
    std_dev = 0.000201593520
    MABE_wait = random.gauss(mean, std_dev)

    mean = 0.000011554021
    std_dev = 0.000002528596
    time_wait = random.gauss(mean, std_dev)

    mean = 0.000012840250
    std_dev = 0.000005130293
    time_wait += random.gauss(mean, std_dev)   


    time_wait += MABE_wait

    #Simulated LLM task
    time_wait += 5.0

    await asyncio.sleep(time_wait)

    server2.ClientSend(send_package)

    message = await fut
    #message = fut.get_result()
    
    #message = pickle.loads(data)
    end_time = time.time()            
    print(f"Recvived data from previous request 2")
    #Message data, requestID
    reqID = message[2]
    total_time = end_time - server2_req_time[reqID]


    streamID = req_map[reqID]
    mes = data_map[reqID]

    print("ReplyBack 2")
    time_end_now = time.perf_counter()

    
    with open("TimedReply_finished.txt", "a") as f:
        f.write(f"{time_end_now- time_start_global}\n")
    host_server.ServerSend(streamID, mes)  

                
async def receiver(sock, pend):
    while True:
        data, stream_id = await asyncio.to_thread(sock.RecvFrom)  # blocking, off event loop
        if(data != b''):
            msg = pickle.loads(data)
            reqID = msg[2]
            fut = pend.pop(reqID, None)
            print("Got data")
            if fut:
                fut.set_result(msg) 


# runs continiously to ensure the list of things to be aggregated gets done
def trainerOnce(client_id, client_weights):
    ###
    #check if there is work to be done
    global client_keys
    global global_weights
    global epochs
    global epoch
    global_weights1 = global_weights
    #print(client_keys[0][0],  client_keys[0][1])
    time_s = time.time()
    cipher = Cipher(algorithms.AES(client_keys[client_id][0]), modes.CBC(client_keys[client_id][1]), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_weights = decryptor.update(client_weights) + decryptor.finalize()
    client_weight = pickle.loads(unpadder.update(decrypted_weights) + unpadder.finalize())        
    
    print("Lets go")
    #make sure our training is not finished yet
    if epoch <= epochs:
        epoch +=1
        print("Starting aggregation")

        global_weights1 = average_weights([global_weights1, client_weight])
        processed.append([global_model, int(epochs + 1),client_id])
        print("done aggregating")
    time_e = time.time()
    print("Proccess Time: ", time_e - time_s)
    processed_list = [global_model, int(epochs + 1),client_id]
    return processed_list

def first_bind(server):
    while(True):
        #print("send")
        send_package = b'no id' + encrypted_key_bytes + iv
        print(iv)
        server.ClientSendMessage(send_package, len(send_package))

        data, _ = server.RecvFrom()
        print("Got data")
        if(data == b'turn'):
            print("turned away")
            continue
        message = pickle.loads(data)
        print(message)
        #if it is a valid sting move on
        if(isinstance(message,list)):
            return message
      
async def main():
    ###In case we wish to do funky port switches late

    #host = server  # Listen on all available interfaces
    #port = por # Replace with the desired port number

    # spin up a thread for the cclient handler and trainer
    global my_id1
    global my_id2

    server1.CreateClientSocket("20.84.110.81", 5007, 1000)
    print("SSS")
    global_info = first_bind(server1)
    my_id1 = global_info[2]
    print(my_id1)


    server2.CreateClientSocket("172.172.235.2", 5008, 1000)
    global_info = first_bind(server2)
    my_id2 = global_info[2]
    asyncio.create_task(receiver(server1, pending1))
    asyncio.create_task(receiver(server2, pending2))
    await handle_client()
    print("in main")

                         



#grpc 
if __name__ == '__main__':
    start_time = time.time()

    # define paths
    args = args_parser()
    exp_details(args)

    device =  'cpu'
    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
    server1 = msquic.MSQuicSocket()
    server2 = msquic.MSQuicSocket()

    my_id1 = None
    my_id2 = None

    # BUILD MODEL
    if args.model == 'cnn':
        # Convolutional neural netork
        if args.dataset == 'mnist':
            global_model = CNNMnist(args=args)
        elif args.dataset == 'fmnist':
            global_model = CNNFashion_Mnist(args=args)
        elif args.dataset == 'cifar':
            global_model = CNNCifar(args=args)

    elif args.model == 'mlp':
        # Multi-layer preceptron
        img_size = train_dataset[0][0].shape
        len_in = 1
        for x in img_size:
            len_in *= x
            global_model = MLP(dim_in=len_in, dim_hidden=64,
                               dim_out=args.num_classes)
    else:
        exit('Error: unrecognized model')
    

    # Set the model to train and send it to device.
    global_model.to(device)
    global_model.train()

    # copy weights
    global_weights = global_model.state_dict()
    epoch = 0
    # Training
    train_loss, train_accuracy = [], []
    val_acc_list, net_list = [], []
    cv_loss, cv_acc = [], []
    print_every = 2
    val_loss_pre, counter = 0, 0
    epochs = 10*args.num_users
    print("we made it here")

    #begin the network loop
    #main()
    asyncio.run(main())



