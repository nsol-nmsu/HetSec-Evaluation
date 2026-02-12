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
import ssl
import json
import random
import asyncio


idx_rounds = {}
idx_weights = [0]*10
id1 = 0
to_be_processed = queue.Queue()
processed = []
prev_clients = set()
awaiting_response = set()
chunkSize = 1000
client_keys = {}

#ReqID to Time sent
server1_req_time = {}
server2_req_time = {}

#ReqID to streamID
req_map = {}
data_map = {}
socket1_map = {}
socket2_map = {}

currentReqID = 1

ssl_context_client = ssl._create_unverified_context()
ssl_context_client.load_verify_locations('certificate.pem') 
#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client(reader, writer):   
    global my_id1
    global my_id2
    global server1_req  
    global server2_req    
    global currentReqID    
    global global_weights

    client_data = await read(reader)

    if client_data == "" or client_data == b'':
        return
    message = 0
    try:
        message = pickle.loads(client_data)
    except:
        message = 0
        print("Not a message")

    print("in the Handle")

    flag = True
    #check if client is wanting their waits and is a valid client

    #if our client had no ID get them set up
    if client_data[:5] == b'no id':
        global id1

        print(f"New Client joins Id:{id1}")
        prev_clients.add(id1)
        global_pickle = pickle.dumps([global_model, 0, id1])
        id1 = id1 + 1
        print(len(global_pickle)) 
        chunks = len(global_pickle)/1024
        if ( (chunks - int(chunks)) > 0 ):
            chunks =str( int(chunks) + 1 )
        else:
            chunks = str(int(chunks))
        print (chunks.encode() + b'\n')
        writer.write(chunks.encode()+ b'\n')            
        await writer.drain()

        writer.write(bytes(global_pickle))#, len(global_pickle))
        await writer.drain()
        writer.close()
        await writer.wait_closed()            
        print("Sent")

    # if the client is not asking for an id, nor is it asking for its data, we can assume it has just sent its weights,so we add them to the line            
    else:
        print(f"Returning Client {message[1]}")
        mes = pickle.dumps([global_model, message[2]]) 

        print("Sending 1", my_id1)
        reqID = currentReqID
        currentReqID+=1

        server1_req_time[reqID] = time.perf_counter()
        data_map[reqID] = mes
        await send([global_model, my_id1, reqID], [global_model, my_id2, reqID], 0.002, writer) 


    #after resolving client, check if any clients tried to contact us during the loop

async def send(data1, data2, delay, host_server):
    global our_addr
    global ssl_context_client    
    if delay != 0:
        await asyncio.sleep(delay)    #0.002    

    ##set up udp


    not_done = True
    send_package = pickle.dumps(data1)
    print("sending")


    reader1, writer1 = await asyncio.open_connection(
       "20.84.110.81", 5007, ssl=ssl_context_client
    )    

    reader2, writer2 = await asyncio.open_connection(
       "172.172.235.2", 5008, ssl=ssl_context_client
    )        

    chunks = len(send_package)/1024 
    if ( (chunks - int(chunks)) > 0 ):
        chunks =str( int(chunks) + 1 )
    else:
        chunks = str(int(chunks))   

    writer1.write(chunks.encode()+ b'\n')
    await writer1.drain()
    writer1.write(send_package)
    await writer1.drain()

    send_package = pickle.dumps(data2)
    chunks = len(send_package)/1024 
    if ( (chunks - int(chunks)) > 0 ):
        chunks =str( int(chunks) + 1 )
    else:
        chunks = str(int(chunks))   

    writer2.write(chunks.encode()+ b'\n')
    await writer2.drain()
    writer2.write(send_package)
    await writer2.drain()    

    data1 = await read(reader1)
    data2 = await read(reader2)

    message = pickle.loads(data1)
    reqID = message[2]
    end_time = time.perf_counter()            
    total_time = end_time - server1_req_time[reqID]

    with open("s1_time_tls_para.txt", "a") as f:
        f.write(f"{total_time}\n")

    mes = data_map[reqID]

    #print("ReplyBack")
    chunks = len(mes)/1024
    if ( (chunks - int(chunks)) > 0 ):
        chunks =str( int(chunks) + 1 )
    else:
        chunks = str(int(chunks))   

    host_server.write(chunks.encode()+ b'\n')
    await host_server.drain()

    host_server.write(mes)
    host_server.close()
    await host_server.wait_closed()     
             
async def first_bind(reader, writer):
    while True: 

        send_package = b'1\n' + b'no id'
        writer.write(send_package)
        await writer.drain()
 
        
        data = await read(reader)

        print("Got data", len(data))
        if(data == b'turn'):
            print("turned away")
            continue
        message = pickle.loads(data)
        print(message)
        #if it is a valid sting move on
        if(isinstance(message,list)):
            return message
      
                         

async def read(reader):
    data = b''
    chunks = await reader.readline()
    chunks = int(chunks[:-1])
    for chunk in range(chunks):
        data += await reader.read(1024)
    return data

async def main():
    ###In case we wish to do funky port switches late

    #host = server  # Listen on all available interfaces
    #port = por # Replace with the desired port number

    # spin up a thread for the cclient handler and trainer
    global my_id1
    global my_id2
    global ssl_context_client

 
    reader_c1, writer_c1 = await asyncio.open_connection(
       "20.84.110.81", 5007, ssl=ssl_context_client
    )    
    global_info = await first_bind(reader_c1, writer_c1)
    my_id1 = global_info[2]
    print(my_id1)


    reader_c2, writer_c2 = await asyncio.open_connection(
       "172.172.235.2", 5008, ssl=ssl_context_client
    )    
    global_info = await first_bind(reader_c2, writer_c2)
    my_id2 = global_info[2]

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('certificate.pem', 'key.pem')
    
    host = "127.0.0.1"
    host = socket.gethostname()

    port = 5006
    server = await asyncio.start_server(
        handle_client, host, port, ssl=ssl_context
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()



#grpc 
if __name__ == '__main__':
    start_time = time.perf_counter()

    # define paths
    args = args_parser()
    exp_details(args)

    device =  'cpu'
    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
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


