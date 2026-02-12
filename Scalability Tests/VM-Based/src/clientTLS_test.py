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
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details
import json
import subprocess
import asyncio
import ssl 

##Our clients Id, and backoff for denial
my_id =1500
backoff = 2

ssl_context_client = ssl._create_unverified_context()
ssl_context_client.load_verify_locations('certificate.pem') 
start_times = {}
#bind at an adress, grab each packet, accept our ID as a client
#set up udp
async def first_bind(reader, writer):
    while True: 

        send_package = b'1\n' + b'no id'
        writer.write(send_package)
        await writer.drain()
        #riter.close()
        #await writer.wait_closed() 
        
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
#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 
#bind to server, send them our weights, wait for our turn to receive data in aggregation q
async def send(data):
    ##set up udp
    not_done = True
    send_package = pickle.dumps(data)
    print("sending")
    addr = "20.83.35.85"
    #addr = "localhost"

    reader, writer = await asyncio.open_connection(
      addr, 5006, ssl=ssl_context_client
    ) 
    
    chunks = len(send_package)/1024
    if ( (chunks - int(chunks)) > 0 ):
        chunks =str( int(chunks) + 1 )
    else:
        chunks = str(int(chunks))   

    writer.write(chunks.encode()+ b'\n')
    await writer.drain()

    writer.write(send_package)
    await writer.drain()
    try:
        data = await read(reader)


        message = pickle.loads(data)

        start_time = start_times[message[1]]
        end_time = time.perf_counter()    
        total_time = end_time - start_time
        #print("Time to send and Recv weights: ", end_time - start_time) 
        with open("client_time_tls_para.txt", "a") as f:
            f.write(f"{total_time}\n")
    except:
        with open("client_time_tls_para.txt", "a") as f:
            f.write(f"{10000}\n")



async def main():
    start_time = time.perf_counter()
    count = 0
    # define paths
    args = args_parser()
    exp_details(args)
    device = 'cpu'

    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
    

    addr = "20.83.35.85"
    #addr = "localhost"
    #addr = "57.154.240.53"    
    port = random.randrange(2550,5000)

    print("Sending") 

    start_time = time.perf_counter()
    reader, writer = await asyncio.open_connection(
       addr, 5006, ssl=ssl_context_client
    ) 
    global_info = await first_bind(reader, writer)

    end_time = time.perf_counter()
    print("Time for initial connection: ", end_time - start_time) 
    my_id = global_info[2]
    print(my_id)

    global_model = global_info[0]
    global_model.train()

    global_model.to(device)
    global_weights = global_model.state_dict()

    # Training
    train_loss, train_accuracy = [], []
    val_acc_list, net_list = [], []
    cv_loss, cv_acc = [], []
    print_every = 2
    val_loss_pre, counter = 0, 0
    idx = 0
    global_epoch = global_info[1]
 
    #local_weights, local_losses = [], []
    #local_model = LocalUpdate(args=args, dataset=train_dataset, idxs=user_groups[idx])
    #w, loss = local_model.update_weights(model=copy.deepcopy(global_model), global_round=global_epoch)


    print("done")
 
    async with asyncio.TaskGroup() as tg:
        while count < 200:
            #await asyncio.sleep(.0067)
            count += 1
            print("Req: " , count)

            updated_weights = global_weights
            start_time = time.perf_counter()
            start_times[count] = start_time  

            tg.create_task(send(["Message", my_id, count]))
 

if __name__ == '__main__':
    #main()
    asyncio.run(main())


