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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import json
import subprocess
import msquic
import asyncio

##Our clients Id, and backoff for denial
my_id =1500
backoff = 2
# remove all the hard wiring and fix import export stuff
chunkSize = 1368
key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
padder = padding.PKCS7(128).padder()
encrypted_key_f = open('encrypt1.json')
subprocess.run("./MABE-encrypt")
encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
print(key)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#ALMOST DO A COPY AND PASTE OF THE SERVER VERSION OF THIS TO DO RUDP ON CLIENT SIDE
encryptor = cipher.encryptor()
pending = {} 
start_times = {}
#bind at an adress, grab each packet, accept our ID as a client
#set up udp



reqs = 200
seg_size = reqs
def first_bind(server):
    while(True):
        #print("send")
        send_package = b'no id' + encrypted_key_bytes + iv
        print(iv)
        server.ClientSendMessage(send_package, len(send_package))
        print("Wait")

        data, _ = server.RecvFrom()

        print("Data")
        if(data == b'turn'):
            print("turned away")
            continue
        message = pickle.loads(data)
        print(message)
        #if it is a valid sting move on
        if(isinstance(message,list)):
            return message

#assures that packets are not dropping, if they are we begin to resend the ones that dropped
async def receiver_loop(sock):
    count1 = reqs
    while count1 > 0:
        data, _ = await asyncio.to_thread(sock.RecvFrom)

        msg = pickle.loads(data)

        # Assumption: response includes req_id in a stable position.
        # Adjust if needed. Based on current usage: [payload, req_id] or similar.
        req_id = msg[1] if isinstance(msg, list) and len(msg) > 1 else None
        fut = pending.pop(req_id, None)
        if fut and not fut.done():
            fut.set_result(msg)
        count1 = count1 - 1
            
#bind to server, send them our weights, wait for our turn to receive data in aggregation q
async def send(socket, data):

    send_package = pickle.dumps(data)

    req_id = data[2]

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    pending[req_id] = fut

    socket.ClientSend(send_package)
    message = ""

    print("sending")

    try:
        print("Wait")

        #message = await asyncio.wait_for(fut, timeout=200.0)
        data, _ = await asyncio.to_thread(socket.RecvFrom)
        print("Recv it", len(data))

        #message = pickle.loads(data)
    except asyncio.TimeoutError:
        pending.pop(req_id, None)
        with open("client_time.txt", "a") as f:
            f.write("timeout\n")
        return    

    start_time = start_times[req_id]
    end_time = time.perf_counter()    
    total_time = end_time - start_time
    #print("Time to send and Recv weights: ", end_time - start_time) 
    with open("client_time.txt", "a") as f:
        f.write(f"{total_time}\n")


async def main():
    start_time = time.perf_counter()
    count = 0
    # define paths
    args = args_parser()
    exp_details(args)
    device = 'cpu'

    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
    
    server = msquic.MSQuicSocket()
    addr = "20.83.35.85"
    #addr = "localhost"
    port = random.randrange(2550,5000)


    start_time = time.perf_counter()
    server.CreateClientSocket(addr, 5006, 1000)
    global_info = first_bind(server)
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

    
    print("done")

    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()    
    start_time3 = time.perf_counter()

    servers = []
    for each in range(0,seg_size):
        servers.append(msquic.MSQuicSocket())
        servers[each].CreateClientSocket(addr, 5006, 1000)


    padded_updated_weights = padder.update(pickle.dumps(global_model)) + padder.finalize()
    encrypted_updated_weights = encryptor.update(padded_updated_weights) + encryptor.finalize()
    
    #recv_task = asyncio.create_task(receiver_loop(server))

    
    async with asyncio.TaskGroup() as tg:
        while count < reqs:
            #await asyncio.sleep(.005)
            count += 1
            print("Req: " , count)

            start_time = time.perf_counter()
            start_times[count] = start_time

            server_id = (count - 1) % seg_size
 
            tg.create_task(send(servers[server_id], ["Message", my_id, count]))
 

if __name__ == '__main__':
    #main()
    asyncio.run(main())

