import os
import copy
import time
import pickle
import numpy as np
import random
from tqdm import tqdm
import socket
import torch
from network import Network
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
##Our clients Id, and backoff for denial
my_id =1000
backoff = 2

def process_recieved(client):
    data = b""
    while True:
        data_chunk = client.recv(2048)
        if(data_chunk[-18:] == b'complete file sent'):
            data += data_chunk[:-18]
            print("received all")
            return pickle.loads(data)        
        if(data_chunk[-11:] == b'update_sent'):
            data += data_chunk[:-11]
            return pickle.loads(data)        
        else:
            data += data_chunk
    
def connect(addr, client):
    client.send(b'no id')
    data = process_recieved(client)
    return data

## break down the pickle file and send to server

def break_pickle_file(client_socket, data_pickle):
    chunk_size = 2048  # Adjust the buffer size
    for i in range(0, len(data_pickle), chunk_size):
        client_socket.send(data_pickle[i:i+chunk_size])
    client_socket.send(b'complete file sent')
    
#bind to server, send them our weights, wait for our turn to receive data in aggregation q
def send(addr, client, data):
    client.connect(addr)
    break_pickle_file(client, pickle.dumps(data)) 
    print("I have sent the entire update")

def ask_for_weights(s):
    ##set up udp
    while(True):
        print(my_id.to_bytes(2, byteorder="big"))
        #print(int.from_bytes(my_id.to_bytes()))
        s.send(my_id.to_bytes(2, byteorder="big"))

        data = process_recieved(s)
        if(data != b'turn'):
            break
    
    print("got my things back from server")
    return data

def deny_send():
    global backoff
    time.sleep(1*backoff)
    backoff = backoff**2
    return ask_for_weights()


if __name__ == '__main__':

    # define paths
    args = args_parser()
    exp_details(args)
    device = 'cpu'

    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)

    server = "127.0.0.1"
    server = "gtsz2.eastus.cloudapp.azure.com"

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ssl_cert = "../certificate.pem"
    ssl_context.load_verify_locations(ssl_cert)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client =  ssl_context.wrap_socket(client, server_hostname=server)

    port = 5000
    addr = (server, port)
    #client.bind((HOST, PORT))
    start_time = time.time()
    client.connect(addr)
    global_info = connect(addr, client) 
    end_time = time.time()
    client.close()

    print("Time for initial connection: ", end_time - start_time) 
    #n = Network()
    #global_info = n.bind()
    my_id = global_info[2]
    global_model = global_info[0]
    global_model.train()
    # copy weights
    global_model.to(device)
    global_weights = global_model.state_dict()

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
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = ssl_context.wrap_socket(client, server_hostname=server)  
        print("reconnect")   
        start_time = time.time()
        send(addr, client, [updated_weights, my_id])
        end_time = time.time()
        print("asking for them back")
        start_time1 = time.time()
        global_info = ask_for_weights(client)
        end_time1 = time.time()
        print("Time to send weights: ", end_time - start_time) 
        print("Time to recieve weights: ", end_time1 - start_time1)   
        print("Total time sending and recieving weights: ", end_time1 - start_time)   

        global_weights = global_info[0]
        global_model.to(device)
        global_epoch = global_info[1]

        
        #server_model.load_state_dict(w)
        
