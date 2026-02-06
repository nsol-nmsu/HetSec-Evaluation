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
import msquic
##Our clients Id, and backoff for denial
my_id =1500
backoff = 2
# remove all the hard wiring and fix import export stuff
chunkSize = 1368
key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
padder = padding.PKCS7(128).padder()
encrypted_key_f = open('encrypt.json')
encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
print(key)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#ALMOST DO A COPY AND PASTE OF THE SERVER VERSION OF THIS TO DO RUDP ON CLIENT SIDE
encryptor = cipher.encryptor()

#bind at an adress, grab each packet, accept our ID as a client
#set up udp
def first_bind():
    while(True):
        #print("send")
        send_package = b'no id' + encrypted_key_bytes + iv
        print(iv)
        server.ClientSendMessage(send_package, len(send_package))

        data = server.RecvFrom()
        if(data == b'turn'):
            print("turned away")
            continue
        message = pickle.loads(data)
        print(message)
        #if it is a valid sting move on
        if(isinstance(message,list)):
            return message

    return data
  
#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 
#bind to server, send them our weights, wait for our turn to receive data in aggregation q
def send(data):
    ##set up udp
    global our_addr
    send_package = pickle.dumps(data)
    server.ClientSend(send_package)
    print("I have sent the entire update")

def ask_for_weights():
    ##set up udp
    global backoff
    server = msquic.MSQuicSocket()
    server.CreateClientSocket("gtsz2.eastus.cloudapp.azure.com", 5006)
    while(True):
        #print(int.from_bytes(my_id.to_bytes()))
        x = 0
        total = 1
        message = pickle.dumps(my_id)
        print("Myid:", my_id)
        server.ClientSend(message)

        data = server.RecvFrom()

        if data == b'deny':
            print("I was denied")
            return deny_send()        
        if(data != b'turn'):
            break
        print("turned away")


    
    print("got my things back from server")
    backoff = 2
    m = pickle.loads(data)
    #if it is a valid sting move on
    if(isinstance(m,list)):
        return m    
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
    
    server = msquic.MSQuicSocket()
    addr = "128.123.63.242"
    port = random.randrange(2550,5000)

    our_addr = (addr, port)
    #print("bind") 
    start_time = time.time()
    server.CreateClientSocket("gtsz2.eastus.cloudapp.azure.com", 5006)
    global_info = first_bind()
    end_time = time.time()
    print("Time for initial connection: ", end_time - start_time) 


    #print("bound") 
    #n = NetworkTCP()
    #global_info = n.bind()
    my_id = global_info[2]
    #print("ID: ", my_id)
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
        #print(f'\n | Local Training Round : {epoch+1} |\n')
        local_model = LocalUpdate(args=args, dataset=train_dataset, idxs=user_groups[idx])
        w, loss = local_model.update_weights(model=copy.deepcopy(global_model), global_round=global_epoch)
        updated_weights = w
        start_time = time.time()
        server = msquic.MSQuicSocket()
        server.CreateClientSocket("gtsz2.eastus.cloudapp.azure.com", 5006)
        padded_updated_weights = padder.update(pickle.dumps(w)) + padder.finalize()
        encrypted_updated_weights = encryptor.update(padded_updated_weights) + encryptor.finalize()        
        send([encrypted_updated_weights, my_id])
        end_time = time.time()
        data = server.RecvFrom()
        #print("asking for them back", my_id)
        time.sleep(.02)
        start_time1 = time.time()  
        global_info = ask_for_weights()
        end_time1 = time.time()
        #print("we are here")
        print("Time to send weights: ", end_time - start_time) 
        print("Time to recieve weights: ", end_time1 - start_time1)   
        print("Total time sending and recieving weights: ", end_time1 - start_time)           
        global_weights = global_info[0]
        global_model.to(device)
        global_epoch = global_info[1]

        
        #server_model.load_state_dict(w)
        
