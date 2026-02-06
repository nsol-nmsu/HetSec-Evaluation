import os
import copy
import time
import pickle
import numpy as np
from tqdm import tqdm
import socket
import torch
from tensorboardX import SummaryWriter
from network import Network
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details

def connect(addr, client):
    client.connect(addr)
    data = b""
    while True:
        data_chunk = client.recv(2048)
        if not data_chunk :
            break
        else:
            data += data_chunk
    return pickle.loads(data)

def break_pickle_file(client_socket, data_pickle):
    chunk_size = 2048  # Adjust the buffer size
    #data_pickle = pickle.dumps(range())
    for i in range(0, len(data_pickle), chunk_size):
        client_socket.send(data_pickle[i:i+chunk_size])

def send(addr, client, data):
    client.connect(addr)
    break_pickle_file(client, pickle.dumps(data)) 
    #client.close()
    client.send(b'complete file sent')
    print("I have sent the entire update")
    data = b""
    while True:
        data_chunk = client.recv(2048)
        if(data_chunk[-11:] == b'update_sent'):
            data += data_chunk[:-11]
            break
        else:
            data += data_chunk
    
    return pickle.loads(data)

if __name__ == '__main__':
    start_time = time.time()

    # define paths
    path_project = os.path.abspath('..')
    logger = SummaryWriter('../logs')
    args = args_parser()
    exp_details(args)

    if args.gpu_id:
        torch.cuda.set_device(args.gpu_id)
    device = 'cuda' if args.gpu else 'cpu'

    # load dataset and user groups
    train_dataset, test_dataset, user_groups = get_dataset(args)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = "127.0.0.1"
    port = 5553
    addr = (server, port)

    global_info = connect(addr, client) 
    #n = Network()
    client.close()
    #global_info = n.connect()
    global_model = global_info[0]
    global_model.train()
    # copy weights
    global_model.to(device)
    global_weights = global_model.state_dict()

    #self.client_port = 5553
    #self.global_model = self.connect()
    #self.client.bind((server,port))
    time.sleep(10)
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
        local_model = LocalUpdate(args=args, dataset=train_dataset, idxs=user_groups[idx], logger=logger)
        w, loss = local_model.update_weights(model=copy.deepcopy(global_model), global_round=global_epoch)
        updated_weights = w
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        global_info = send(addr, client, updated_weights)
        global_weights = global_info[0]
        global_model.to(device)
        global_epoch = global_info[1]

        
        #client_model.load_state_dict(w)
        
