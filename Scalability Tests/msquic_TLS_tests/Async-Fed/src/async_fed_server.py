import os
import copy
import time
import pickle
import numpy as np
from tqdm import tqdm
import socket
import torch
from tensorboardX import SummaryWriter
from options import args_parser
from update import LocalUpdate, test_inference
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar
from utils import get_dataset, average_weights, exp_details

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
    
    server = "127.0.0.1"
    port = 5553

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((server, port))
    except socket.error as e:
        str(e)

    s.listen(2)
    # Set the model to train and send it to device.
    global_model.to(device)
    global_model.train()

    # copy weights
    global_weights = global_model.state_dict()

    # Training
    train_loss, train_accuracy = [], []
    val_acc_list, net_list = [], []
    cv_loss, cv_acc = [], []
    print_every = 2
    val_loss_pre, counter = 0, 0

idx_rounds = {}
idx_weights = [0]*10

def break_pickle_file(client_socket, data_pickle):
    chunk_size = 2048  # Adjust the buffer size
    #data_pickle = pickle.dumps(range())
    for i in range(0, len(data_pickle), chunk_size):
        client_socket.send(data_pickle[i:i+chunk_size])
    #client_socket.send(pickle.dumps("end of pickle"))

epochs = 10*args.num_users
for client in range(args.num_users):
    conn, addr = s.accept()
    print("New Client joins", addr)
    global_pickle = pickle.dumps([global_model, 0])
    break_pickle_file(conn, global_pickle)
    conn.close()

for epoch in tqdm(range(epochs)):
    #global_pickle = pickle.dumps(global_model)
    #conn, addr = s.accept()
    #print("New Client joins", addr)
        #a = [3,2]
        #conn.send(pickle.dumps(a))
    #global_pickle = pickle.dumps([global_model, epoch])
    #break_pickle_file(conn, global_pickle)
    #conn.close()
    conn, addr = s.accept()
    #conn.send(pickle.dumps("end of pickle"))
    #print(len(pickle.dumps(global_model)))
    #global_info = [global_model, int(epoch)]
    #conn.send(global_pickle)
    client_byte= b""
    while True:
        try:
            data_byte = conn.recv(2048)
            if(data_byte[-18:] == b'complete file sent'):
                client_byte += data_byte[:-18]
                break
            else:
                client_byte += data_byte
        except:
            print("done in except block")
            #iif not data_byte :
            break
            #else:
            #client_byte += data_byte

    client_weights = pickle.loads(client_byte)
    global_weights = average_weights([global_weights, client_weights])
    conn.send(pickle.dumps([global_model, int(epoch + 1)]))
    conn.send(b"update_sent")
    conn.close()
