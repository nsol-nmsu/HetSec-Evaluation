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

import subprocess
idx_rounds = {}
idx_weights = [0]*10
id1 = 0
to_be_processed = queue.Queue()
processed = []
prev_clients = set()
awaiting_response = set()
chunkSize = 1000
client_keys = {}
#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
def handle_client():      
    server = "127.0.0.1"
    server = socket.gethostname()
    por = 5005

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((server, por))
    except socket.error as e:
        str(e)

    s.listen(2)


    print("in the Handle")
    while True:

        conn, addr = s.accept()

        #wait here for some data to be recieved and processed
        client_data, awaiting_response = NetworkTCP.RUDPrecv(conn)
        message = 0
        try:
            message = pickle.loads(client_data)
        except:
            message = int.from_bytes(client_data, byteorder='big') 
        #process_recieved()
        to_remove = []

        print("in the Handle")

        flag = True
        #check if client is wanting their waits and is a valid client

        #if our client had no ID get them set up
        if client_data[:5] == b'no id':
            global id1
            global client_keys
            print(f"New Client joins {addr} Id:{id1}")

            prev_clients.add(id1)
            encrypted_key_string = client_data[5:37].decode()
            #decrypted_key = bytes.fromhex(subprocess.run("./src/MABE-decrypt", capture_output=True, text=True).stdout[2:])
            #print(decrypted_key)
            decrypted_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
            #iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
            #print(client_data[-16:])
            client_keys[id1] = [decrypted_key, client_data[-16:]]
            #print(prev_clients)
            global_pickle = pickle.dumps([global_model, 0, id1])
            id1 = id1 + 1
            #print("ds", addr)
            NetworkTCP.break_data(conn, global_pickle)

        elif(( not isinstance(message, list) ) and (message in prev_clients)):
            print(f"trying to give client {message} their weights")

            #check if trainer() has finished processing their weights
            for finish in processed:
                if(finish[2] == message):
                    NetworkTCP.break_data(conn, pickle.dumps(finish))
                    print("finished sending weights")
                    flag = False
                    to_remove.append(processed.index(finish))

            #if the clients data is not ready, begin backoff  
            if(flag):
                print(f"denied {message}")
                NetworkTCP.break_data(conn, b'deny')

            #remove finished and sent data from the waiting list
            for removal in to_remove:
                del processed[removal]                   

        # if the client is not asking for an id, nor is it asking for its data, we can assume it has just sent its weights,so we add them to the line
        else:
            print(f"Returning Client {message[1]}")
            to_be_processed.put(message)

        #after resolving client, check if any clients tried to contact us during the loop



# runs continiously to ensure the list of things to be aggregated gets done
def trainer():
    ###
    while True:
        #check if there is work to be done
        if not to_be_processed.empty():
            client_weights = to_be_processed.get()
            global client_keys
            global global_weights
            global epochs
            global epoch
            cipher = Cipher(algorithms.AES(client_keys[client_weights[1]][0]), modes.CBC(client_keys[client_weights[1]][1]))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_weights = decryptor.update(client_weights[0]) + decryptor.finalize()
            client_weight = pickle.loads(unpadder.update(decrypted_weights) + unpadder.finalize())
            print(client_weight)
            #make sure our training is not finished yet
            if epoch <= epochs:
                epoch +=1
                print("Starting aggregation")

                global_weights = average_weights([global_weights, client_weight])
                processed.append([global_model, int(epochs + 1),client_weights[1]])
                print("done aggregating")
                
        else:
                time.sleep(.25)
                  
def main():
    ###In case we wish to do funky port switches late

    #host = server  # Listen on all available interfaces
    #port = por # Replace with the desired port number

    # spin up a thread for the cclient handler and trainer
    client_handler_thread = threading.Thread(target=handle_client)
    trainer_thread = threading.Thread(target=trainer)

    trainer_thread.start()
    client_handler_thread.start()

    # these threads should never finish as they are infinite looping, but just in case
    trainer_thread.join()
    client_handler_thread.join() 

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
    main()


