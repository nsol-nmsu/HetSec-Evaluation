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
import asyncio
import ssl

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
    try:  
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

            writer.write(chunks.encode()+ b'\n')            
            writer.write(bytes(global_pickle))#, len(global_pickle))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            print("Sent")

        # if the client is not asking for an id, nor is it asking for its data, we can assume it has just sent its weights,so we add them to the line  
        else:
            print(f"Returning Client {message[1]}")

            send_package = pickle.dumps([message[0], "Req_1", message[2]])
            await send(send_package, writer, 0.005)

    except:
        print("Hello.")
        #after resolving client, check if any clients tried to contact us during the loop

async def send(data, writer, delay):
    if delay != 0:
        await asyncio.sleep(delay)        

    ##set up udp
    print("sending")

    chunks = len(data)/1024 
    if ( (chunks - int(chunks)) > 0 ):
        chunks =str( int(chunks) + 1 )
    else:
        chunks = str(int(chunks))    

    writer.write(chunks.encode()+ b'\n')
    await writer.drain()
    writer.write(bytes(data))#, len(global_pickle))
    await writer.drain()
    writer.close()
    await writer.wait_closed()
async def main():

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('certificate.pem', 'key.pem')

    host = "127.0.0.1"
    host = socket.gethostname()
    port = 5007
    server = await asyncio.start_server(
        handle_client, host, port, ssl=ssl_context
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()


async def read(reader):
    data = b''
    chunks = await reader.readline()
    chunks = int(chunks[:-1])
    for chunk in range(chunks):
        data += await reader.read(1024)
    return data


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
    asyncio.run(main())


