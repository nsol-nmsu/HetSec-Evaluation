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
import ctypes
from ctypes import (
    POINTER, byref, c_char_p, c_int, c_size_t, c_ubyte, c_void_p,
    create_string_buffer,
)
import asyncio

agent_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")

_HERE = os.path.dirname(os.path.abspath(__file__))
_libmabe = ctypes.CDLL(os.path.join(_HERE, "libmabe.so"))
_libmabe.mabe_ctx_create.argtypes = [c_char_p, c_char_p]
_libmabe.mabe_ctx_create.restype = c_void_p
_libmabe.mabe_ctx_free.argtypes = [c_void_p]
_libmabe.mabe_ctx_free.restype = None
_libmabe.mabe_encrypt_json_for_key32_files.argtypes = [
    c_void_p, c_char_p, c_char_p, c_char_p,
    POINTER(c_ubyte), c_char_p, c_size_t, POINTER(c_size_t),
]
_libmabe.mabe_encrypt_json_for_key32_files.restype = c_int
_libmabe.mabe_decrypt_key32_files.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_ubyte)]
_libmabe.mabe_decrypt_key32_files.restype = c_int

_mabe_ctx = _libmabe.mabe_ctx_create(b"a.param", b"public.json")
if not _mabe_ctx:
    raise RuntimeError("mabe_ctx_create failed")

_key_arr = (c_ubyte * 32).from_buffer_copy(agent_key)

def real_mabe_encrypt():
    buf = create_string_buffer(256 * 1024)
    out_len = c_size_t(0)
    rc = _libmabe.mabe_encrypt_json_for_key32_files(
        _mabe_ctx, b"Auth1.json", b"Auth2.json", b"Auth3.json",
        _key_arr, buf, ctypes.sizeof(buf), byref(out_len),
    )
    if rc != 0:
        raise RuntimeError(f"mabe_encrypt failed rc={rc} need={out_len.value}")
    return buf.value

def real_mabe_decrypt():
    out_key = (c_ubyte * 32)()
    rc = _libmabe.mabe_decrypt_key32_files(_mabe_ctx, b"encrypt.json", b"userInfo.json", out_key)
    if rc != 0:
        raise RuntimeError(f"mabe_decrypt failed rc={rc}")
    return bytes(out_key)

def real_sym_encrypt(data):
    c = Cipher(algorithms.AES(agent_key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()
    p = padding.PKCS7(128).padder()
    return e.update(p.update(data) + p.finalize()) + e.finalize()

def real_sym_decrypt(data):
    c = Cipher(algorithms.AES(agent_key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    u = padding.PKCS7(128).unpadder()
    plain = d.update(data) + d.finalize()
    return u.update(plain) + u.finalize()

with open("encrypt.json", "wb") as _f:
    _f.write(real_mabe_encrypt())


idx_rounds = {}
idx_weights = [0]*10
id1 = 0
to_be_processed = queue.Queue()
processed = []
prev_clients = set()
awaiting_response = set()
chunkSize = 1000
client_keys = {}
read_delay = 0.001

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client():      
    server = "127.0.0.1"
    #server = socket.gethostname()
    por = 5008

    s = msquic.MSQuicSocket()
    s.CreateServerSocket(por)
    
    server = msquic.MSQuicSocket()
    print("in the Handle")
    first = True
    while True:
        #wait here for some data to be recieved and processed
        await asyncio.sleep(read_delay)        
        try:
            client_data, streamID = s.RecvFromNow()
            #client_data, streamID = await asyncio.to_thread(s.RecvAny)
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

        print(client_data[:5])
        print(client_data[-10:])

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
                print(len(global_pickle)) 
                s.ServerSend(streamID, bytes(global_pickle))#, len(global_pickle))


            # if the client is not asking for an id, nor is it asking for its data, we can assume it has just sent its weights,so we add them to the line
            else:
                print(f"Returning Client {message[1]}")
                #s.ServerSendMessage(streamID, b'ack', len(b'ack'))
                processed_list = trainerOnce(message[1], message[0])
                mes = pickle.dumps(processed_list)
                
                #server = msquic.MSQuicSocket()
                #if first:
                #    server.CreateClientSocket("20.83.35.85", 5006, 10000)
                #    first = True
                
                send_package = pickle.dumps([mes, "Req_2", message[2]])

                asyncio.create_task( replySend(streamID, bytes(send_package), s ) )

                #s.ServerSend(streamID, bytes(send_package))
                #asyncio.create_task( send(send_package, server, 0.005) )

        except:
            print("Hello.")
        #after resolving client, check if any clients tried to contact us during the loop

async def replySend(streamID, data, sever):
    t0 = time.perf_counter()
    _ = real_mabe_decrypt()
    t1 = time.perf_counter()
    with open("mabe_decrypt_3.txt", "a") as f:
        f.write(f"{t1 - t0}\n")

    t2 = time.perf_counter()
    _enc_payload = real_sym_encrypt(data)
    _ = real_sym_decrypt(_enc_payload)
    t3 = time.perf_counter()
    with open("sym_time_3.txt", "a") as f:
        f.write(f"{t3 - t2}\n")

    sever.ServerSend(streamID, data)

async def send(data, cserver, delay):
    #nserver.CreateClientSocket("localhost", 5006, 100000)
    if delay != 0:
        await asyncio.sleep(delay)        

    ##set up udp
    print("sending")

    cserver.ClientSend(data)


# runs continiously to ensure the list of things to be aggregated gets done
def trainerOnce(client_id, client_weights):
    ###
    #check if there is work to be done
    global client_keys
    global global_weights
    global epochs
    global epoch
    print(client_keys[0][0],  client_keys[0][1])
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

        global_weights = average_weights([global_weights, client_weight])
        processed.append([global_model, int(epochs + 1),client_id])
        print("done aggregating")
    
    processed_list = [global_model, int(epochs + 1),client_id]
    return processed_list

    
      
async def main():
    ###In case we wish to do funky port switches late

    #host = server  # Listen on all available interfaces
    #port = por # Replace with the desired port number

    # spin up a thread for the cclient handler and trainer

    '''client_handler_thread = Process(target=handle_client)
    trainer_thread = Process(target=trainer)

    client_handler_thread.start()
    trainer_thread.start()

    # these threads should never finish as they are infinite looping, but just in case
    trainer_thread.join()
    client_handler_thread.join() '''
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


