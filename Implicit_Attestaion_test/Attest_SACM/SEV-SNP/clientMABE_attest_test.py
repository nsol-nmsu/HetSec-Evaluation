import os
import time
import random
import asyncio
import ssl 
import re
import base64
import msquic
import subprocess
import json

async def main():

    server = msquic.MSQuicSocket()
    addr = "20.40.217.126"
    port = 5007

    server.CreateClientSocket(addr, port, 1000)
    
    t0 = time.perf_counter()
    encrypted_key_f = open('encrypt1.json')
    subprocess.run("./MABE-encrypt", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    encrypted_key_bytes = json.dumps(json.load(encrypted_key_f)).encode()    
    t_mabe_encrypt = time.perf_counter()

    server.ClientSendMessage(encrypted_key_bytes, len(encrypted_key_bytes))
    t_send_challenge = time.perf_counter()

    challenge_response, _ = server.RecvFrom()
    t_recv_proof = time.perf_counter()

    key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")

    if(challenge_response != key):
        raise RuntimeError(f"attestation failed") 

    server.ClientSendMessage(b'Ok', len(b'Ok'))
    t_send_ok = time.perf_counter()

    challenge, _ = server.RecvFrom()
    t_recv_challenge = time.perf_counter()

    encrypted_key_string = challenge.decode()

    keyBytes = subprocess.run("./MABE-decrypt", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t_mabe_decrypt = time.perf_counter()

    decrypted_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")

    server.ClientSendMessage(decrypted_key, len(decrypted_key))
    t_send_proof = time.perf_counter()

    response, streamID = server.RecvFrom()

    t_total = time.perf_counter()
    if(response != b'Ok'):
        raise RuntimeError(f"attestation failed") 


    print(
        "Client timings ms:",
        f"mabe_encrypt={(t_mabe_encrypt-t0)*1000:.2f}",
        f"send_challenge={(t_send_challenge-t_mabe_encrypt)*1000:.2f}",
        f"recv_proof={(t_recv_proof-t_send_challenge)*1000:.2f}",
        f"send_ok={(t_send_ok-t_recv_proof)*1000:.2f}",
        f"recv_challenge={(t_recv_challenge-t_send_ok)*1000:.2f}",
        f"mabe_decrypt={(t_mabe_decrypt-t_recv_challenge)*1000:.2f}",
        f"send_proof={(t_send_proof-t_mabe_decrypt)*1000:.2f}",
        f"total={(t_total-t0)*1000:.2f}",
    )    

if __name__ == '__main__':
    #main()
    asyncio.run(main())


