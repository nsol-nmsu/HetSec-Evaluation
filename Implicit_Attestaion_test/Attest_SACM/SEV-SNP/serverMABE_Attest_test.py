import os
import time
import queue
import asyncio
import ssl
import msquic
import subprocess

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client():   

    s = msquic.MSQuicSocket()
    s.CreateServerSocket(5007)

    while True:

        client_data = s.RecvAny()
        t0 = time.perf_counter()

        encrypted_key_string = client_data.decode()

        keyBytes = subprocess.run("./MABE-decrypt", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        t_mabe_decrypt = time.perf_counter()

        decrypted_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")

        s.ServerSend(streamID, decrypted_key)#, len(global_pickle))
        t_send_proof = time.perf_counter()

        response, streamID = await asyncio.to_thread(s.RecvAny)

        t_recv_ok = time.perf_counter()
        if(response != b'Ok'):
            raise RuntimeError(f"attestation failed") 

        subprocess.run("./MABE-encrypt", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        t_mabe_encrypt = time.perf_counter()

        s.ServerSend(streamID, encrypted_key_string)#, len(global_pickle))
        t_send_challenge = time.perf_counter()

        challenge_response, streamID = await asyncio.to_thread(s.RecvAny)
        t_recv_proof = time.perf_counter()

        if(challenge_response != decrypted_key):
            raise RuntimeError(f"attestation failed") 

        s.ServerSend(streamID, b'Ok')#, len(global_pickle))
        t_total = time.perf_counter()

        print(
            "Server timings ms:",
            f"mabe_decrypt={(t_mabe_decrypt-t0)*1000:.2f}",
            f"send_proof={(t_send_proof-t_mabe_decrypt)*1000:.2f}",
            f"recv_ok={(t_recv_ok-t_send_proof)*1000:.2f}",
            f"mabe_encrypt={(t_mabe_encrypt-t_recv_ok)*1000:.2f}",
            f"send_challenge={(t_send_challenge-t_mabe_encrypt)*1000:.2f}",
            f"recv_proof={(t_recv_proof-t_send_challenge)*1000:.2f}",
            f"total={(t_total-t0)*1000:.2f}",
        )


    
async def main():
    await handle_client()

#grpc 
if __name__ == '__main__':
    asyncio.run(main())

