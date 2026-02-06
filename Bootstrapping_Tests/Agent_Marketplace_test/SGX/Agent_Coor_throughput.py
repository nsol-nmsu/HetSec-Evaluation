import os
import time
import socket
import queue
import asyncio
import ssl
from attest_util_async import verify_peer_cert_via_qve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")
iv = bytes.fromhex("22dc9c199a5d430a95a4020b1348130a")
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()
encryptor = cipher.encryptor()    
with open("coorApp.py", 'r') as file:
    raw_file = file.read().encode("utf-8")
padded_file = padder.update(raw_file) + padder.finalize()
encrypted_file = encryptor.update(padded_file) + encryptor.finalize()     


total = 0
async def read_framed(reader):
    chunks = await reader.readline()
    if not chunks:
        return b""
    chunks = int(chunks[:-1])
    data = b""
    for _ in range(chunks):
        data += await reader.read(1024)
    return data

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def write_framed(writer, blob: bytes):
    writer.write(chunks_for_len(len(blob)))
    await writer.drain()
    writer.write(blob)
    await writer.drain()

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client(reader, writer):   
    global key
    global iv
    global encrypted_file
    global t_0
    global total

    if total == 0:
        t_0 = time.perf_counter()

    request = await read_framed(reader)

    t_verify1 = 0
    t_verify2 = 0

    response = None
    if request == b'Agent_Start':
        with open("bootApp.py", 'r') as file:
            response = file.read().encode("utf-8")
        response += b'Item' + encrypted_file



    elif request[0:12] == b'Agent_Attest':

        '''
        try:
            ver = await verify_peer_cert_via_qve(request[12:], "127.0.0.1", 7777)

        except Exception as e:
            print(f"Client attestation exception: {e}")
            writer.close()
            await writer.wait_closed()
            return
        '''
        await asyncio.sleep(.015981) # Average time for execution

        response = key + iv
        with open("userInfo.json", 'rb') as file:
            response += file.read()       
            
    await write_framed(writer, response)
    #writer.write(response)
    await writer.drain()
    t_resp = time.perf_counter()

    writer.close()
    await writer.wait_closed()

    if( request[0:12] == b'Agent_Attest'):
        total += 1
        if(total == 10000):
            print(f"{t_resp - t_0}, {total}")    
            total = 0

    
async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('server.crt', 'server.key')
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE   # IMPORTANT: ask for client cert
    
    host = "127.0.0.1"
    #host = socket.gethostname()
    host = "0.0.0.0"

    port = 5007
    server = await asyncio.start_server(
        handle_client, host, port, ssl=ssl_context, family=socket.AF_INET
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")    


    async with server:
        await server.serve_forever()

#grpc 
if __name__ == '__main__':
    asyncio.run(main())


