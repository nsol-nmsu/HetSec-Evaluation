import os
import time
import random
import socket
import asyncio
import ssl 
from snp_attest_util import gen_report_bytes_bound_to_nonce, nonce_to_report_data_hex, verify_report_via_tcp
import re
import base64


EXPECTED_CLIENT_MEASUREMENT = "0x6A063BE9DD79F6371C842E480F8DC3B5C725961344E57130E88C5ADF49E8F7F6C79B75A5EB77FC769959F4AEB2F9401E"
start_times = {}
#bind at an adress, grab each packet, accept our ID as a client
#set up udp

async def recv_exact(reader, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = await reader.read(n - len(b))
        if not chunk:
            raise ConnectionError("eof")
        b += chunk
    return b


async def send_frame(writer, blob: bytes):
    writer.write(len(blob).to_bytes(4, "big") + blob)
    await writer.drain()

async def recv_frame(reader) -> bytes:
    n = int.from_bytes(await recv_exact(reader, 4), "big")
    return await recv_exact(reader, n)




_PEM_RE = re.compile(
    r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----\s+"
    r"([A-Za-z0-9+/=\s]+?)"
    r"-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S,
)

def pem_certfile_to_der(path: str) -> bytes:
    data = open(path, "rb").read()
    text = data.decode("ascii", errors="ignore")
    m = _PEM_RE.search(text)
    if not m:
        raise ValueError(f"No PEM certificate block found in {path}")
    b64 = re.sub(r"\s+", "", m.group(1))
    return base64.b64decode(b64)
             

async def read(reader):
    data = b''
    chunks = await reader.readline()
    chunks = int(chunks[:-1])
    for chunk in range(chunks):
        data += await reader.read(1024)
    return data
#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 



async def main():

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
    ssl_ctx.load_cert_chain('client.crt', 'client.key')
   
    addr = "20.83.35.85"
    addr = "172.172.235.2"
    port = random.randrange(2550,5000)

    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(
       addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
    ) 
    t_handshake = time.perf_counter()

    server_report = await recv_frame(reader)
    t_getcert  = time.perf_counter()

    out = verify_report_via_tcp(
        "20.84.110.81", 7777,
        server_report,
        expected_measurement_hex=EXPECTED_CLIENT_MEASUREMENT,
        expected_report_data_hex=None,
        endorser="vcek",
    )
    t_verify = time.perf_counter()    

    if not out.get("ok"):
        raise RuntimeError(f"server attestation failed: {out}")

    await send_frame(writer, b'Ok')
    t_send_ok = time.perf_counter()    

    #time.sleep(15)
    t_gen0 = time.perf_counter()    
    my_report = gen_report_bytes_bound_to_nonce(use_platform=True)
    t_gen1 = time.perf_counter()    

    await send_frame(writer, my_report)
    response = await recv_frame(reader)
    t_total = time.perf_counter() # finished mutual exchange

    if(response != b'Ok'):
        raise RuntimeError(f"attestation failed") 

    writer.close()
    await writer.wait_closed()

    print(
        "Client timings ms:",
        f"handshake={(t_handshake-t0)*1000:.2f}",
        f"recv_server_report={(t_getcert-t_handshake)*1000:.2f}",
        f"verify_server={(t_verify-t_getcert)*1000:.2f}",
        f"send_ok={(t_send_ok-t_verify)*1000:.2f}",
        f"gen_client_report={(t_gen1-t_gen0)*1000:.2f}",
        f"send_report+final={(t_total-t_send_ok)*1000:.2f}",
        f"total={(t_total-t0)*1000:.2f}",
    )    

if __name__ == '__main__':
    #main()
    asyncio.run(main())


