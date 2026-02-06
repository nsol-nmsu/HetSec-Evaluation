import os
import time
import random
import socket
import json
import asyncio
import ssl 
from attest_util import verify_peer_cert_via_qve
from snp_util import verify_report_via_tcp
import re
import base64

 
handshake_times = []
getcert_times = []
verify_times = []
send_resp_times = []
total_times = []

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
                  
EXPECTED_CLIENT_MEASUREMENT = "0x6A063BE9DD79F6371C842E480F8DC3B5C725961344E57130E88C5ADF49E8F7F6C79B75A5EB77FC769959F4AEB2F9401E"


#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 
async def recv_exact(reader, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = await reader.read(n - len(b))
        if not chunk:
            raise ConnectionError("eof")
        b += chunk
    return b

async def recv_frame(reader) -> bytes:
    n = int.from_bytes(await recv_exact(reader, 4), "big")
    return await recv_exact(reader, n)

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def send_frame(writer, blob: bytes):
    writer.write(len(blob).to_bytes(4, "big") + blob)
    await writer.drain()


async def main():

    i = 0
    await asyncio.sleep(4)
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
    ssl_ctx.load_cert_chain('client.crt', 'client.key')

    addr = "20.83.35.85"
    addr = "172.172.235.2"
    port = random.randrange(2550,5000)

    while(i < 11):


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

        t_verify  = time.perf_counter()

        await send_frame(writer, b'Ok')
        t_send_ok = time.perf_counter()  

        client_cert_der = pem_certfile_to_der("client.crt")
        await send_frame(writer, client_cert_der)

        server_data = await recv_frame(reader)
        t_done  = time.perf_counter()

        if not server_data:
            raise RuntimeError("server closed before sending OK")
        if server_data.rstrip(b"\n") != b"Ok":
            raise RuntimeError(f"server returned unexpected response:")    

        await writer.drain()    
        writer.close()
        await writer.wait_closed()

        print(
            "Client timings ms:",
            f"handshake={ (t_handshake - t0)*1000:.2f}",
            f"getcert={ (t_getcert - t_handshake)*1000:.2f}",
            f"verify={ (t_verify - t_getcert)*1000:.2f}",
            f"send_ok={ (t_send_ok - t_verify)*1000:.2f}",
            f"send+resp={ (t_done - t_verify)*1000:.2f}",
            f"total={ (t_done - t0)*1000:.2f}",
        )
        i+=1
        await asyncio.sleep(10)


if __name__ == '__main__':
    #main()
    asyncio.run(main())


