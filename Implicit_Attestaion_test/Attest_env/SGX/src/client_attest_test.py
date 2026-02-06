import os
import time
import random
import socket
import json
import asyncio
import ssl 
from attest_util import verify_peer_cert_via_qve
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
                  


#assures that packets are not dropping, if they are we begin to resend the ones that dropped
 

def chunks_for_len(n: int) -> bytes:
    chunks = (n + 1023) // 1024
    return (str(chunks).encode() + b"\n")

async def write_framed(writer, blob: bytes):
    writer.write(chunks_for_len(len(blob)))
    await writer.drain()
    writer.write(blob)
    await writer.drain()

async def main():

    i = 0
    time.sleep(4)
    while(i < 11):
        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # we verify via RA-TLS after handshake
        ssl_ctx.load_cert_chain('client.crt', 'client.key')
    
        addr = "20.83.35.85"
        addr = "57.154.240.53"
        port = random.randrange(2550,5000)

        t0 = time.perf_counter()
        reader, writer = await asyncio.open_connection(
        addr, 5007, ssl=ssl_ctx, family=socket.AF_INET
        ) 
        t_handshake = time.perf_counter()

        sslobj = writer.get_extra_info("ssl_object")
        server_cert_der = sslobj.getpeercert(binary_form=True)
        t_getcert  = time.perf_counter()

        try:
            out = verify_peer_cert_via_qve(server_cert_der, "127.0.0.1", 7777)
        except Exception as e:
            print(f"Server attestation exception: {e}")
            writer.close()
            await writer.wait_closed()
            return

        # Policy: accept rc 0 or rc 1, reject rc < 0
        if int(out.get("rc", -1)) < 0:
            writer.close()
            await writer.wait_closed()
            return

        t_verify  = time.perf_counter()

        client_cert_der = pem_certfile_to_der("client.crt")
        await write_framed(writer, client_cert_der)

        server_data = await reader.readline()
        t_done  = time.perf_counter()

        if not server_data:
            raise RuntimeError("server closed before sending OK")
        if server_data.rstrip(b"\n") != b"OK":
            raise RuntimeError(f"server returned unexpected response: {ok!r}")    

        writer.close()
        await writer.wait_closed()

        print(
            "Client timings ms:",
            f"handshake={ (t_handshake - t0)*1000:.2f}",
            f"getcert={ (t_getcert - t_handshake)*1000:.2f}",
            f"verify={ (t_verify - t_getcert)*1000:.2f}",
            f"send+resp={ (t_done - t_verify)*1000:.2f}",
            f"total={ (t_done - t0)*1000:.2f}",
        )
        i+=1


if __name__ == '__main__':
    #main()
    asyncio.run(main())


