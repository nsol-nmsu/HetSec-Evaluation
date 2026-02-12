import os, subprocess, tempfile, json, socket, struct
import hashlib
import base64

TDX_TEE_TYPE = 0x00000081


def gen_tdx_quote_bytes( config_path: str ) -> bytes:

    cmd = [
        "trustauthority-cli",
        "evidence",
        "--tdx",
        "--config", config_path,
        #"--no-verifier-nonce",
    ]        


    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError(p.stdout.decode("utf-8", "ignore"))

    json_string = ""
    if(p.stdout.decode("utf-8")[0] != "{"):
        splitString = p.stdout.decode("utf-8").split("\n")

        json_string = splitString[1]
        for each in splitString[2:]:
            json_string = json_string + '\n' + each

    else:
        json_string = p.stdout.decode("utf-8")

    evidence = json.loads(json_string)
    quote_b64 = evidence["tdx"]["quote"]  # matches your jq path: .tdx.quote

    return base64.b64decode(quote_b64) 


def _recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            raise RuntimeError("socket closed")
        b += x
    return b

def verify_quote_tcp(host: str, port: int, quote: bytes) -> dict:
    """
    Send raw quote bytes to the local QvE verifier daemon over TCP and return its JSON.
    Protocol: [u32 len_be][quote bytes] -> [u32 rc_be][u32 json_len_be][json bytes]
    """    
    with socket.create_connection((host, port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(struct.pack("!I", len(quote)) + quote)
        rc = struct.unpack("!I", _recvn(s, 4))[0]
        jlen = struct.unpack("!I", _recvn(s, 4))[0]
        payload = _recvn(s, jlen) if jlen else b"{}"
    out = json.loads(payload.decode("utf-8"))
    out["rc_wire"] = int(rc)
    return out