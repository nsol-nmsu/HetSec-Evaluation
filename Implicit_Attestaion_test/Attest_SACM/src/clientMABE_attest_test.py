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

import ctypes
from ctypes import (
    c_char_p, c_void_p, c_int, c_size_t,
    POINTER, c_ubyte, create_string_buffer, byref
)

def load_mabe():
    lib = ctypes.CDLL("./libmabe.so")

    # ctx lifecycle
    lib.mabe_ctx_create.argtypes = [c_char_p, c_char_p]
    lib.mabe_ctx_create.restype = c_void_p
    lib.mabe_ctx_free.argtypes = [c_void_p]
    lib.mabe_ctx_free.restype = None

    # decrypt
    lib.mabe_decrypt_key32_files.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_ubyte)]
    lib.mabe_decrypt_key32_files.restype = c_int

    # encrypt
    lib.mabe_encrypt_json_for_key32_files.argtypes = [
        c_void_p,              # ctx
        c_char_p, c_char_p, c_char_p,  # Auth1/2/3 paths
        POINTER(c_ubyte),      # key32
        ctypes.c_char_p,       # out_json buffer
        c_size_t,              # out_json_cap
        POINTER(c_size_t),     # out_json_len (in/out)
    ]
    lib.mabe_encrypt_json_for_key32_files.restype = c_int

    ctx = lib.mabe_ctx_create(b"a.param", b"public.json")
    if not ctx:
        raise RuntimeError("mabe_ctx_create failed")

    return lib, ctx

async def main():

    server = msquic.MSQuicSocket()
    addr = "20.42.59.99"
    addr = "127.0.0.1"
    port = 5007
    print("Test Start")

    server.CreateClientSocket(addr, port, 1000)
    libmabe, mabe_ctx = load_mabe()
    try:
        i = 0
        print("Test Start")
        while i < 10:
            t0 = time.perf_counter()
            
            key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")

            out_len = c_size_t(0)
            buf = create_string_buffer(256 * 1024)
            key_arr = (c_ubyte * 32).from_buffer_copy(key)

            rc = libmabe.mabe_encrypt_json_for_key32_files(
                mabe_ctx,
                b"Auth1.json", b"Auth2.json", b"Auth3.json",
                key_arr,
                buf, ctypes.sizeof(buf),
                byref(out_len),
            )
            if rc != 0:
                raise RuntimeError(f"mabe_encrypt_json_for_key32_files failed rc={rc} need={out_len.value}")

            encrypted_key_bytes = buf.value  # JSON bytes 

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

            with open("encrypt.json", "wb") as f:
                f.write(challenge)

            out_key = (c_ubyte * 32)()
            rc = libmabe.mabe_decrypt_key32_files(mabe_ctx, b"encrypt.json", b"userInfo.json", out_key)
            if rc != 0:
                raise RuntimeError(f"mabe_decrypt_key32_files failed rc={rc}")

            t_mabe_decrypt = time.perf_counter()
            decrypted_key = bytes(out_key)

            server.ClientSendMessage(decrypted_key, len(decrypted_key))
            t_send_proof = time.perf_counter()

            response, streamID = server.RecvFrom()

            t_total = time.perf_counter()
            if(response != b'Ok'):
                raise RuntimeError(f"attestation failed") 

            if i == 0:
                print(
                    "mabe_encrypt",
                    "send_challenge",
                    "recv_proof",
                    "send_ok",
                    "recv_challenge",
                    "mabe_decrypt",
                    "send_proof",
                    "total",
                )

            print(
                f"{(t_mabe_encrypt - t0) * 1000:.2f}",
                f"{(t_send_challenge - t_mabe_encrypt) * 1000:.2f}",
                f"{(t_recv_proof - t_send_challenge) * 1000:.2f}",
                f"{(t_send_ok - t_recv_proof) * 1000:.2f}",
                f"{(t_recv_challenge - t_send_ok) * 1000:.2f}",
                f"{(t_mabe_decrypt - t_recv_challenge) * 1000:.2f}",
                f"{(t_send_proof - t_mabe_decrypt) * 1000:.2f}",
                f"{(t_total - t0) * 1000:.2f}",
            )
            i+=1
    finally:
        libmabe.mabe_ctx_free(mabe_ctx)
if __name__ == '__main__':
    #main()
    asyncio.run(main())


