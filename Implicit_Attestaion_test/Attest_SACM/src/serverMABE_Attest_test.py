import os
import time
import queue
import asyncio
import ssl
import msquic
import subprocess

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

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client():   

    s = msquic.MSQuicSocket()
    s.CreateServerSocket(5007)

    libmabe, mabe_ctx = load_mabe()
    try:
        while True:

            client_data, streamID = await asyncio.to_thread(s.RecvAny)
            t0 = time.perf_counter()

            _client_encrypt_json = client_data.decode(errors="replace")

            out_key = (c_ubyte * 32)()
            rc = libmabe.mabe_decrypt_key32_files(mabe_ctx, b"encrypt.json", b"userInfo.json", out_key)
            if rc != 0:
                raise RuntimeError(f"mabe_decrypt_key32_files failed rc={rc}")

            decrypted_key = bytes(out_key)
            t_mabe_decrypt = time.perf_counter()

            decrypted_key = bytes.fromhex("C09A05030C15CBC957E60D0678BD47451367E9BBC427EC5B5C60E9C6B286C87B")

            s.ServerSend(streamID, decrypted_key)#, len(global_pickle))
            t_send_proof = time.perf_counter()

            response, streamID = await asyncio.to_thread(s.RecvAny)

            t_recv_ok = time.perf_counter()
            if(response != b'Ok'):
                raise RuntimeError(f"attestation failed") 

            out_len = c_size_t(0)
            buf = create_string_buffer(256 * 1024)  # adjust if your JSON can exceed this
            key_arr = (c_ubyte * 32).from_buffer_copy(decrypted_key)

            rc = libmabe.mabe_encrypt_json_for_key32_files(
                mabe_ctx,
                b"Auth1.json", b"Auth2.json", b"Auth3.json",
                key_arr,
                buf, ctypes.sizeof(buf),
                byref(out_len),
            )
            if rc != 0:
                raise RuntimeError(f"mabe_encrypt_json_for_key32_files failed rc={rc} need={out_len.value}")

            challenge_json = buf.value 
            t_mabe_encrypt = time.perf_counter()

            s.ServerSend(streamID, challenge_json)#, len(global_pickle))
            t_send_challenge = time.perf_counter()

            challenge_response, streamID = await asyncio.to_thread(s.RecvAny)
            t_recv_proof = time.perf_counter()

            if(challenge_response != decrypted_key):
                raise RuntimeError(f"attestation failed") 

            s.ServerSend(streamID, b'Ok')#, len(global_pickle))
            t_total = time.perf_counter()



            print(
                "Server timings ms:",
                f"{(t_mabe_decrypt - t0) * 1000:.2f}",
                f"{(t_send_proof - t_mabe_decrypt) * 1000:.2f}",
                f"{(t_recv_ok - t_send_proof) * 1000:.2f}",
                f"{(t_mabe_encrypt - t_recv_ok) * 1000:.2f}",
                f"{(t_send_challenge - t_mabe_encrypt) * 1000:.2f}",
                f"{(t_recv_proof - t_send_challenge) * 1000:.2f}",
                f"{(t_total - t0) * 1000:.2f}",
            )
    finally:
        libmabe.mabe_ctx_free(mabe_ctx)

    
async def main():
    await handle_client()

#grpc 
if __name__ == '__main__':
    print(
    "Server timings ms:",
    "mabe_decrypt",
    "send_proof",
    "recv_ok",
    "mabe_encrypt",
    "send_challenge",
    "recv_proof",
    "total",
    )
    asyncio.run(main())

