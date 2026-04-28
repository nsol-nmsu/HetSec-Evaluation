import os
import time
import queue
import asyncio
import ssl
import msquic

import ctypes
from ctypes import (
    POINTER, byref, c_char_p, c_int, c_size_t, c_ubyte, c_void_p,
    create_string_buffer,
)

HERE = os.path.dirname(os.path.abspath(__file__))

def load_mabe():
    lib = ctypes.CDLL(os.path.join(HERE, "libmabe.so"))

    lib.mabe_ctx_create.argtypes = [c_char_p, c_char_p]
    lib.mabe_ctx_create.restype = c_void_p
    lib.mabe_ctx_free.argtypes = [c_void_p]
    lib.mabe_ctx_free.restype = None

    lib.mabe_decrypt_key32_files.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_ubyte)]
    lib.mabe_decrypt_key32_files.restype = c_int

    lib.mabe_encrypt_json_for_key32_files.argtypes = [
        c_void_p, c_char_p, c_char_p, c_char_p,
        POINTER(c_ubyte), c_char_p, c_size_t, POINTER(c_size_t),
    ]
    lib.mabe_encrypt_json_for_key32_files.restype = c_int

    ctx = lib.mabe_ctx_create(b"a.param", b"public.json")
    if not ctx:
        raise RuntimeError("mabe_ctx_create failed")
    return lib, ctx

#handles what the clients sends, and formats it for the handle_client()
#handling of clients, what to send to them, what to do to them
async def handle_client(libmabe, mabe_ctx):

    s = msquic.MSQuicSocket()
    s.CreateServerSocket(5007)

    while True:

        client_data, streamID = await asyncio.to_thread(s.RecvAny)
        t0 = time.perf_counter()

        with open("encrypt.json", "wb") as f:
            f.write(client_data)

        out_key = (c_ubyte * 32)()
        rc = libmabe.mabe_decrypt_key32_files(mabe_ctx, b"encrypt.json", b"userInfo.json", out_key)
        if rc != 0:
            raise RuntimeError(f"mabe_decrypt_key32_files failed rc={rc}")
        t_mabe_decrypt = time.perf_counter()

        decrypted_key = bytes(out_key)

        s.ServerSend(streamID, decrypted_key)#, len(global_pickle))
        t_send_proof = time.perf_counter()

        response, streamID = await asyncio.to_thread(s.RecvAny)

        t_recv_ok = time.perf_counter()
        if(response != b'Ok'):
            raise RuntimeError(f"attestation failed")

        buf = create_string_buffer(256 * 1024)
        out_len = c_size_t(0)
        key_arr = (c_ubyte * 32).from_buffer_copy(decrypted_key)
        rc = libmabe.mabe_encrypt_json_for_key32_files(
            mabe_ctx, b"Auth1.json", b"Auth2.json", b"Auth3.json",
            key_arr, buf, ctypes.sizeof(buf), byref(out_len),
        )
        if rc != 0:
            raise RuntimeError(f"mabe_encrypt_json_for_key32_files failed rc={rc} need={out_len.value}")
        encrypted_key_bytes = buf.value
        t_mabe_encrypt = time.perf_counter()

        s.ServerSend(streamID, encrypted_key_bytes)#, len(global_pickle))
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
    os.chdir(HERE)
    libmabe, mabe_ctx = load_mabe()
    try:
        await handle_client(libmabe, mabe_ctx)
    finally:
        libmabe.mabe_ctx_free(mabe_ctx)

#grpc
if __name__ == '__main__':
    asyncio.run(main())
