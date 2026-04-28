import os
import copy
import time
import pickle
import ctypes
from ctypes import POINTER, c_char_p, c_int, c_void_p, c_ubyte

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

lib = ctypes.CDLL(os.path.join(HERE, "libmabe.so"))
lib.mabe_ctx_create.argtypes = [c_char_p, c_char_p]
lib.mabe_ctx_create.restype = c_void_p
lib.mabe_ctx_free.argtypes = [c_void_p]
lib.mabe_ctx_free.restype = None
lib.mabe_decrypt_key32_files.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_ubyte)]
lib.mabe_decrypt_key32_files.restype = c_int

ctx = lib.mabe_ctx_create(b"a.param", b"public.json")
if not ctx:
    raise RuntimeError("mabe_ctx_create failed")

try:
    out_key = (c_ubyte * 32)()
    start_time = time.time()
    rc = lib.mabe_decrypt_key32_files(ctx, b"encrypt.json", b"userInfo.json", out_key)
    end_time = time.time()
    if rc != 0:
        raise RuntimeError(f"mabe_decrypt_key32_files failed rc={rc}")
finally:
    lib.mabe_ctx_free(ctx)

print("Time to run MABE: ", end_time - start_time)
