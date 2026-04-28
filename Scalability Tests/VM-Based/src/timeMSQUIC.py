#!/usr/bin/env python3
"""
Sequentially time MABE decrypt via libmabe.so N times (no async, no parallelism).

Outputs:
- timings.txt: one elapsed_s per line (raw samples)
- prints mu and sigma (sample and population) for a normal distribution fit
"""

import os
import time
import statistics
import ctypes
from ctypes import POINTER, c_char_p, c_int, c_void_p, c_ubyte

HERE = os.path.dirname(os.path.abspath(__file__))
N = 1000
WARMUP = 10
OUTFILE = "timings.txt"  # one elapsed_s per line

def load_lib():
    lib = ctypes.CDLL(os.path.join(HERE, "libmabe.so"))
    lib.mabe_ctx_create.argtypes = [c_char_p, c_char_p]
    lib.mabe_ctx_create.restype = c_void_p
    lib.mabe_ctx_free.argtypes = [c_void_p]
    lib.mabe_ctx_free.restype = None
    lib.mabe_decrypt_key32_files.argtypes = [c_void_p, c_char_p, c_char_p, POINTER(c_ubyte)]
    lib.mabe_decrypt_key32_files.restype = c_int
    return lib

def percentile(sorted_vals, p: float) -> float:
    # linear interpolation percentile, p in [0,100]
    k = (p / 100.0) * (len(sorted_vals) - 1)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac

def run_once(lib, ctx) -> float:
    out_key = (c_ubyte * 32)()
    t0 = time.perf_counter()
    rc = lib.mabe_decrypt_key32_files(ctx, b"encrypt.json", b"userInfo.json", out_key)
    t1 = time.perf_counter()
    if rc != 0:
        raise RuntimeError(f"mabe_decrypt_key32_files failed rc={rc}")
    return t1 - t0

def main():
    os.chdir(HERE)
    lib = load_lib()
    ctx = lib.mabe_ctx_create(b"a.param", b"public.json")
    if not ctx:
        raise RuntimeError("mabe_ctx_create failed")

    try:
        # warmup
        for _ in range(WARMUP):
            run_once(lib, ctx)

        times = []
        for _ in range(N):
            times.append(run_once(lib, ctx))
    finally:
        lib.mabe_ctx_free(ctx)

    with open(OUTFILE, "w", encoding="utf-8") as f:
        for t in times:
            f.write(f"{t:.12f}\n")

    times_sorted = sorted(times)
    mu = statistics.mean(times_sorted)
    sigma_sample = statistics.stdev(times_sorted)   # n-1
    sigma_pop = statistics.pstdev(times_sorted)     # n

    print(f"n={len(times_sorted)}")
    print(f"mu={mu:.12f}")
    print(f"sigma_sample={sigma_sample:.12f}")
    print(f"sigma_population={sigma_pop:.12f}")
    print(f"min={times_sorted[0]:.12f}")
    print(f"p50={percentile(times_sorted, 50):.12f}")
    print(f"p90={percentile(times_sorted, 90):.12f}")
    print(f"p95={percentile(times_sorted, 95):.12f}")
    print(f"p99={percentile(times_sorted, 99):.12f}")
    print(f"max={times_sorted[-1]:.12f}")
    print(f"raw_samples_file={OUTFILE}")

if __name__ == "__main__":
    main()
