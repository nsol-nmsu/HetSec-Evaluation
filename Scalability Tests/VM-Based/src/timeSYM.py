import os
import time
import statistics
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------- Config --------
N = 1000
WARMUP = 50

PLAINTEXT_BYTES = 4096      # set to your typical payload size
AAD = b""                  # set if you use associated data; else keep empty

ENC_OUTFILE = "sym_encrypt_timings.txt"
DEC_OUTFILE = "sym_decrypt_timings.txt"


def percentile(sorted_vals, p: float) -> float:
    k = (p / 100.0) * (len(sorted_vals) - 1)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def time_encrypt(aesgcm: AESGCM, key: bytes, plaintext: bytes) -> float:
    nonce = os.urandom(12)  # GCM standard nonce size
    t0 = time.perf_counter()
    _ct = aesgcm.encrypt(nonce, plaintext, AAD)
    t1 = time.perf_counter()
    return t1 - t0


def time_decrypt(aesgcm: AESGCM, nonce: bytes, ciphertext: bytes) -> float:
    t0 = time.perf_counter()
    _pt = aesgcm.decrypt(nonce, ciphertext, AAD)
    t1 = time.perf_counter()
    return t1 - t0


def summarize(label: str, samples):
    s = sorted(samples)
    mu = statistics.mean(s)
    sigma_sample = statistics.stdev(s) if len(s) > 1 else 0.0
    sigma_pop = statistics.pstdev(s) if len(s) > 0 else 0.0

    print(f"\n[{label}]")
    print(f"n={len(s)}")
    print(f"mu={mu:.12f}")
    print(f"sigma_sample={sigma_sample:.12f}")
    print(f"sigma_population={sigma_pop:.12f}")
    print(f"min={s[0]:.12f}")
    print(f"p50={percentile(s, 50):.12f}")
    print(f"p90={percentile(s, 90):.12f}")
    print(f"p95={percentile(s, 95):.12f}")
    print(f"p99={percentile(s, 99):.12f}")
    print(f"max={s[-1]:.12f}")


def main():
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    plaintext = os.urandom(PLAINTEXT_BYTES)

    # Warmup encrypt
    for _ in range(WARMUP):
        nonce = os.urandom(12)
        _ = aesgcm.encrypt(nonce, plaintext, AAD)

    # Timed encrypt runs (fresh nonce each time)
    enc_times = []
    last_nonce = None
    last_ct = None
    for _ in range(N):
        nonce = os.urandom(12)
        t0 = time.perf_counter()
        ct = aesgcm.encrypt(nonce, plaintext, AAD)
        t1 = time.perf_counter()
        enc_times.append(t1 - t0)
        last_nonce, last_ct = nonce, ct

    # Prepare a ciphertext for decrypt benchmarking (fixed input)
    # Use the last produced ciphertext to avoid measuring encrypt here.
    nonce_fixed = last_nonce
    ct_fixed = last_ct

    # Warmup decrypt
    for _ in range(WARMUP):
        _ = aesgcm.decrypt(nonce_fixed, ct_fixed, AAD)

    # Timed decrypt runs (same ciphertext each time, isolates decrypt cost)
    dec_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        _ = aesgcm.decrypt(nonce_fixed, ct_fixed, AAD)
        t1 = time.perf_counter()
        dec_times.append(t1 - t0)

    # Write raw samples
    with open(ENC_OUTFILE, "w", encoding="utf-8") as f:
        for t in enc_times:
            f.write(f"{t:.12f}\n")

    with open(DEC_OUTFILE, "w", encoding="utf-8") as f:
        for t in dec_times:
            f.write(f"{t:.12f}\n")

    # Print distribution parameters
    summarize(f"AES-256-GCM encrypt ({PLAINTEXT_BYTES} bytes)", enc_times)
    summarize(f"AES-256-GCM decrypt ({PLAINTEXT_BYTES} bytes)", dec_times)

    print(f"\nRaw samples written to: {ENC_OUTFILE}, {DEC_OUTFILE}")


if __name__ == "__main__":
    main()