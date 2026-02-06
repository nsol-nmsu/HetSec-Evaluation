#!/usr/bin/env python3
"""
Sequentially time ./MABE-decrypt N times (no async, no parallelism).

Outputs:
- timings.txt: one elapsed_s per line (raw samples)
- prints mu and sigma (sample and population) for a normal distribution fit
"""

import subprocess
import time
import statistics

CMD = ["./MABE-decrypt"]
N = 1000
WARMUP = 10
OUTFILE = "timings.txt"  # one elapsed_s per line

def percentile(sorted_vals, p: float) -> float:
    # linear interpolation percentile, p in [0,100]
    k = (p / 100.0) * (len(sorted_vals) - 1)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac

def run_once() -> float:
    t0 = time.perf_counter()
    r = subprocess.run(
        CMD,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        text=False,
    )
    t1 = time.perf_counter()
    if r.returncode != 0:
        raise RuntimeError(f"decrypt failed with return code {r.returncode}")
    return t1 - t0

def main():
    # warmup
    for _ in range(WARMUP):
        run_once()

    times = []
    for _ in range(N):
        times.append(run_once())

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
