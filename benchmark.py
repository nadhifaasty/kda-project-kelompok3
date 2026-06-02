import json
import math
import os
import statistics
import time

from crypto_utils import encrypt_with_key, decrypt_with_key

SIZES = [
    ("1 KB", 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
]

ALGOS = [128, 192, 256]
RESULTS_PATH = "notes/benchmark_results.json"


def generate_test_data(size_bytes: int) -> str:
    return os.urandom(math.ceil(size_bytes / 2)).hex()[:size_bytes]


def run_benchmark(iterations_small: int = 100, iterations_large: int = 10) -> list[dict]:
    results = []
    for bit_length in ALGOS:
        for label, size in SIZES:
            iters = iterations_large if size >= 1024 * 1024 else iterations_small
            data = generate_test_data(size)

            # warm up
            _ = encrypt_with_key(data, bit_length)

            enc_times: list[float] = []
            dec_times: list[float] = []

            for _ in range(iters):
                t0 = time.perf_counter()
                ct = encrypt_with_key(data, bit_length)
                t1 = time.perf_counter()
                decrypt_with_key(ct, bit_length)
                t2 = time.perf_counter()

                enc_times.append((t1 - t0) * 1000)
                dec_times.append((t2 - t1) * 1000)

            avg_enc = statistics.mean(enc_times)
            avg_dec = statistics.mean(dec_times)
            throughput = (size / (avg_enc / 1000)) / (1024 * 1024)

            results.append({
                "algo": f"AES-{bit_length}",
                "bit_length": bit_length,
                "size_label": label,
                "size_bytes": size,
                "enc_avg_ms": round(avg_enc, 4),
                "enc_min_ms": round(min(enc_times), 4),
                "enc_max_ms": round(max(enc_times), 4),
                "enc_stdev_ms": round(statistics.stdev(enc_times), 4) if len(enc_times) > 1 else 0,
                "dec_avg_ms": round(avg_dec, 4),
                "dec_min_ms": round(min(dec_times), 4),
                "dec_max_ms": round(max(dec_times), 4),
                "dec_stdev_ms": round(statistics.stdev(dec_times), 4) if len(dec_times) > 1 else 0,
                "throughput_mbps": round(throughput, 4),
                "iterations": iters,
            })
    return results


def save_results(results: list[dict], path: str = RESULTS_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def load_results(path: str = RESULTS_PATH) -> list[dict] | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def print_results(results: list[dict]) -> None:
    header = f"{'Algoritma':<12} {'Ukuran':<8} {'Enc (ms)':<10} {'Dec (ms)':<10} {'Throughput (MB/s)':<16}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for r in results:
        print(
            f"{r['algo']:<12} {r['size_label']:<8} {r['enc_avg_ms']:<10.4f} {r['dec_avg_ms']:<10.4f} {r['throughput_mbps']:<16.2f}"
        )
    print(sep)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark AES-GCM performance")
    parser.add_argument("--small-iters", type=int, default=100, help="Iterations for small data")
    parser.add_argument("--large-iters", type=int, default=10, help="Iterations for large data")
    args = parser.parse_args()

    print("Menjalankan benchmark AES-GCM...")
    results = run_benchmark(args.small_iters, args.large_iters)
    save_results(results)
    print_results(results)
    print(f"\nHasil disimpan ke: {RESULTS_PATH}")
