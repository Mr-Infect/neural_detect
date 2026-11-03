#!/usr/bin/env python3
"""Measure authenticated GET latency without returning or recording response bodies."""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile_value / 100) * (len(ordered) - 1))))
    return round(ordered[index], 2)


def request_once(url: str, token: str, timeout: float) -> tuple[float, int]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
            return (time.perf_counter() - started) * 1000, response.status
    except urllib.error.HTTPError as error:
        return (time.perf_counter() - started) * 1000, error.code
    except (OSError, TimeoutError):
        return (time.perf_counter() - started) * 1000, 0


def run(base_url: str, path: str, requests: int, concurrency: int, timeout: float) -> dict[str, Any]:
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("--path must be an origin-relative path beginning with one slash")
    if requests < 1 or concurrency < 1 or timeout <= 0:
        raise ValueError("requests, concurrency, and timeout must be positive")
    url = base_url.rstrip("/") + path
    token = os.environ.get("ND_BENCHMARK_TOKEN", "")
    started = time.perf_counter()
    samples: list[tuple[float, int]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(request_once, url, token, timeout) for _ in range(requests)]
        for future in as_completed(futures):
            samples.append(future.result())
    elapsed = time.perf_counter() - started
    latencies = [sample[0] for sample in samples]
    statuses: dict[str, int] = {}
    for _, status in samples:
        key = str(status) if status else "network_error"
        statuses[key] = statuses.get(key, 0) + 1
    return {
        "target": path,
        "requests": requests,
        "concurrency": concurrency,
        "duration_seconds": round(elapsed, 3),
        "requests_per_second": round(requests / elapsed, 2) if elapsed else 0.0,
        "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95), "p99": percentile(latencies, 99)},
        "status_counts": statuses,
        "successful_responses": sum(1 for _, status in samples if 200 <= status < 400),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8001")
    parser.add_argument("--path", default="/api/v1/health")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", help="Optional path for a JSON result file")
    args = parser.parse_args()
    report = run(args.base_url, args.path, args.requests, args.concurrency, args.timeout)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
