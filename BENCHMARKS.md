# Benchmarks and evaluation status

No production performance or AI-quality benchmark numbers are published by this repository. No value below is estimated or inferred. Results must come from recorded runs with the exact code commit, infrastructure, dataset, model, settings, and hardware identified.

## API latency harness

`scripts/benchmark_api.py` sends authenticated GET requests and reports elapsed time percentiles, request rate, and HTTP errors. It does not create telemetry or measure ingestion/detection throughput. Example:

```bash
export ND_BENCHMARK_TOKEN='short-lived-token'
python scripts/benchmark_api.py --base-url http://localhost:8001 --path /api/v1/auth/me --requests 100 --concurrency 4
```

Do not place a token in shell history or benchmark output. Run only against an environment where the test account and load are authorized. Use a dedicated lab cluster for load work.

## Required evaluation matrix

| Area | Status | Required evidence |
|---|---|---|
| Event ingestion throughput | Not measured | Fixed event corpus, sustained events/sec, loss and index health |
| Elasticsearch query latency | Not measured | Query set, index size/shards, warm/cold p50/p95/p99 |
| Detection execution | Not measured | Rule set, event corpus, match accuracy and end-to-end latency |
| AI investigation | Not measured | Versioned labeled cases, evidence correctness, model/runtime, reviewer scoring |
| Model gateway | Not measured | Provider/model/runtime, concurrency, token counts, p50/p95/p99 |
| Queue throughput | Not measured | Worker count, queue depth, task success/failure, sustained rate |
| API response time | Harness available; no baseline | Raw JSON output, endpoint, concurrency, host/container resources |
| Prompt-injection resistance | Functional controls only; no score | Versioned adversarial set, repeated runs, failure taxonomy |
| Detection generation quality | Not measured | Held-out rule tasks, schema/compiler pass rate, analyst review |

Publish raw methodology and representative machine-readable output alongside any future report. Never compare runs that use different datasets or model settings without stating the difference.
