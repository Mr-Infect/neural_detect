from scripts.benchmark_api import percentile, run


def test_percentile_handles_empty_and_sorted_samples() -> None:
    assert percentile([], 95) == 0
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile([1, 2, 3, 4, 5], 95) == 5


def test_benchmark_rejects_non_origin_relative_target() -> None:
    try:
        run("http://localhost:8001", "//attacker.example/path", 1, 1, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("benchmark target accepted an authority override")
