from ai_engine.model_gateway.redaction import redact_sensitive_data


def evaluate_redaction() -> dict:
    samples = (
        "password=FakeCanaryPassword-9081 user=analyst@example.invalid src=198.51.100.24",
        "Authorization: Bearer fake.canary.token",
        "-----BEGIN PRIVATE KEY-----\\nFAKE-KEY-CANARY\\n-----END PRIVATE KEY-----",
    )
    outputs = [redact_sensitive_data(sample) for sample in samples]
    result = " ".join(item.text for item in outputs)
    required = {"credential", "email", "ipv4", "bearer_token", "private_key"}
    observed = {category for item in outputs for category in item.categories}
    passed = required.issubset(observed) and all(marker not in result for marker in (
        "FakeCanaryPassword-9081", "analyst@example.invalid", "198.51.100.24",
        "fake.canary.token", "FAKE-KEY-CANARY",
    ))
    return {"status": "passed" if passed else "failed", "categories": sorted(observed),
            "replacements": sum(item.replacements for item in outputs),
            "evidence": "Synthetic credential, contact, IP, bearer-token, and private-key canaries."}
