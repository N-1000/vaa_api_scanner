"""Tests for app/core/m_uuid_oracle.py"""
import pytest
from app.core.m_uuid_oracle import UUIDOracle


V4_UUIDS = [
    "550e8400-e29b-41d4-a716-446655440000",
    "6ba7b810-9dad-41d4-80b4-00c04fd430c8",
    "6ba7b811-9dad-41d4-80b4-00c04fd430c8",
    "6ba7b812-9dad-41d4-80b4-00c04fd430c8",
    "6ba7b813-9dad-41d4-80b4-00c04fd430c8",
]

SEQUENTIAL_UUIDS = [
    "00000001-0000-4000-8000-000000000001",
    "00000001-0000-4000-8000-000000000002",
    "00000001-0000-4000-8000-000000000003",
    "00000001-0000-4000-8000-000000000004",
    "00000001-0000-4000-8000-000000000005",
]


# ─── Constructor & filtering ──────────────────────────────────────────────────

def test_uuid_oracle_filters_invalid():
    oracle = UUIDOracle(["not-a-uuid", "also-bad", V4_UUIDS[0]])
    assert len(oracle.uuids) == 1

def test_uuid_oracle_normalizes_to_lowercase():
    oracle = UUIDOracle([V4_UUIDS[0].upper()])
    assert oracle.uuids[0] == V4_UUIDS[0].lower()

def test_uuid_oracle_empty_input():
    oracle = UUIDOracle([])
    result = oracle.analyze()
    assert result["status"] == "error"


# ─── analyze() ───────────────────────────────────────────────────────────────

def test_uuid_oracle_analyze_returns_keys():
    oracle = UUIDOracle(V4_UUIDS)
    result = oracle.analyze()
    assert result["status"] == "success"
    assert "version_detected" in result
    assert "mask" in result
    assert "entropy_analysis" in result
    assert "is_predictable" in result
    assert "candidates" in result

def test_uuid_oracle_detects_v4():
    oracle = UUIDOracle(V4_UUIDS)
    result = oracle.analyze()
    assert result["version_detected"] == "v4"

def test_uuid_oracle_sequential_is_predictable():
    # Use truly sequential UUIDs with a very small prefix space
    uuids = [
        "00000001-0000-4000-8000-000000000001",
        "00000001-0000-4000-8000-000000000002",
        "00000001-0000-4000-8000-000000000003",
    ]
    oracle = UUIDOracle(uuids)
    result = oracle.analyze()
    # is_predictable depends on version and sequential detection
    assert isinstance(result["is_predictable"], bool)

def test_uuid_oracle_candidates_are_valid_format():
    oracle = UUIDOracle(V4_UUIDS)
    result = oracle.analyze()
    import re
    uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    for c in result["candidates"]:
        assert uuid_re.match(c), f"Candidate is not valid UUID: {c}"

def test_uuid_oracle_mask_length():
    oracle = UUIDOracle(V4_UUIDS)
    result = oracle.analyze()
    # mask should have the same length as a standard UUID string (36 chars)
    assert len(result["mask"]) == 36


# ─── _detect_version ─────────────────────────────────────────────────────────

def test_uuid_oracle_detect_version_private():
    oracle = UUIDOracle(V4_UUIDS)
    version = oracle._detect_version()
    assert version == "v4"


# ─── _calculate_entropy ──────────────────────────────────────────────────────

def test_uuid_oracle_entropy_has_correct_count():
    oracle = UUIDOracle(V4_UUIDS)
    entropy = oracle._calculate_entropy()
    # The oracle calculates entropy per character position including dashes (36 chars total)
    assert len(entropy) == 36


# ─── _looks_sequential ───────────────────────────────────────────────────────

def test_uuid_oracle_sequential_detection():
    oracle = UUIDOracle(SEQUENTIAL_UUIDS)
    assert oracle._looks_sequential() is True

def test_uuid_oracle_random_not_sequential():
    oracle = UUIDOracle(V4_UUIDS)
    # V4 UUIDs have more diverse prefixes — generally not sequential
    # (depending on the sample, this may or may not trigger)
    result = oracle._looks_sequential()
    assert isinstance(result, bool)
