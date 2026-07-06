"""Tests for app/core/engine/specialized/bola_harvest.py — AdaptiveBackoff circuit breaker"""
import pytest
from app.core.network_manager import AdaptiveBackoff


def test_adaptive_backoff_initial_state():
    cb = AdaptiveBackoff()
    assert cb.block_count == 0


def test_adaptive_backoff_on_block_below_threshold_returns_none():
    cb = AdaptiveBackoff()
    for _ in range(4):
        result = cb.on_block(403)
    assert result is None


def test_adaptive_backoff_on_block_exceeds_threshold_returns_action():
    cb = AdaptiveBackoff()
    result = None
    for _ in range(6):
        result = cb.on_block(429)
    assert result is not None
    assert result["action"] == "rotate_identity"
    assert "delay_ms" in result
    assert result["clear_cookies"] is True


def test_adaptive_backoff_cooldown_decrements():
    cb = AdaptiveBackoff()
    for _ in range(3):
        cb.on_block(403)
    initial_count = cb.block_count
    cb.cooldown()
    assert cb.block_count < initial_count


def test_adaptive_backoff_reset_clears_state():
    cb = AdaptiveBackoff()
    for _ in range(6):
        cb.on_block(403)
    cb.reset()
    assert cb.block_count == 0


def test_adaptive_backoff_different_status_codes():
    """Both 403 and 429 should trigger the block counter."""
    cb = AdaptiveBackoff()
    for code in [403, 429, 403, 429, 403, 429]:
        cb.on_block(code)
    assert cb.block_count >= 6
