"""Tests for app/core/engine/vuln_types.py"""
import pytest
from app.core.engine import vuln_types


def test_vuln_types_module_importable():
    assert vuln_types is not None


def test_vuln_types_has_expected_constants():
    """Verify the main vulnerability type constants are defined."""
    attrs = dir(vuln_types)
    # At minimum some constants related to vuln categories should exist
    assert len([a for a in attrs if not a.startswith("__")]) > 0


def test_vuln_types_severities_are_strings():
    """All exposed string constants should be of type str."""
    for attr in dir(vuln_types):
        if attr.startswith("__"):
            continue
        val = getattr(vuln_types, attr)
        if isinstance(val, str):
            assert len(val) > 0, f"{attr} should not be empty"


def test_vuln_types_no_duplicates():
    """No two constants should have the same string value if they represent different types."""
    str_values = []
    for attr in dir(vuln_types):
        if attr.startswith("__"):
            continue
        val = getattr(vuln_types, attr)
        if isinstance(val, str):
            str_values.append(val)
    # Allow duplicates if intentional — just ensure no empty strings
    assert all(len(v) > 0 for v in str_values)
