import pytest

from nmap_parser import parse_scans


def test_text_scan_preserves_source_and_warns_on_duplicate():
    scans = [
        "Nmap scan report for example.com (192.0.2.10)",
        "22/tcp open ssh OpenSSH 9.0",
        "22/tcp open ssh OpenSSH 9.0",
    ]

    results, warnings = parse_scans(scans, return_warnings=True)

    assert len(results) == 1
    assert results[0]["source"] == "22/tcp open ssh OpenSSH 9.0"
    assert results[0]["host"] == "192.0.2.10"
    assert any("duplicate port" in warning for warning in warnings)


def test_scan_line_limit_is_enforced():
    scans = ["22/tcp open ssh"] * 10_001

    with pytest.raises(ValueError, match="too many lines"):
        parse_scans(scans)