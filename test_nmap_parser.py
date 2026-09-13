import pytest

from ai import NmapAnalysis
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


def test_nmap_analysis_includes_evidence_and_limitations():
    analysis = NmapAnalysis.model_validate({
        "findings": [{
            "port": 22,
            "service": "ssh",
            "severity": "informational",
            "confidence": "high",
            "finding": "SSH is exposed.",
            "reason": "Remote access service detected.",
            "recommendation": "Restrict access to trusted networks.",
            "evidence": ["22/tcp is open and reports ssh."],
        }],
        "limitations": [
            "The scan does not establish the SSH patch state.",
        ],
    })

    assert analysis.findings[0].evidence == ["22/tcp is open and reports ssh."]
    assert analysis.limitations == [
        "The scan does not establish the SSH patch state.",
    ]