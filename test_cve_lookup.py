from cve_lookup import lookup_scan_cves


def test_closed_ports_are_not_sent_to_cve_lookup(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("closed ports must not trigger CVE lookup")

    monkeypatch.setattr("cve_lookup.search_cves", fail_if_called)

    results = lookup_scan_cves([
        {
            "port": 22,
            "state": "closed",
            "service": "ssh",
            "version": "OpenSSH 9.0",
        }
    ])

    assert results == []