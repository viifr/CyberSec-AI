import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword, limit=5):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    response = requests.get(
        NVD_URL,
        params=params,
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        results.append({
            "id": cve.get("id", "Unknown"),
            "published": cve.get("published", "Unknown"),
            "description": get_description(cve),
            "severity": get_severity(cve),
            "score": get_score(cve)
        })

    return results


def get_description(cve):
    descriptions = cve.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "No description")

    return "No description"


def get_cvss_data(cve):
    metrics = cve.get("metrics", {})

    for metric_name in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30"
    ]:
        metric_list = metrics.get(metric_name, [])

        if metric_list:
            return metric_list[0].get("cvssData", {})

    return {}


def get_severity(cve):
    cvss_data = get_cvss_data(cve)

    return cvss_data.get("baseSeverity", "Unknown")


def get_score(cve):
    cvss_data = get_cvss_data(cve)

    return cvss_data.get("baseScore", "Unknown")


def lookup_scan_cves(scan_results):
    results = []

    for scan in scan_results:
        service = scan.get("service", "")
        version = scan.get("version", "")

        if not version:
            continue

        keyword = f"{service} {version}".strip()

        try:
            cves = search_cves(keyword, limit=3)

        except requests.RequestException as error:
            print(
                f"CVE lookup failed for {keyword}: {error}"
            )
            continue

        results.append({
            "port": scan.get("port"),
            "service": service,
            "version": version,
            "cves": cves
        })

    return results