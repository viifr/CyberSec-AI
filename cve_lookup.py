import os
import re
import time

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 2
MAX_RESULTS = 20
USER_AGENT = "CyberSec-AI/0.1 (local security analysis tool)"
_CACHE = {}


def _positive_int(value, name, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")

    return value


def _request_settings():
    try:
        timeout = float(os.getenv("NVD_TIMEOUT", DEFAULT_TIMEOUT))
        retries = int(os.getenv("NVD_RETRIES", DEFAULT_RETRIES))
    except ValueError as error:
        raise ValueError("NVD_TIMEOUT and NVD_RETRIES must be numeric") from error

    if timeout <= 0:
        raise ValueError("NVD_TIMEOUT must be greater than zero")

    if not 0 <= retries <= 5:
        raise ValueError("NVD_RETRIES must be between 0 and 5")

    return timeout, retries


def _retry_delay(response, attempt):
    retry_after = response.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return min(float(retry_after), 30)

    return min(2 ** attempt, 30)


def _validate_cpe(cpe_name):
    if not isinstance(cpe_name, str) or not cpe_name.strip():
        raise ValueError("CPE name must be a non-empty string")

    cpe_name = cpe_name.strip()
    if not re.fullmatch(r"cpe:2\.3:[^\s]+", cpe_name, flags=re.IGNORECASE):
        raise ValueError("CPE name must be a valid CPE 2.3 identifier")

    return cpe_name


def search_cves(keyword=None, limit=5, *, cpe_name=None):
    if keyword is None and cpe_name is None:
        raise ValueError("Provide a keyword or CPE name")

    if keyword is not None and cpe_name is not None:
        raise ValueError("Provide either a keyword or CPE name, not both")

    if keyword is not None:
        if not isinstance(keyword, str) or not keyword.strip():
            raise ValueError("CVE keyword must be a non-empty string")
        keyword = " ".join(keyword.split())
        query = keyword
        query_parameter = "keywordSearch"
    else:
        cpe_name = _validate_cpe(cpe_name)
        query = cpe_name
        query_parameter = "cpeName"

    limit = _positive_int(limit, "limit", MAX_RESULTS)
    timeout, retries = _request_settings()
    cache_key = (query_parameter, query.casefold(), limit)

    if cache_key in _CACHE:
        return [dict(result) for result in _CACHE[cache_key]]

    params = {
        query_parameter: query,
        "resultsPerPage": limit
    }

    headers = {"User-Agent": os.getenv("NVD_USER_AGENT", USER_AGENT)}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(retries + 1):
        response = requests.get(
            NVD_URL,
            params=params,
            headers=headers,
            timeout=timeout
        )

        if response.status_code not in {429, 500, 502, 503, 504}:
            break

        if attempt == retries:
            response.raise_for_status()

        time.sleep(_retry_delay(response, attempt))

    response.raise_for_status()

    try:
        data = response.json()
    except ValueError as error:
        raise ValueError("NVD returned invalid JSON") from error

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities", []), list):
        raise ValueError("NVD returned an unexpected response shape")

    results = []

    for item in data.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue

        cve = item.get("cve", {})
        if not isinstance(cve, dict):
            continue

        results.append({
            "id": cve.get("id", "Unknown"),
            "published": cve.get("published", "Unknown"),
            "description": get_description(cve),
            "severity": get_severity(cve),
            "score": get_score(cve),
            "cvss_version": get_cvss_data(cve).get("version", "Unknown"),
            "vector": get_cvss_data(cve).get("vectorString", "Unknown"),
            "cwes": get_cwes(cve),
            "references": get_references(cve),
            "match_method": "exact_cpe" if cpe_name else "keyword_candidate",
            "verification": (
                "CPE matched in NVD; verify the installed product, version, and configuration"
                if cpe_name
                else "Keyword match only; verify the product, version, and configuration"
            ),
        })

    _CACHE[cache_key] = [dict(result) for result in results]
    return results


def get_description(cve):
    descriptions = cve.get("descriptions", [])

    if not isinstance(descriptions, list):
        return "No description"

    for description in descriptions:
        if not isinstance(description, dict):
            continue
        if description.get("lang") == "en":
            return description.get("value", "No description")

    return "No description"


def get_cvss_data(cve):
    metrics = cve.get("metrics", {})

    if not isinstance(metrics, dict):
        return {}

    for metric_name in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30"
    ]:
        metric_list = metrics.get(metric_name, [])

        if not isinstance(metric_list, list) or not metric_list:
            continue

        metric = metric_list[0]
        if not isinstance(metric, dict):
            continue

        cvss_data = metric.get("cvssData", {})
        return cvss_data if isinstance(cvss_data, dict) else {}

    return {}


def get_severity(cve):
    cvss_data = get_cvss_data(cve)

    return cvss_data.get("baseSeverity", "Unknown")


def get_score(cve):
    cvss_data = get_cvss_data(cve)

    return cvss_data.get("baseScore", "Unknown")


def get_cwes(cve):
    weaknesses = cve.get("weaknesses", [])
    cwes = []

    if not isinstance(weaknesses, list):
        return cwes

    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue

        for description in weakness.get("description", []):
            if not isinstance(description, dict):
                continue
            if description.get("lang") == "en" and description.get("value"):
                cwes.append(description["value"])

    return sorted(set(cwes))


def get_references(cve):
    references = []

    raw_references = cve.get("references", [])
    if not isinstance(raw_references, list):
        return references

    for reference in raw_references:
        if isinstance(reference, dict) and reference.get("url"):
            references.append(reference["url"])

    return references


def lookup_scan_cves(scan_results):
    results = []
    seen_queries = set()

    for scan in scan_results:
        if not isinstance(scan, dict):
            continue

        if scan.get("state") != "open":
            continue

        service = scan.get("service", "")
        version = scan.get("version", "")
        cpe_name = scan.get("cpe")

        if not isinstance(service, str) or not isinstance(version, str):
            continue

        if cpe_name is not None and not isinstance(cpe_name, str):
            cpe_name = None

        if not version.strip() and not cpe_name:
            continue

        keyword = " ".join(f"{service} {version}".split())
        query_key = ("cpe", cpe_name.casefold()) if cpe_name else ("keyword", keyword.casefold())
        if query_key in seen_queries:
            continue
        seen_queries.add(query_key)

        try:
            if cpe_name:
                cves = search_cves(limit=3, cpe_name=cpe_name)
                lookup_method = "exact_cpe"
            else:
                cves = search_cves(keyword, limit=3)
                lookup_method = "keyword_candidate"

        except requests.RequestException as error:
            results.append({
                "port": scan.get("port"),
                "service": service,
                "version": version,
                "cpe": cpe_name,
                "lookup_method": lookup_method,
                "cves": [],
                "lookup_status": "failed",
                "lookup_error": str(error),
            })
            continue
        except ValueError as error:
            results.append({
                "port": scan.get("port"),
                "service": service,
                "version": version,
                "cpe": cpe_name,
                "lookup_method": lookup_method,
                "cves": [],
                "lookup_status": "skipped",
                "lookup_error": str(error),
            })
            continue

        results.append({
            "port": scan.get("port"),
            "service": service,
            "version": version,
            "cpe": cpe_name,
            "lookup_method": lookup_method,
            "cves": cves,
            "lookup_status": "ok",
        })

    return results