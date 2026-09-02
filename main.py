import time

from ai import start_chat, analyse_scan, analyse_http
from nmap_parser import get_scan, parse_scans
from http_parser import get_http_request, parse_http_request
from cve_lookup import lookup_scan_cves


def analyse_nmap():
    scans = get_scan()
    results = parse_scans(scans)

    if not results:
        print("No valid Nmap results found.")
        return

    print("\nParsed results:")

    for result in results:
        print(result)

    print("\nAnalysing scan...\n")

    start = time.perf_counter()
    analysis = analyse_scan(results)
    end = time.perf_counter()

    print(f"Analysis took {end - start:.2f} seconds.\n")
    print("CyberSec AI:\n")

    for finding in analysis.get["findings"]:
        print("Port:", finding.get["port"])
        print("Service:", finding.get["service"])
        print("Severity:", finding.get["severity"])
        print("Confidence:", finding.get["confidence"])
        print("Finding:", finding.get["finding"])
        print("Reason:", finding.get["reason"])
        print("Recommendation:", finding.get["recommendation"])
        print()

    search_cves = input("Search NVD for candidate CVEs? [y/N]: ").strip().lower()

    if search_cves != "y":
        return

    print("\nSearching for candidate CVEs. This may take a while...\n")

    try:
        cve_results = lookup_scan_cves(results)

    except Exception as error:
        print(f"CVE lookup failed; scan analysis is still available: {error}")
        return

    if not cve_results:
        print("No version information was available for CVE lookup.")
        return

    print("Candidate CVEs (verify product, version, and configuration):\n")

    for service_result in cve_results:
        print(
            f"Port {service_result['port']}: "
            f"{service_result['service']} {service_result['version']}"
        )

        if not service_result["cves"]:
            print("- No matching CVEs returned.")

        for cve in service_result["cves"]:
            print(
                f"- {cve['id']} | severity: {cve['severity']} | "
                f"score: {cve['score']} | published: {cve['published']}"
            )
            print(" ", cve["description"])

        print()


def analyse_http_request():
    request = get_http_request()

    try:
        request_data = parse_http_request(request)

    except ValueError as error:
        print("Invalid HTTP request:", error)
        return

    print("\nParsed request:")
    print(request_data)

    print("\nAnalysing HTTP request...\n")
    analysis = analyse_http(request_data)

    print("CyberSec AI:\n")

    print("Method:", request_data["method"])
    print("Path:", request_data["path"])

    print("\nObservations:")
    for observation in analysis.get("observations", []):
        print("-", observation)

    print("\nPotential areas:")
    for area in analysis.get("potential_areas", []):
        print("\nName:", area.get("name", "Unknown"))
        print("Confidence:", area.get("confidence", "Unknown"))
        print("Reason:", area.get("reason", "No reason provided"))

    print("\nRecommendations:")
    for recommendation in analysis.get("recommendations", []):
        print("-", recommendation)


def main():
    while True:
        print("\nCyberSec AI")
        print("1. Ask a cybersecurity question")
        print("2. Analyse Nmap results")
        print("3. Analyse HTTP/Burp Request")
        print("4. Exit")

        try:
            choice = input("\nChoose an option: ").strip()

        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return

        if choice == "4":
            print("Goodbye.")
            return

        try:
            if choice == "1":
                start_chat()

            elif choice == "2":
                analyse_nmap()

            elif choice == "3":
                analyse_http_request()

            else:
                print("Invalid option.")

        except Exception as error:
            print(f"Operation failed: {error}")


if __name__ == "__main__":
    main()