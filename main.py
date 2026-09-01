import time

from ai import start_chat, analyse_scan, analyse_http
from nmap_parser import get_scan, parse_scans
from http_parser import get_http_request, parse_http_request


def main():
    print("CyberSec AI")
    print("1. Ask a cybersecurity question")
    print("2. Analyse Nmap results")
    print("3. Analyse HTTP/Burp Request")

    choice = input("\nChoose an option: ")

    if choice == "1":
        start_chat()

    elif choice == "2":
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

        for finding in analysis["findings"]:
            print("Port:", finding["port"])
            print("Service:", finding["service"])
            print("Severity:", finding["severity"])
            print("Confidence:", finding["confidence"])
            print("Finding:", finding["finding"])
            print("Reason:", finding["reason"])
            print("Recommendation:", finding["recommendation"])
            print()

    elif choice == "3":
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

        print("Method:", analysis.get("method", "Unknown"))
        print("Path:", analysis.get("path", "Unknown"))

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

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()