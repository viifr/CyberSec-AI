import json
import time
from ollama import chat

def ask_ai(question, history):
    history.append({
        "role": "user",
        "content": question
    })

    response = chat(
        model="qwen3:4b",
        messages=history,
        think=False
    )

    answer = response.message.content

    history.append({
        "role": "assistant",
        "content": answer
    })

    return answer

def start_chat():
    history = [
        {
            "role": "system",
            "content": """
            You are a cybersecurity assistant.

            Your job is to:
            - answer cybersecurity questions clearly
            - explain concepts at the user's level
            - analyse cybersecurity data
            - distinguish facts from assumptions
            - focus on defensive and authorized security work
            """
        }
    ]

    print("\nCyberSec AI Chat")
    print("Type 'exit' to return.\n")

    while True:
        question = input("You: ")

        if question.lower() == "exit":
            break

        answer = ask_ai(question, history)

        print("\nCyberSec AI:")
        print(answer)
        print()

def analyse_scan(results):
    prompt = f"""
    Analyse the following Nmap scan results:

    {results}

    Return ONLY valid JSON.

    Use exactly this structure:

    {{
        "findings": [
            {{
                "port": 22,
                "service": "ssh",
                "severity": "informational",
                "confidence": "high",
                "finding": "SSH service detected",
                "reason": "An SSH service is listening on port 22.",
                "recommendation": "Identify the SSH version and review its authentication configuration."
            }}
        ]
    }}

    Severity must be one of:
    - informational
    - low
    - medium
    - high
    - critical

    Confidence must be one of:
    - low
    - medium
    - high

    Important:
    - Do not claim a vulnerability exists without evidence.
    - An open port alone is not a vulnerability.
    - Base findings only on the supplied scan.
    - Focus on defensive and authorized security analysis.
    """

    response = chat(
        model="qwen3:4b",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity analysis assistant."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        format="json",
        think=False
    )

    return json.loads(response.message.content)

def get_scan():
    print("Paste Nmap results.")
    print("Press Enter on an empty line when finished.\n")

    scans = []

    while True:
        line = input("> ")

        if line == "":
            break

        scans.append(line)

    return scans


def parse_scan(scan):
    parts = scan.split()

    if len(parts) < 3:
        raise ValueError(
            "Expected at least: PORT/PROTOCOL STATE SERVICE"
        )

    port_protocol = parts[0]
    state = parts[1]
    service = parts[2]

    version = " ".join(parts[3:])

    if "/" not in port_protocol:
        raise ValueError("Expected PORT/PROTOCOL, for example 22/tcp")

    port, protocol = port_protocol.split("/")

    if not port.isdigit():
        raise ValueError("Port must be a number")

    if protocol not in ["tcp", "udp"]:
        raise ValueError("Protocol must be tcp or udp")

    if not 1 <= int(port) <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    return {
        "port": int(port),
        "protocol": protocol,
        "state": state,
        "service": service,
        "version": version
    }

def is_port_line(line):
    parts = line.split()

    if len(parts) < 3:
        return False

    first_part = parts[0]

    if "/" not in first_part:
        return False

    port, protocol = first_part.split("/", 1)

    if not port.isdigit():
        return False

    if protocol not in ["tcp", "udp"]:
        return False

    return True

def main():
    print("CyberSec AI")
    print("1. Ask a cybersecurity question")
    print("2. Analyse Nmap results")

    choice = input("\nChoose an option: ")

    if choice == "1":
        start_chat()

    elif choice == "2":
        scans = get_scan()

        results = []

        for scan in scans:
            if not is_port_line(scan):
                continue

            try:
                result = parse_scan(scan)
                results.append(result)

            except ValueError as error:
                print(error)

        if not results:
            print("No valid Nmap results found.")
            return

        print("\nParsed results:")

        for result in results:
            print(result)

        print("\nAnalysing scan...\n")

        start = time.time()

        analysis = analyse_scan(results)

        end = time.time()

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

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()