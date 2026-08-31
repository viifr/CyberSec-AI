from ollama import chat

def ask_ai(question):
    response = chat(
        model="qwen3:4b",
        messages=[
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
            },
            {
                "role": "user",
                "content": question
            }
        ],
        think=False
    )

    return response.message.content

def analyse_scan(results):
    prompt = f"""
    Analyse the following Nmap scan results:

    {results}

    For every service:
    - explain what the service is
    - identify relevant security concerns
    - explain why they matter
    - suggest safe, authorized investigation steps

    Do not assume a vulnerability exists just because a port is open.
    """

    return ask_ai(prompt)

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
        question = input("\nCybersecurity question: ")

        answer = ask_ai(question)

        print("\nCyberSec AI:")
        print(answer)

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

        answer = analyse_scan(results)

        print("CyberSec AI:")
        print(answer)

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()