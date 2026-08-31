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
        raise ValueError(
            "Expected PORT/PROTOCOL, for example 22/tcp"
        )

    port, protocol = port_protocol.split("/", 1)

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

def parse_scans(scans):
    results = []

    for scan in scans:
        if not is_port_line(scan):
            continue

        try:
            result = parse_scan(scan)
            results.append(result)

        except ValueError as error:
            print(error)

    return results
