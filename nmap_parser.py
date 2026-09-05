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


def normalize_scan_line(line):
    if not isinstance(line, str):
        raise ValueError("Scan input must be a string")

    return line.strip()


def _extract_host_identity(line):
    if not line.startswith("Nmap scan report for"):
        return None, None

    remainder = line[len("Nmap scan report for"):].strip()

    if not remainder:
        return None, None

    if " (" in remainder and remainder.endswith(")"):
        host_label, _, address = remainder.rpartition(" (")
        host_label = host_label.strip()
        address = address[:-1].strip()
        return host_label, address

    return remainder, remainder


def is_port_line(line):
    cleaned = normalize_scan_line(line)

    if not cleaned:
        return False

    parts = cleaned.split()

    if len(parts) < 3:
        return False

    port_protocol = parts[0]

    if "/" not in port_protocol:
        return False

    try:
        port, protocol = port_protocol.split("/", 1)
    except ValueError:
        return False

    if not port.isdigit():
        return False

    if protocol.lower() not in {"tcp", "udp"}:
        return False

    if not 1 <= int(port) <= 65535:
        return False

    return True


def parse_scan(scan):
    cleaned = normalize_scan_line(scan)

    if not cleaned:
        raise ValueError("Scan line is empty")

    parts = cleaned.split()

    if len(parts) < 3:
        raise ValueError("Expected at least: PORT/PROTOCOL STATE SERVICE")

    port_protocol = parts[0]

    if not is_port_line(cleaned):
        raise ValueError("Expected PORT/PROTOCOL, for example 22/tcp")

    port, protocol = port_protocol.split("/", 1)
    state = parts[1]
    service = parts[2]
    version = " ".join(parts[3:])

    result = {
        "port": int(port),
        "protocol": protocol.lower(),
        "state": state,
        "service": service,
        "version": version,
    }

    if "host" in cleaned:
        return result

    return result


def parse_scans(scans, *, return_warnings=False):
    results = []
    warnings = []
    current_host = None
    current_hostname = None

    for raw_scan in scans:
        cleaned = normalize_scan_line(raw_scan)

        if not cleaned:
            continue

        if cleaned.startswith("Nmap scan report for"):
            host_label, address = _extract_host_identity(cleaned)
            current_host = address or host_label
            current_hostname = host_label if host_label != current_host else None
            continue

        if cleaned.startswith("Starting Nmap"):
            warnings.append("Ignored Nmap banner: starting line")
            continue

        if cleaned.startswith("Nmap done"):
            warnings.append("Ignored Nmap banner: completion line")
            continue

        if cleaned.startswith("Host:") or cleaned.startswith("MAC Address:"):
            warnings.append(f"Ignored host metadata line: {cleaned}")
            continue

        if not is_port_line(cleaned):
            warnings.append(f"Ignored non-port line: {cleaned}")
            continue

        try:
            result = parse_scan(cleaned)
        except ValueError as error:
            warnings.append(f"Ignored invalid scan line: {cleaned} ({error})")
            continue

        if current_host is not None:
            result["host"] = current_host
            if current_hostname and current_hostname != current_host:
                result["hostname"] = current_hostname

        results.append(result)

    if return_warnings:
        return results, warnings

    return results
