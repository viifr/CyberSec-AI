import re
import xml.etree.ElementTree as ET


def get_scan():
    print("Paste Nmap text results or Nmap XML.")
    print("Press Enter on an empty line when finished.\n")

    scans = []

    while True:
        line = input("> ")

        if line == "":
            break

        scans.append(line)

    return scans


VALID_PORT_STATES = {
    "open",
    "closed",
    "filtered",
    "unfiltered",
    "unknown",
    "open|filtered",
    "closed|filtered",
    "open|closed",
    "closed|open",
}
MAX_SCAN_INPUT_SIZE = 2_000_000
MAX_SCAN_LINES = 10_000
MAX_SCAN_LINE_LENGTH = 10_000


def normalize_scan_line(line):
    if not isinstance(line, str):
        raise ValueError("Scan input must be a string")

    if len(line) > MAX_SCAN_LINE_LENGTH:
        raise ValueError("Scan line exceeds supported length")

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
    state = parts[1]

    if not re.fullmatch(r"\d{1,5}/(tcp|udp)", port_protocol, flags=re.IGNORECASE):
        return False

    port, protocol = port_protocol.split("/", 1)

    if not port.isdigit():
        return False

    if protocol.lower() not in {"tcp", "udp"}:
        return False

    if not 1 <= int(port) <= 65535:
        return False

    if state.lower() not in VALID_PORT_STATES:
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
    state = parts[1]

    if not re.fullmatch(r"\d{1,5}/(tcp|udp)", port_protocol, flags=re.IGNORECASE):
        raise ValueError("Expected PORT/PROTOCOL, for example 22/tcp")

    port, protocol = port_protocol.split("/", 1)

    if not 1 <= int(port) <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    normalized_state = state.lower()
    if normalized_state not in VALID_PORT_STATES:
        raise ValueError(f"Unsupported port state: {state}")

    normalized_protocol = protocol.lower()
    service = parts[2]
    version = " ".join(parts[3:])

    result = {
        "port": int(port),
        "protocol": normalized_protocol,
        "state": normalized_state,
        "service": service,
        "version": version,
        "source": cleaned,
    }

    return result


def _xml_text(element, attribute, default=""):
    value = element.get(attribute, default)
    return value.strip() if isinstance(value, str) else default


def parse_nmap_xml(xml_data, *, return_warnings=False):
    if not isinstance(xml_data, str) or not xml_data.strip():
        raise ValueError("Nmap XML input must be a non-empty string")

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML: {error}") from error

    if root.tag != "nmaprun":
        raise ValueError("Expected an Nmap XML document with an nmaprun root")

    warnings = []
    results = []
    seen_ports = set()
    scan_metadata = {
        "nmap_version": _xml_text(root, "version"),
        "scan_args": _xml_text(root, "args"),
        "scan_start": _xml_text(root, "startstr"),
    }

    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next(
            (
                _xml_text(candidate, "addr")
                for candidate in addresses
                if _xml_text(candidate, "addrtype") in {"ipv4", "ipv6"}
            ),
            "",
        )
        hostname_element = host.find("./hostnames/hostname")
        hostname = (
            _xml_text(hostname_element, "name")
            if hostname_element is not None
            else ""
        )
        host_identity = address or hostname

        for port in host.findall("./ports/port"):
            protocol = _xml_text(port, "protocol").lower()
            port_number = _xml_text(port, "portid")
            state_element = port.find("state")
            service_element = port.find("service")

            state = (
                _xml_text(state_element, "state").lower()
                if state_element is not None
                else "unknown"
            )

            if (
                protocol not in {"tcp", "udp"}
                or not port_number.isdigit()
                or not 1 <= int(port_number) <= 65535
                or state not in VALID_PORT_STATES
            ):
                warnings.append(
                    f"Ignored invalid XML port: {port_number}/{protocol}"
                )
                continue

            service = (
                _xml_text(service_element, "name")
                if service_element is not None
                else "unknown"
            ) or "unknown"
            product = (
                _xml_text(service_element, "product")
                if service_element is not None
                else ""
            )
            version = (
                _xml_text(service_element, "version")
                if service_element is not None
                else ""
            )
            extrainfo = (
                _xml_text(service_element, "extrainfo")
                if service_element is not None
                else ""
            )
            cpes = [
                cpe.text.strip()
                for cpe in port.findall("./service/cpe")
                if cpe.text and cpe.text.strip()
            ]
            key = (host_identity, protocol, int(port_number))

            if key in seen_ports:
                warnings.append(
                    f"Ignored duplicate XML port: {port_number}/{protocol}"
                )
                continue
            seen_ports.add(key)

            result = {
                "port": int(port_number),
                "protocol": protocol,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": cpes[0] if cpes else None,
                "cpes": cpes,
                "source": ET.tostring(port, encoding="unicode"),
                **scan_metadata,
            }

            if host_identity:
                result["host"] = host_identity
            if hostname and hostname != host_identity:
                result["hostname"] = hostname

            results.append(result)

    if return_warnings:
        return results, warnings

    return results


def parse_scans(scans, *, return_warnings=False):
    if isinstance(scans, str):
        if len(scans) > MAX_SCAN_INPUT_SIZE:
            raise ValueError("Nmap input exceeds supported size limit")
        if "<nmaprun" in scans[:500]:
            return parse_nmap_xml(scans, return_warnings=return_warnings)
        scans = scans.splitlines()
    else:
        scans = list(scans)
        if len(scans) > MAX_SCAN_LINES:
            raise ValueError("Nmap input contains too many lines")
        joined_scans = "\n".join(
            scan for scan in scans if isinstance(scan, str)
        )
        if len(joined_scans) > MAX_SCAN_INPUT_SIZE:
            raise ValueError("Nmap input exceeds supported size limit")
        if "<nmaprun" in joined_scans[:500]:
            return parse_nmap_xml(joined_scans, return_warnings=return_warnings)

    if len(scans) > MAX_SCAN_LINES:
        raise ValueError("Nmap input contains too many lines")

    results = []
    warnings = []
    current_host = None
    current_hostname = None
    seen_ports = set()

    for line_number, raw_scan in enumerate(scans, start=1):
        try:
            cleaned = normalize_scan_line(raw_scan)
        except ValueError as error:
            warnings.append(f"Ignored invalid line {line_number}: {error}")
            continue

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
            warnings.append(
                f"Ignored invalid scan line {line_number}: {cleaned} ({error})"
            )
            continue

        port_key = (current_host, result["protocol"], result["port"])
        if port_key in seen_ports:
            warnings.append(
                f"Ignored duplicate port on line {line_number}: "
                f"{result['port']}/{result['protocol']}"
            )
            continue
        seen_ports.add(port_key)

        if current_host is not None:
            result["host"] = current_host
            if current_hostname and current_hostname != current_host:
                result["hostname"] = current_hostname

        results.append(result)

    if return_warnings:
        return results, warnings

    return results
