import json
import re
from urllib.parse import parse_qs, urlsplit

REDACTED_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "api-key",
}

REDACTED_PARAM_KEYWORDS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
)

METHOD_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HTTP_VERSIONS = {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}

MAX_HEADER_NAME_LENGTH = 200
MAX_HEADER_VALUE_LENGTH = 8192
MAX_BODY_SIZE = 1_000_000
MAX_REQUEST_SIZE = 2_000_000
MAX_PARAMETER_PAIRS = 200


def _is_valid_request_target(target):
    if not target or any(ch.isspace() for ch in target):
        return False

    if target == "*":
        return True

    if target.startswith("/"):
        return True

    if "://" in target:
        try:
            parsed = urlsplit(target)
        except ValueError:
            return False
        return bool(parsed.scheme) and bool(parsed.netloc)

    if re.fullmatch(r"[A-Za-z0-9.-]+:\d+", target):
        return True

    return False


def is_sensitive_key(key):
    lowered_key = str(key).lower()
    return lowered_key in REDACTED_HEADERS or any(
        keyword in lowered_key for keyword in REDACTED_PARAM_KEYWORDS
    )


def redact_value(value):
    if isinstance(value, dict):
        redacted = {}
        for key, child in value.items():
            if is_sensitive_key(key):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_value(child)
        return redacted

    if isinstance(value, list):
        return [redact_value(item) for item in value]

    return value


def redact_request_data(request_data):
    redacted = dict(request_data)

    for field in ("headers", "cookies", "query_parameters", "body_parameters"):
        values = redacted.get(field)

        if isinstance(values, dict):
            redacted[field] = {
                key: ("[REDACTED]" if is_sensitive_key(key) else redact_value(value))
                for key, value in values.items()
            }

    return redacted

def is_probably_http_request(raw_request: str) -> bool:
    if not isinstance(raw_request, str) or not raw_request.strip():
        return False

    normalized = raw_request.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    first_line = normalized.splitlines()[0].strip() if normalized.splitlines() else ""

    if not first_line:
        return False

    try:
        parse_request_line(first_line)
    except ValueError:
        return False

    return True


def parse_request_line(line):
    if not isinstance(line, str):
        raise ValueError("Request line must be a string")

    parts = line.split()

    if len(parts) != 3:
        raise ValueError("Expected request line: METHOD TARGET HTTP/VERSION")

    method, target, http_version = parts

    if not METHOD_PATTERN.fullmatch(method):
        raise ValueError("Invalid HTTP method")

    if not _is_valid_request_target(target):
        raise ValueError("Invalid HTTP request target")

    if http_version not in HTTP_VERSIONS:
        raise ValueError(f"Unsupported HTTP version: {http_version}")

    return method, target, http_version


def split_http_message(request):
    if not isinstance(request, str):
        raise ValueError("HTTP request must be a string")

    normalized = request.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    separator_index = normalized.find("\n\n")

    if separator_index != -1:
        header_section = normalized[:separator_index]
        body = normalized[separator_index + 2:]
        return header_section.splitlines(), body

    return normalized.splitlines(), ""


def get_http_request():
    print("\nPaste the HTTP request.")
    print("Type END on its own line when finished.\n")

    lines = []

    while True:
        line = input()

        if line == "END":
            break

        lines.append(line)

    return "\n".join(lines)


def extract_query_parameters(path):
    parsed_url = urlsplit(path)
    return parse_qs(parsed_url.query, keep_blank_values=True)


def normalize_http_request(request):
    if not isinstance(request, str):
        raise ValueError("HTTP request must be a string")

    normalized = request.lstrip("\ufeff")
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")

    lines = []
    pending = None

    for raw_line in normalized.splitlines():
        line = raw_line.rstrip()

        if not line:
            if pending is not None and lines and lines[-1] != "":
                lines.append("")
            continue

        if line.startswith((" ", "\t")) and pending is not None:
            lines[-1] = f"{lines[-1]} {line.strip()}"
            continue

        lines.append(line.strip())
        pending = line

    while lines and not lines[0].strip():
        lines.pop(0)

    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)

def normalize_header_value(value):
    if not isinstance(value, str):
        return str(value)

    return value.strip().replace("\r", "").replace("\n", " ")

def get_content_type(headers):
    content_type = headers.get("content-type", "")
    return content_type.split(";", 1)[0].strip().lower()


def extract_body_parameters(body, headers):
    if not body:
        return {}

    if len(body) > MAX_BODY_SIZE:
        raise ValueError("HTTP body exceeds supported size limit")

    media_type = get_content_type(headers)

    if media_type == "application/x-www-form-urlencoded":
        return parse_qs(body, keep_blank_values=True)

    if media_type == "application/json":
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return {}

        if isinstance(data, dict):
            return data

        return {}

    return {}


def extract_cookies(headers):
    cookies = {}
    cookie_header = headers.get("cookie")

    if not cookie_header:
        return cookies

    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()

        if not cookie or "=" not in cookie:
            continue

        name, value = cookie.split("=", 1)
        cookie_name = name.strip()

        if not cookie_name:
            continue

        cookies[cookie_name] = value.strip()

    return cookies


def parse_http_request(request):
    if not isinstance(request, str):
        raise ValueError("HTTP request must be a string")

    if len(request) > MAX_REQUEST_SIZE:
        raise ValueError("HTTP request exceeds supported size limit")

    request = normalize_http_request(request)

    if not request.strip():
        raise ValueError("HTTP request is empty")

    if not is_probably_http_request(request):
        raise ValueError("Request does not look like a valid HTTP request")

    lines, body = split_http_message(request)

    if not lines:
        raise ValueError("HTTP request is empty")

    method, path, http_version = parse_request_line(lines[0])

    headers = {}

    for line_number, line in enumerate(lines[1:], start=1):
        if not line:
            continue

        if ":" not in line:
            raise ValueError(f"Malformed header at line {line_number}: {line}")

        name, value = line.split(":", 1)
        normalized_name = name.strip().lower()
        normalized_value = normalize_header_value(value)

        if not normalized_name:
            raise ValueError(f"Malformed header at line {line_number}: empty header name")

        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", normalized_name):
            raise ValueError(f"Malformed header at line {line_number}: invalid header name")

        if len(normalized_name) > MAX_HEADER_NAME_LENGTH:
            raise ValueError("Header name exceeds supported length")

        if len(normalized_value) > MAX_HEADER_VALUE_LENGTH:
            raise ValueError("Header value exceeds supported length")

        headers[normalized_name] = normalized_value

    if len(headers) > MAX_PARAMETER_PAIRS:
        raise ValueError("Too many headers in request")

    query_parameters = extract_query_parameters(path)
    body_parameters = extract_body_parameters(body, headers)
    cookies = extract_cookies(headers)

    return {
        "method": method,
        "path": path,
        "http_version": http_version,
        "headers": headers,
        "query_parameters": query_parameters,
        "body_parameters": body_parameters,
        "cookies": cookies,
        "body": body,
    }