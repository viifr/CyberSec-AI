import json
from urllib.parse import urlsplit, parse_qs


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


def parse_http_request(request):
    lines = request.splitlines()

    if not lines:
        raise ValueError("HTTP request is empty")

    request_line = lines[0].split()

    if len(request_line) != 3:
        raise ValueError(
            "Expected request line: METHOD PATH HTTP/VERSION"
        )

    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2]

    headers = {}
    body_lines = []
    reading_body = False

    for line in lines[1:]:
        if line == "":
            reading_body = True
            continue

        if reading_body:
            body_lines.append(line)
            continue

        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    body = "\n".join(body_lines)

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
        "body": body
    }


def extract_query_parameters(path):
    return parse_qs(urlsplit(path).query)


def extract_body_parameters(body, headers):
    if not body:
        return {}

    content_type = headers.get("Content-Type", "")

    if "application/x-www-form-urlencoded" in content_type:
        return parse_qs(body)

    if "application/json" in content_type:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {}

    return {}


def extract_cookies(headers):
    cookies = {}

    cookie_header = headers.get("Cookie")

    if not cookie_header:
        return cookies

    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()

        if "=" not in cookie:
            continue

        name, value = cookie.split("=", 1)

        cookies[name.strip()] = value.strip()

    return cookies