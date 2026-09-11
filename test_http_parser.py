import pytest

from http_parser import parse_http_request, redact_request_data


def test_parse_form_post_request():
    request = (
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "username=vee&password=test123"
    )

    result = parse_http_request(request)

    assert result["method"] == "POST"
    assert result["path"] == "/login"
    assert result["body_parameters"] == {
        "username": ["vee"],
        "password": ["test123"]
    }
    assert result["body"] == "username=vee&password=test123"


def test_parse_simple_get_request():
    request = (
        "GET /search?q=python HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test-client\r\n"
        "\r\n"
    )

    result = parse_http_request(request)

    assert result["method"] == "GET"
    assert result["path"] == "/search?q=python"
    assert result["http_version"] == "HTTP/1.1"
    assert result["headers"]["host"] == "example.com"
    assert result["headers"]["user-agent"] == "test-client"
    assert result["query_parameters"] == {"q": ["python"]}
    assert result["body"] == ""


def test_parse_json_post_request():
    request = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"username":"vee","password":"test123"}'
    )

    result = parse_http_request(request)

    assert result["method"] == "POST"
    assert result["path"] == "/api/login"
    assert result["body_parameters"] == {
        "username": "vee",
        "password": "test123"
    }


def test_parse_cookies():
    request = (
        "GET /account HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Cookie: session=abc123; theme=dark\r\n"
        "\r\n"
    )

    result = parse_http_request(request)

    assert result["cookies"] == {
        "session": "abc123",
        "theme": "dark"
    }


def test_invalid_request_line():
    request = (
        "THIS IS NOT HTTP\r\n"
        "Host: example.com\r\n"
        "\r\n"
    )

    with pytest.raises(ValueError):
        parse_http_request(request)


def test_redact_sensitive_request_data():
    request = (
        "POST /login?api_key=url-secret HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Authorization: Bearer header-secret\r\n"
        "Cookie: session=cookie-secret; theme=dark\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "username=vee&password=form-secret"
    )

    parsed_request = parse_http_request(request)
    redacted_request = redact_request_data(parsed_request)

    assert redacted_request["headers"]["authorization"] == "[REDACTED]"
    assert redacted_request["headers"]["cookie"] == "[REDACTED]"
    assert redacted_request["query_parameters"]["api_key"] == "[REDACTED]"
    assert redacted_request["body_parameters"]["password"] == "[REDACTED]"


def test_invalid_json_body_is_rejected():
    request = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"username": "vee",'
    )

    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_http_request(request)


def test_json_array_body_is_rejected():
    request = (
        "POST /api/data HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '["one", "two"]'
    )

    with pytest.raises(ValueError, match="JSON body must be an object"):
        parse_http_request(request)


def test_redaction_hides_raw_body():
    request = (
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "username=vee&password=form-secret"
    )

    parsed_request = parse_http_request(request)
    redacted_request = redact_request_data(parsed_request)

    assert redacted_request["body"] == "[REDACTED]"
    assert redacted_request["body_parameters"]["password"] == "[REDACTED]"
