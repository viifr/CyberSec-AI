# CyberSec AI

A locally-running cybersecurity AI assistant built with Python,
Ollama and Qwen.

## Current Features

## Features

- General cybersecurity Q&A with bounded conversation history
- HTTP request parsing for origin-form and absolute-form requests
- Redaction of authorization headers, cookies, API keys, tokens, passwords,
  and raw request bodies before AI analysis
- JSON and URL-encoded request body parsing with size limits
- Nmap text and XML parsing with host, service, version, and CPE metadata
- Nmap duplicate detection, source evidence, parse warnings, and analysis limitations
- AI-assisted Nmap and HTTP analysis with schema-validated responses
- NVD CVE candidate lookup using CPE data when available
- NVD retries, caching, rate-limit handling, CVSS/CWE/reference extraction,
  and open-port filtering

## Requirements

- Python 3.10 or newer
- Ollama installed and running locally
- A downloaded Ollama model, such as `qwen3:8b`
- Network access for NVD lookups, unless CVE lookup is skipped

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
ollama pull qwen3:8b
```

The AI model can be changed with `CYBERSEC_AI_MODEL`:

```bash
export CYBERSEC_AI_MODEL=qwen3:8b
```

Optional NVD settings are controlled through environment variables:

- `NVD_API_KEY`
- `NVD_TIMEOUT`
- `NVD_RETRIES`
- `NVD_USER_AGENT`

## Run

```bash
python main.py
```

The menu provides general chat, Nmap analysis, HTTP/Burp request analysis,
and exit. Paste HTTP requests exactly as captured and type `END` on its own
line when finished.

## Nmap Input

The parser accepts simplified text records such as:

```text
Nmap scan report for example.com (192.0.2.10)
22/tcp open ssh OpenSSH 9.0
80/tcp open http nginx 1.24.0
```

It also accepts Nmap XML, including host addresses, hostnames, service
metadata, CPEs, and scan metadata. Closed and filtered ports are retained in
the parsed scan but are not sent to CVE lookup as exposed services.

## HTTP Input

The parser accepts CRLF, LF, and common HTTP request formats:

```text
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=alice&password=example-password
END
```

Supported structured body types are `application/json` objects and
`application/x-www-form-urlencoded`. Multipart and chunked bodies are not
decoded. Input, header, body, and parameter sizes are bounded.

Do not paste secrets or personal data unless necessary for an authorized test.
The application redacts common sensitive fields before display and AI
analysis, but users remain responsible for the data they provide.

## CVE Results

CVE results are candidates, not proof that a target is vulnerable. CPE matches
are stronger than keyword matches, but product identity, installed version,
configuration, patch state, and exploitability must still be verified manually.

## Testing

Run the deterministic test suite with:

```bash
python -m pytest -v
```

The suite does not require Ollama or a live NVD request. Live integrations
should be tested separately and must not be required for normal unit tests.

## Scope and Failure Modes

Use this tool only for systems you own or are explicitly authorized to assess.
If Ollama is unavailable, the selected model is missing, input is malformed,
NVD is rate-limited, or an AI response fails schema validation, the operation
returns an error instead of treating the result as reliable.

## Technologies

- Python
- Ollama
- Qwen3
- Nmap

## Current Status

Early development.

Planned features include:

- HTTP request analysis
- Burp Suite integration
- Security log analysis
- CVE/CWE lookup
- Structured vulnerability findings
- Cybersecurity knowledge retrieval
- Conversation memory
- File support
- Detailed security report/summary
- Tool integration (Nmap, Wireshark, Burp)
- Web interface
