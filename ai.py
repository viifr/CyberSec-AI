import json
from ollama import chat


SYSTEM_PROMPT = """
You are a cybersecurity assistant.

Give clear, concise answers.

Do not show internal reasoning or thought processes.
Only provide the final answer.

Prefer short explanations unless the user asks for more detail.

Explain cybersecurity concepts in beginner-friendly language.
Distinguish facts from assumptions.
Focus on defensive and authorized security work.
"""


def ask_ai(question, history):
    history.append({
        "role": "user",
        "content": question
    })

    response = chat(
        model="qwen3:4b",
        messages=history,
        think=False,
        options={
            "temperature": 0.3,
            "num_predict": 250
        }
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
            "content": SYSTEM_PROMPT
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
Analyse these Nmap results:

{results}

Return ONLY valid JSON.

Use this structure:

{{
    "findings": [
        {{
            "port": 22,
            "service": "ssh",
            "severity": "informational",
            "confidence": "high",
            "finding": "SSH service detected",
            "reason": "An SSH service is listening on port 22.",
            "recommendation": "Review the SSH version and authentication configuration."
        }}
    ]
}}

Severity:
informational, low, medium, high, critical

Confidence:
low, medium, high

Rules:
- An open port alone is not a vulnerability.
- Do not claim vulnerabilities without evidence.
- Base findings only on the supplied information.
- Keep findings concise.
"""

    response = chat(
        model="qwen3:4b",
        messages=[
            {
                "role": "system",
                "content": "You are a concise cybersecurity analysis assistant."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        format="json",
        think=False,
        options={
            "temperature": 0,
            "num_predict": 400
        }
    )

    return json.loads(response.message.content)
