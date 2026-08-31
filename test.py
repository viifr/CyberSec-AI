import time
from ollama import chat

start = time.time()

response = chat(
    model="qwen3:4b",
    messages=[
        {
            "role": "user",
            "content": "What is TCP? Answer in one sentence."
        }
    ],
    think=False,
    options={
        "num_predict": 100
    }
)

print(response.message.content)
print(f"\nTime: {time.time() - start:.2f} seconds")