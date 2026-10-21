"""Smallest possible check: does our free Groq key reach a Llama-3 model?
Loads the key from .env (never hardcoded), sends one trivial prompt, prints
the reply. If this works, the whole model path works."""
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()                      # reads GROQ_API_KEY from .env
key = os.getenv("GROQ_API_KEY")
if not key:
    raise SystemExit("No GROQ_API_KEY found — check your .env file")

client = Groq(api_key=key)
resp = client.chat.completions.create(
    model="openai/gpt-oss-20b",   # free, fast Llama-3 on Groq
    messages=[{"role": "user", "content": "Reply with exactly: connection ok"}],
    temperature=0,
)
print("Model replied:", resp.choices[0].message.content)
