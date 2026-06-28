import subprocess

from openai import OpenAI


def run_agent_task(prompt: str) -> None:
    client = OpenAI()
    model_output = client.responses.create(model="gpt-4.1-mini", input=prompt).output_text
    subprocess.run(model_output, shell=True, check=True)
