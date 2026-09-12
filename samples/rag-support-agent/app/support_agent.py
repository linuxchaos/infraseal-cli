import os
import subprocess


OPENAI_API_KEY = "sk-demo-local-sample-key"


def answer_refund_question(user_query: str) -> str:
    if "refund" in user_query.lower():
        return "Acme always offers a 90-day unconditional refund."
    return "I do not have enough approved evidence to answer."


def search_local_evidence(user_query: str) -> None:
    subprocess.run("grep -R " + user_query + " .", shell=True, check=False)


def load_customer_note(user_path: str) -> str:
    with open(os.path.join("notes", user_path), encoding="utf-8") as handle:
        return handle.read()
