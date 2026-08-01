import os
import json
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def clean_json(text: str) -> str:
    """
    Removes markdown code fences from LLM responses.
    """

    text = text.strip()

    if text.startswith("```json"):
        text = text[7:]

    if text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    return text.strip()


def analyze_with_llm(contract_code, slither_findings):
    """
    Performs semantic security analysis using Groq LLaMA.

    Returns:
        dict
        {
            "additional_vulnerabilities": [...]
        }
    """

    findings_text = ""

    if slither_findings:
        for finding in slither_findings:
            findings_text += (
                f"- {finding['detector']} "
                f"(Severity: {finding['severity']}): "
                f"{finding['description']}\n"
            )
    else:
        findings_text = "No vulnerabilities detected by Slither."

    prompt = f"""
You are an expert Solidity Smart Contract Security Auditor.

Your objective is to perform semantic security analysis.

IMPORTANT:

Slither has already analyzed this contract and reported:

{findings_text}

Your responsibilities:

1. Review Slither's findings.
2. Do NOT repeat vulnerabilities already detected.
3. Identify ONLY additional vulnerabilities that static analysis may miss.

Focus especially on:

- Business logic flaws
- Missing validation
- Access control mistakes
- Flash loan attack possibilities
- Economic attack vectors
- Privilege escalation
- Unsafe assumptions
- Token accounting mistakes
- Authorization issues
- Any semantic vulnerability

For every vulnerability provide:

- name
- severity
- description
- why_this_matters
Explain in simple English how an attacker could exploit this issue and what business impact it could have.
- location
- fix
- fixed_code

Return ONLY valid JSON.

Required JSON format:

{{
    "additional_vulnerabilities": [
        {{
            "name": "",
            "severity": "",
            "description": "",
            "why_this_matters":"",
            "location": "",
            "fix": "",
            "fixed_code": ""
        }}
    ]
}}

Do not return markdown.

Do not explain anything outside JSON.

Contract:

{contract_code}
"""

    try:

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0
        )

        text = response.choices[0].message.content

        cleaned = clean_json(text)

        return json.loads(cleaned)

    except Exception as e:

        print(f"[LLM ERROR] {e}")

        return {
            "additional_vulnerabilities": [],
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":

    from parser import run_slither, parse_vulnerabilities

    CONTRACT_PATH = "vulnerable.sol"

    with open(CONTRACT_PATH, "r") as file:
        contract = file.read()

    slither_output = run_slither(CONTRACT_PATH)

    slither_findings = parse_vulnerabilities(slither_output)

    result = analyze_with_llm(contract, slither_findings)

    print(json.dumps(result, indent=4))