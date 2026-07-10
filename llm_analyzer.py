import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))-

def analyze_with_llm(contract_code, slither_findings):
    
    findings_text = ""
    for f in slither_findings:
        findings_text += f"- {f['detector']} (Severity: {f['severity']}): {f['description']}\n"
    
    prompt = f"""You are an expert smart contract security auditor.

Analyze this Solidity smart contract for security vulnerabilities.

Slither static analysis already found these issues:
{findings_text}

Now analyze the contract for additional vulnerabilities that static analysis may have missed, especially:
- Business logic flaws
- Access control issues
- Economic attack vectors
- Any other security concerns

Contract code:
{contract_code}

Respond in this exact JSON format:
{{
    "additional_vulnerabilities": [
        {{
            "name": "vulnerability name",
            "severity": "Critical/High/Medium/Low",
            "description": "what the vulnerability is",
            "location": "which function or line",
            "fix": "how to fix it",
            "fixed_code": "corrected solidity code snippet"
        }}
    ],
    "overall_risk_score": "score out of 10",
    "summary": "2-3 line overall assessment"
}}

Return only valid JSON, no extra text."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    
    text = response.choices[0].message.content.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    
    return text.strip()

# Test it
with open("vulnerable.sol", "r") as f:
    contract_code = f.read()

from parser import run_slither, parse_vulnerabilities
slither_output = run_slither("vulnerable.sol")
findings = parse_vulnerabilities(slither_output)

llm_result = analyze_with_llm(contract_code, findings)
print(llm_result)

try:
    parsed = json.loads(llm_result)
    print("\nJSON is valid")
    print(f"Risk Score: {parsed['overall_risk_score']}")
    print(f"Summary: {parsed['summary']}")
    print(f"Additional vulnerabilities found: {len(parsed['additional_vulnerabilities'])}")
except json.JSONDecodeError as e:
    print(f"JSON parsing error: {e}")
    print("Raw response:", llm_result)