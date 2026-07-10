import subprocess
import json

def run_slither(contract_path):
    result = subprocess.run(
        ["slither", contract_path, "--json", "-"],
        capture_output=True,
        text=True
    )
    try:
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError:
        return None

def parse_vulnerabilities(slither_output):
    vulnerabilities = []
    
    if not slither_output:
        return vulnerabilities
    
    results = slither_output.get("results", {}).get("detectors", [])
    
    for result in results:
        vuln = {
            "detector": result.get("check"),
            "severity": result.get("impact"),
            "confidence": result.get("confidence"),
            "description": result.get("description"),
            "reference": result.get("wiki_url")
        }
        vulnerabilities.append(vuln)
    
    return vulnerabilities

# Run it
output = run_slither("vulnerable.sol")
vulns = parse_vulnerabilities(output)

for v in vulns:
    print(f"Detector: {v['detector']}")
    print(f"Severity: {v['severity']}")
    print(f"Confidence: {v['confidence']}")
    print(f"Description: {v['description']}")
    print(f"Reference: {v['reference']}")
    print("---")