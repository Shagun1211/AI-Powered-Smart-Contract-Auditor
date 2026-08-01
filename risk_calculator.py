
SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Informational": 1
}


def calculate_risk_score(findings):
    """
    Calculate overall contract risk score based on merged findings.
    Returns:
        score (float): Risk score out of 10
        summary (str): Human-readable assessment
    """

    if not findings:
        return 0.0, "No vulnerabilities were detected. The contract appears secure based on the performed analysis."

    total_weight = 0

    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:

        severity = finding.get("severity", "Low")

        severity_count[severity] += 1

        total_weight += SEVERITY_WEIGHTS.get(severity, 0)

    max_weight = len(findings) * 10

    score = round((total_weight / max_weight) * 10, 1)

    if severity_count["Critical"] > 0:

        summary = (
            "Critical vulnerabilities were detected. "
            "The contract should not be deployed until these issues are resolved."
        )

    elif severity_count["High"] > 0:

        summary = (
            "High-risk vulnerabilities were identified. "
            "Immediate remediation is strongly recommended."
        )

    elif severity_count["Medium"] > 0:

        summary = (
            "The contract contains medium-risk issues that should be addressed before deployment."
        )

    elif severity_count["Low"] > 0:

        summary = (
            "Only low-risk issues were detected. "
            "The contract is generally secure but could benefit from improvements."
        )

    else:

        summary = (
            "Only informational findings were reported."
        )

    return score, summary