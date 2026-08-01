SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1
}


VULNERABILITY_MAP = {

    "reentrancy": [
        "reentrancy",
        "reentrant"
    ],

    "access control": [
        "access control",
        "onlyowner",
        "owner"
    ],

    "integer overflow": [
        "overflow",
        "underflow",
        "integer overflow"
    ],

    "timestamp dependency": [
        "timestamp",
        "block.timestamp"
    ],

    "unchecked external calls": [
        "unchecked",
        "external call",
        "low level call",
        "call"
    ],

    "denial of service": [
        "dos",
        "denial of service"
    ],

    "front running": [
        "front running",
        "front-running",
        "frontrunning"
    ],

    "flash loan": [
        "flash loan"
    ]
}


DEFAULT_EXPLANATION = (
    "This issue was detected during static analysis. "
    "If left unresolved, it may expose the smart contract "
    "to security vulnerabilities or unexpected behavior."
)


def normalize(text):
    return str(text).lower().strip()


def get_category(name):

    name = normalize(name)

    for category, keywords in VULNERABILITY_MAP.items():

        for keyword in keywords:

            if keyword in name:
                return category

    return name


def create_finding(
    name,
    severity,
    confidence,
    detected_by,
    description,
    why_this_matters,
    fix,
    fixed_code
):
    """
    Creates a standardized finding object.
    """

    return {

        "name": name,

        "severity": severity,

        "confidence": confidence,

        "detected_by": detected_by,

        "description": description,

        "why_this_matters": why_this_matters,

        "fix": fix,

        "fixed_code": fixed_code

    }


def merge_findings(slither_findings, llm_findings):

    merged = []

    used_ai = set()

    for slither in slither_findings:

        slither_category = get_category(
            slither.get("detector", "")
        )

        matched = False

        for index, ai in enumerate(llm_findings):

            ai_category = get_category(
                ai.get("name", "")
            )

            if slither_category != ai_category:
                continue

            severity = slither.get("severity", "Low")

            if SEVERITY_ORDER.get(
                ai.get("severity", "Low"),
                0
            ) > SEVERITY_ORDER.get(
                severity,
                0
            ):

                severity = ai["severity"]

            merged.append(

                create_finding(

                    name=slither_category.title(),

                    severity=severity,

                    confidence="Very High",

                    detected_by=[
                        "Slither",
                        "AI"
                    ],

                    description=ai.get(
                        "description",
                        slither.get("description", "")
                    ),

                    why_this_matters=ai.get(
                        "why_this_matters",
                        DEFAULT_EXPLANATION
                    ),

                    fix=ai.get(
                        "fix",
                        "Review manually."
                    ),

                    fixed_code=ai.get(
                        "fixed_code",
                        ""
                    )

                )

            )

            used_ai.add(index)

            matched = True

            break

        if not matched:

            merged.append(

                create_finding(

                    name=slither_category.title(),

                    severity=slither.get(
                        "severity",
                        "Low"
                    ),

                    confidence="High",

                    detected_by=[
                        "Slither"
                    ],

                    description=slither.get(
                        "description",
                        ""
                    ),

                    why_this_matters=DEFAULT_EXPLANATION,

                    fix="Manual review recommended.",

                    fixed_code=""

                )

            )


    for index, ai in enumerate(llm_findings):

        if index in used_ai:
            continue

        merged.append(

            create_finding(

                name=ai.get(
                    "name",
                    "Unknown"
                ),

                severity=ai.get(
                    "severity",
                    "Low"
                ),

                confidence="Medium",

                detected_by=[
                    "AI"
                ],

                description=ai.get(
                    "description",
                    ""
                ),

                why_this_matters=ai.get(
                    "why_this_matters",
                    DEFAULT_EXPLANATION
                ),

                fix=ai.get(
                    "fix",
                    "Manual review recommended."
                ),

                fixed_code=ai.get(
                    "fixed_code",
                    ""
                )

            )

        )

    return merged