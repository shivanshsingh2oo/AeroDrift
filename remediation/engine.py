def get_remediation_action(severity):
    actions = {
        "CRITICAL": "Immediately remove the unsafe public access.",
        "HIGH": "Restrict the resource to a private network.",
        "MEDIUM": "Review the connection and apply least-privilege access."
    }

    return actions.get(
        severity,
        "Review the security finding manually."
    )


def build_remediation_plan(findings):
    plan = []

    for finding in findings:
        action = get_remediation_action(finding["severity"])

        plan.append({
            "rule": finding["rule"],
            "severity": finding["severity"],
            "message": finding["message"],
            "path": finding["path"],
            "action": action
        })

    return plan


def execute_remediation_plan(data, remediation_plan):
    results = []

    for item in remediation_plan:
        if item["rule"] == "PUBLIC_DATABASE_EXPOSURE":
            fixed = apply_mock_remediation(data)

            results.append({
                "rule": item["rule"],
                "severity": item["severity"],
                "action": item["action"],
                "fixed": fixed
            })

    return results


def generate_remediation(result):
    if not result["drift_detected"]:
        return {
            "remediation_required": False,
            "action": "No action required."
        }

    severity = result.get("severity", "CRITICAL")

    action = get_remediation_action(severity)

    return {
        "remediation_required": True,
        "action": action,
        "reason": result["message"],
        "detected_path": result["path"],
        "severity": severity
    }


def apply_mock_remediation(data):
    connections = data["connections"]

    original_count = len(connections)

    data["connections"] = [
        connection
        for connection in connections
        if not (
            connection["source"] == "internet"
            and connection["target"] == "database"
        )
    ]

    return original_count != len(data["connections"])