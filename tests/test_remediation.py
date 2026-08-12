from core.aws_ingestion import load_mock_aws_data
from remediation.engine import (
    build_remediation_plan,
    execute_remediation_plan
)


def test_critical_remediation_plan():
    findings = [
        {
            "rule": "PUBLIC_DATABASE_EXPOSURE",
            "severity": "CRITICAL",
            "message": "Private database has direct internet access.",
            "path": ["internet", "database"]
        }
    ]

    plan = build_remediation_plan(findings)

    assert len(plan) == 1
    assert plan[0]["rule"] == "PUBLIC_DATABASE_EXPOSURE"
    assert plan[0]["severity"] == "CRITICAL"
    assert plan[0]["action"] == (
        "Immediately remove the unsafe public access."
    )


def test_remediation_execution():
    data = load_mock_aws_data()

    remediation_plan = [
        {
            "rule": "PUBLIC_DATABASE_EXPOSURE",
            "severity": "CRITICAL",
            "action": "Immediately remove the unsafe public access."
        }
    ]

    results = execute_remediation_plan(
        data,
        remediation_plan
    )

    assert len(results) == 1
    assert results[0]["rule"] == "PUBLIC_DATABASE_EXPOSURE"
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["fixed"] is True


def test_remediation_removes_public_database_access():
    data = load_mock_aws_data()

    remediation_plan = [
        {
            "rule": "PUBLIC_DATABASE_EXPOSURE",
            "severity": "CRITICAL",
            "action": "Immediately remove the unsafe public access."
        }
    ]

    execute_remediation_plan(
        data,
        remediation_plan
    )

    for connection in data["connections"]:
        assert not (
            connection["source"] == "internet"
            and connection["target"] == "database"
        )