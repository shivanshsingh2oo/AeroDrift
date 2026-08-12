from core.aws_ingestion import load_mock_aws_data
from core.topology import build_topology
from detection.rules import (
    check_public_database,
    check_public_subnet_database,
    check_direct_web_database_access
)


def test_public_database_detection():
    data = load_mock_aws_data()
    graph = build_topology(data)

    result = check_public_database(graph)

    assert result is not None
    assert result["rule"] == "PUBLIC_DATABASE_EXPOSURE"
    assert result["severity"] == "CRITICAL"
    assert result["path"] == ["internet", "database"]


def test_public_subnet_database_detection():
    data = load_mock_aws_data()

    data["connections"].append({
        "source": "subnet-public",
        "target": "database"
    })

    graph = build_topology(data)

    result = check_public_subnet_database(graph)

    assert result is not None
    assert result["rule"] == "DATABASE_IN_PUBLIC_SUBNET"
    assert result["severity"] == "HIGH"


def test_direct_web_database_access():
    data = load_mock_aws_data()

    data["connections"].append({
        "source": "web-server",
        "target": "database"
    })

    graph = build_topology(data)

    result = check_direct_web_database_access(graph)

    assert result is not None
    assert result["rule"] == "DIRECT_WEB_DATABASE_ACCESS"
    assert result["severity"] == "MEDIUM"