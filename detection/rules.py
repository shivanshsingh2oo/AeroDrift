def check_public_database(graph):
    """
    Check whether the private database
    is directly reachable from the internet.
    """

    source = "internet"
    target = "database"

    if graph.has_edge(source, target):
        return {
            "rule": "PUBLIC_DATABASE_EXPOSURE",
            "severity": "CRITICAL",
            "message": "Private database has direct internet access.",
            "path": [source, target]
        }

    return None


def check_public_subnet_database(graph):
    """
    Check whether the database is connected
    to a public subnet.
    """

    if graph.has_edge("subnet-public", "database"):
        return {
            "rule": "DATABASE_IN_PUBLIC_SUBNET",
            "severity": "HIGH",
            "message": "Database is directly connected to a public subnet.",
            "path": ["subnet-public", "database"]
        }

    return None


def run_security_rules(graph):
    findings = []

    database_finding = check_public_database(graph)

    if database_finding:
        findings.append(database_finding)

    public_subnet_finding = check_public_subnet_database(graph)

    if public_subnet_finding:
        findings.append(public_subnet_finding)
    web_database_finding = check_direct_web_database_access(graph)

    if web_database_finding:
     findings.append(web_database_finding)

    return findings
def check_direct_web_database_access(graph):
    """
    Check whether the web server has a direct
    connection to the database.
    """

    if graph.has_edge("web-server", "database"):
        return {
            "rule": "DIRECT_WEB_DATABASE_ACCESS",
            "severity": "MEDIUM",
            "message": "Web server has direct access to the database.",
            "path": ["web-server", "database"]
        }

    return None