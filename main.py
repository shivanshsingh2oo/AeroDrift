from detection.rules import run_security_rules

from reports.pdf_report import generate_pdf_report
from reports.incident_report import generate_incident_report

from rich.table import Table
from rich.console import Console
from rich.panel import Panel

from remediation.engine import (
    generate_remediation,
    build_remediation_plan,
    execute_remediation_plan
)

from database.history import (
    create_database,
    save_drift,
    get_drift_history
)

from core.aws_ingestion import load_mock_aws_data
from core.topology import build_topology, get_topology_diff

from detection.drift_detector import detect_database_exposure


console = Console()


# ============================================================
# 1. LOAD MOCK AWS DATA
# ============================================================

data = load_mock_aws_data()


# ============================================================
# 2. BUILD ORIGINAL TOPOLOGY
# ============================================================

graph = build_topology(data)

before_graph = build_topology(data)


# ============================================================
# 3. DETECT DRIFT
# ============================================================

result = detect_database_exposure(graph)


# ============================================================
# 4. RUN SECURITY RULES
# ============================================================

findings = run_security_rules(graph)

print("\nSecurity Findings:")

findings_table = Table(title="Security Findings")

findings_table.add_column("Rule")
findings_table.add_column("Severity")
findings_table.add_column("Message")
findings_table.add_column("Path")


for finding in findings:
    findings_table.add_row(
        finding["rule"],
        finding["severity"],
        finding["message"],
        " → ".join(finding["path"])
    )


console.print(findings_table)


# ============================================================
# 5. BUILD REMEDIATION PLAN
# ============================================================

remediation_plan = build_remediation_plan(findings)

print("\nRemediation Plan:")

for item in remediation_plan:
    print(item)


# ============================================================
# 6. GENERATE REMEDIATION DETAILS
# ============================================================

if findings:

    primary_finding = findings[0]

    remediation_result = {
        "drift_detected": True,
        "severity": primary_finding["severity"],
        "message": primary_finding["message"],
        "path": primary_finding["path"]
    }

    remediation = generate_remediation(
        remediation_result
    )

else:

    remediation = {
        "remediation_required": False,
        "action": "No action required."
    }


# ============================================================
# 7. EXECUTE REMEDIATION PLAN
# ============================================================

execution_results = execute_remediation_plan(
    data,
    remediation_plan
)

print("\nRemediation Execution:")

for execution in execution_results:
    print(execution)


# ============================================================
# 8. BUILD TOPOLOGY AFTER REMEDIATION
# ============================================================

fixed_graph = build_topology(data)


# ============================================================
# 9. VERIFY REMEDIATION
# ============================================================

verification = detect_database_exposure(
    fixed_graph
)

print("\nVerification Result:")
print(verification)


# ============================================================
# 10. TOPOLOGY DIFF
# ============================================================

diff = get_topology_diff(
    before_graph,
    fixed_graph
)

print("\nTopology Diff:")
print(
    "Removed connections:",
    diff["removed_connections"]
)

print(
    "Added connections:",
    diff["added_connections"]
)


# ============================================================
# 11. INCIDENT REPORT
# ============================================================

report = generate_incident_report(
    result,
    remediation,
    verification,
    diff
)

print("\n")
print(report)


# ============================================================
# 12. GENERATE PDF REPORT
# ============================================================

pdf_file = generate_pdf_report(
    result,
    remediation,
    verification,
    diff
)

print(
    f"\n📄 PDF report generated: {pdf_file}"
)


# ============================================================
# 13. SAVE DRIFT HISTORY
# ============================================================

create_database()

save_drift(
    result,
    remediation
)


# ============================================================
# 14. READ DRIFT HISTORY
# ============================================================

history = get_drift_history()


# ============================================================
# 15. HISTORY TABLE
# ============================================================

table = Table(
    title="AeroDrift History"
)

table.add_column("ID")
table.add_column("Timestamp")
table.add_column("Status")
table.add_column("Path")
table.add_column("Remediation")


for record in history:

    status = (
        "DRIFT"
        if record[2]
        else "SECURE"
    )

    table.add_row(
        str(record[0]),
        record[1],
        status,
        record[4],
        record[5]
    )


console.print(table)


# ============================================================
# 16. FINAL SECURITY STATUS
# ============================================================

if verification["drift_detected"]:

    path = " → ".join(
        verification["path"]
    )

    console.print(
        Panel(
            f"[bold red]🚨 SECURITY DRIFT DETECTED[/bold red]\n\n"
            f"[bold]Message:[/bold] "
            f"{verification['message']}\n"
            f"[bold]Path:[/bold] {path}\n"
            f"[bold]Remediation:[/bold] "
            f"{remediation['action']}",
            title="AeroDrift Security",
            border_style="red"
        )
    )

else:

    console.print(
        Panel(
            "[bold green]✅ SYSTEM SECURE[/bold green]\n\n"
            "Private database is not reachable "
            "from the internet.",
            title="AeroDrift Security",
            border_style="green"
        )
    )