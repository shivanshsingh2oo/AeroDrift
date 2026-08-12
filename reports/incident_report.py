from datetime import datetime


def generate_incident_report(
    result,
    remediation,
    verification,
    diff
):
    report = f"""
========================================
        AERODRIFT INCIDENT REPORT
========================================

Generated At:
{datetime.now().isoformat()}

INCIDENT
--------
{result["message"]}

STATUS
------
{"REMEDIATED" if not verification["drift_detected"] else "DRIFT STILL PRESENT"}

BEFORE REMEDIATION
------------------
Path:
{" → ".join(result["path"])}

REMEDIATION ACTION
------------------
{remediation["action"]}

TOPOLOGY DIFF
-------------
Removed Connections:
{diff["removed_connections"]}

Added Connections:
{diff["added_connections"]}

AFTER REMEDIATION
-----------------
Message:
{verification["message"]}

Path:
{" → ".join(verification["path"]) if verification["path"] else "No path"}

VERIFICATION
------------
{"SECURE" if not verification["drift_detected"] else "DRIFT STILL DETECTED"}

========================================
          END OF INCIDENT REPORT
========================================
"""

    return report