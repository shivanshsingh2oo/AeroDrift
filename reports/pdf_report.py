from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


def generate_pdf_report(
    result,
    remediation,
    verification,
    diff
):
    filename = "aerodrift_incident_report.pdf"

    document = SimpleDocTemplate(
        filename,
        pagesize=A4
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    story = []

    story.append(
        Paragraph(
            "AERODRIFT INCIDENT REPORT",
            title_style
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Incident:</b> {result['message']}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 10))

    status = (
        "REMEDIATED"
        if not verification["drift_detected"]
        else "DRIFT STILL PRESENT"
    )

    story.append(
        Paragraph(
            f"<b>Status:</b> {status}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "<b>Before Remediation</b>",
            styles["Heading2"]
        )
    )

    before_path = (
        " → ".join(result["path"])
        if result["path"]
        else "No path"
    )

    story.append(
        Paragraph(
            f"Path: {before_path}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "<b>Remediation Action</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            remediation["action"],
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "<b>Topology Diff</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            f"Removed Connections: {diff['removed_connections']}",
            styles["BodyText"]
        )
    )

    story.append(
        Paragraph(
            f"Added Connections: {diff['added_connections']}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "<b>After Remediation</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            f"Message: {verification['message']}",
            styles["BodyText"]
        )
    )

    after_path = (
        " → ".join(verification["path"])
        if verification["path"]
        else "No path"
    )

    story.append(
        Paragraph(
            f"Path: {after_path}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 15))

    final_status = (
        "SECURE"
        if not verification["drift_detected"]
        else "DRIFT STILL DETECTED"
    )

    story.append(
        Paragraph(
            f"<b>Verification:</b> {final_status}",
            styles["BodyText"]
        )
    )

    document.build(story)

    return filename