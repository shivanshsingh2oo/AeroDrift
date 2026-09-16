import streamlit as st

from core.aws_ingestion import load_mock_aws_data
from core.topology import build_topology, get_topology_diff

from detection.drift_detector import detect_database_exposure
from detection.rules import run_security_rules

from remediation.engine import (
    build_remediation_plan,
    execute_remediation_plan
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AeroDrift Security",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 18px;
        margin-bottom: 20px;
    }

    .status-box {
        padding: 20px;
        border-radius: 12px;
        margin: 15px 0;
    }

    .secure {
        background-color: #e8f5e9;
        border-left: 6px solid #2e7d32;
    }

    .danger {
        background-color: #ffebee;
        border-left: 6px solid #c62828;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">'
    '🛡️ AeroDrift Security Dashboard'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Agentic Cloud Topology & Remediation Graph'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# ============================================================
# LOAD CLOUD DATA
# ============================================================

data = load_mock_aws_data()


# ============================================================
# BUILD ORIGINAL TOPOLOGY
# ============================================================

before_graph = build_topology(data)


# ============================================================
# DRIFT DETECTION
# ============================================================

result = detect_database_exposure(
    before_graph
)


# ============================================================
# SECURITY RULES
# ============================================================

findings = run_security_rules(
    before_graph
)


# ============================================================
# SECURITY COUNTS
# ============================================================

critical_count = sum(
    1
    for finding in findings
    if finding["severity"] == "CRITICAL"
)

high_count = sum(
    1
    for finding in findings
    if finding["severity"] == "HIGH"
)

medium_count = sum(
    1
    for finding in findings
    if finding["severity"] == "MEDIUM"
)

low_count = sum(
    1
    for finding in findings
    if finding["severity"] == "LOW"
)


# ============================================================
# SECURITY SCORE
# ============================================================

security_score = 100

security_score -= critical_count * 40
security_score -= high_count * 20
security_score -= medium_count * 10
security_score -= low_count * 5

security_score = max(
    0,
    min(100, security_score)
)


# ============================================================
# RESOURCE INFORMATION
# ============================================================

resource_count = len(
    data["resources"]
)

connection_count = len(
    before_graph.edges()
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ AeroDrift")

    st.write(
        "Cloud Security Control Center"
    )

    st.divider()

    st.metric(
        "Security Score",
        f"{security_score}/100"
    )

    st.metric(
        "Resources",
        resource_count
    )

    st.metric(
        "Connections",
        connection_count
    )

    st.divider()

    st.info(
        "AeroDrift detects cloud topology "
        "drift and automatically generates "
        "remediation actions."
    )


# ============================================================
# TOP METRICS
# ============================================================

st.header("📊 Security Overview")


col1, col2, col3, col4, col5 = st.columns(5)


with col1:

    st.metric(
        "Security Findings",
        len(findings)
    )


with col2:

    st.metric(
        "Critical",
        critical_count
    )


with col3:

    st.metric(
        "Drift",
        "YES"
        if result["drift_detected"]
        else "NO"
    )


with col4:

    st.metric(
        "Resources",
        resource_count
    )


with col5:

    st.metric(
        "Security Score",
        f"{security_score}/100"
    )


st.divider()


# ============================================================
# SECURITY SCORE
# ============================================================

st.header("🎯 Security Score")


if security_score >= 80:

    st.success(
        f"🟢 Excellent Security Score — "
        f"{security_score}/100"
    )

elif security_score >= 60:

    st.warning(
        f"🟡 Moderate Security Score — "
        f"{security_score}/100"
    )

else:

    st.error(
        f"🔴 Critical Security Risk — "
        f"{security_score}/100"
    )


st.progress(
    security_score / 100
)


st.divider()


# ============================================================
# SECURITY STATUS
# ============================================================

st.header("🚨 Security Status")


if result["drift_detected"]:

    st.markdown(
        f"""
        <div class="status-box danger">

        <h3>🚨 SECURITY DRIFT DETECTED</h3>

        <p>{result["message"]}</p>

        <b>Attack Path:</b>
        {" → ".join(result["path"])}

        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        """
        <div class="status-box secure">

        <h3>✅ SYSTEM SECURE</h3>

        <p>
        Private database is not reachable
        from the internet.
        </p>

        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# SECURITY ANALYTICS
# ============================================================

st.header("📈 Security Analytics")


analytics_col1, analytics_col2 = st.columns(2)


# ============================================================
# SEVERITY CHART
# ============================================================

with analytics_col1:

    st.subheader(
        "Severity Breakdown"
    )

    severity_data = {
        "Critical": critical_count,
        "High": high_count,
        "Medium": medium_count,
        "Low": low_count
    }

    st.bar_chart(
        severity_data
    )


# ============================================================
# SCORE BREAKDOWN
# ============================================================

with analytics_col2:

    st.subheader(
        "Security Posture"
    )

    st.metric(
        "Current Security Score",
        f"{security_score}/100"
    )

    st.progress(
        security_score / 100
    )

    st.write(
        f"🔴 Critical: {critical_count}"
    )

    st.write(
        f"🟠 High: {high_count}"
    )

    st.write(
        f"🟡 Medium: {medium_count}"
    )

    st.write(
        f"🔵 Low: {low_count}"
    )


st.divider()


# ============================================================
# SECURITY FINDINGS
# ============================================================

st.header("🔍 Security Findings")


if findings:

    for finding in findings:

        severity = finding["severity"]

        if severity == "CRITICAL":

            st.error(
                f"🔴 {finding['rule']} — "
                f"{severity}"
            )

        elif severity == "HIGH":

            st.warning(
                f"🟠 {finding['rule']} — "
                f"{severity}"
            )

        elif severity == "MEDIUM":

            st.warning(
                f"🟡 {finding['rule']} — "
                f"{severity}"
            )

        else:

            st.info(
                f"🔵 {finding['rule']} — "
                f"{severity}"
            )

        st.write(
            finding["message"]
        )

        st.code(
            " → ".join(
                finding["path"]
            )
        )

else:

    st.success(
        "No security findings detected."
    )


st.divider()


# ============================================================
# CLOUD TOPOLOGY
# ============================================================

st.header("🌐 Cloud Topology")

st.write(
    "Visual representation of the current "
    "cloud network topology."
)


topology_data = """
digraph {

    rankdir=LR;

    graph [
        bgcolor="transparent",
        nodesep=0.8,
        ranksep=1.2
    ];

    node [
        shape=box,
        style="rounded,filled",
        fontname="Arial",
        fontsize=12
    ];

    internet [
        label="Internet",
        fillcolor="#E3F2FD"
    ];

    subnet_public [
        label="Public Subnet",
        fillcolor="#E8F5E9"
    ];

    web_server [
        label="Web Server",
        fillcolor="#E8F5E9"
    ];

    subnet_private [
        label="Private Subnet",
        fillcolor="#E8F5E9"
    ];

    database [
        label="Database",
        fillcolor="#FFEBEE",
        color="#C62828",
        penwidth=2
    ];

    internet -> subnet_public [
        label=" SAFE "
    ];

    subnet_public -> web_server [
        label=" SAFE "
    ];

    web_server -> subnet_private [
        label=" SAFE "
    ];

    internet -> database [
        label=" DRIFT ",
        color="#C62828",
        fontcolor="#C62828",
        penwidth=3
    ];

}
"""


st.graphviz_chart(
    topology_data,
    use_container_width=True
)


topology_col1, topology_col2 = st.columns(2)


with topology_col1:

    st.metric(
        "Cloud Resources",
        resource_count
    )


with topology_col2:

    st.metric(
        "Network Connections",
        connection_count
    )


st.divider()


# ============================================================
# REMEDIATION PLAN
# ============================================================

st.header("🔧 Remediation Plan")


remediation_plan = build_remediation_plan(
    findings
)


if remediation_plan:

    for item in remediation_plan:

        st.warning(
            f"""
**Rule:** {item["rule"]}

**Severity:** {item["severity"]}

**Message:** {item["message"]}

**Action:** {item["action"]}
"""
        )

else:

    st.success(
        "No remediation required."
    )


st.divider()


# ============================================================
# AUTO REMEDIATION
# ============================================================

st.header("🚀 Auto Remediation")


if remediation_plan:

    st.write(
        "Execute the generated remediation "
        "plan against the mock cloud topology."
    )

    if st.button(
        "🚀 Run Auto Remediation",
        use_container_width=True
    ):

        execution_results = (
            execute_remediation_plan(
                data,
                remediation_plan
            )
        )


        st.success(
            "Remediation execution completed."
        )


        # ====================================================
        # EXECUTION RESULTS
        # ====================================================

        for execution in execution_results:

            if execution.get("fixed"):

                st.success(
                    f"✅ {execution['action']}"
                )

            else:

                st.error(
                    f"❌ Remediation failed: "
                    f"{execution.get('rule', 'Unknown rule')}"
                )


        # ====================================================
        # FIXED TOPOLOGY
        # ====================================================

        fixed_graph = build_topology(
            data
        )


        # ====================================================
        # VERIFICATION
        # ====================================================

        verification = detect_database_exposure(
            fixed_graph
        )


        st.divider()

        st.header("✅ Verification")


        if verification["drift_detected"]:

            st.error(
                "🚨 Security drift still detected."
            )

            st.write(
                verification["message"]
            )

        else:

            st.success(
                "✅ SYSTEM SECURE"
            )

            st.write(
                verification["message"]
            )


        # ====================================================
        # TOPOLOGY DIFF
        # ====================================================

        st.header("📊 Topology Diff")


        diff = get_topology_diff(
            before_graph,
            fixed_graph
        )


        diff_col1, diff_col2 = st.columns(2)


        with diff_col1:

            st.subheader(
                "🔴 Removed Connections"
            )


            if diff["removed_connections"]:

                for connection in diff[
                    "removed_connections"
                ]:

                    st.write(
                        f"🔴 {connection[0]} "
                        f"→ "
                        f"{connection[1]}"
                    )

            else:

                st.write(
                    "No connections removed."
                )


        with diff_col2:

            st.subheader(
                "🟢 Added Connections"
            )


            if diff["added_connections"]:

                for connection in diff[
                    "added_connections"
                ]:

                    st.write(
                        f"🟢 {connection[0]} "
                        f"→ "
                        f"{connection[1]}"
                    )

            else:

                st.write(
                    "No new connections."
                )

else:

    st.info(
        "System is already secure. "
        "No remediation is required."
    )


st.divider()


# ============================================================
# SECURITY SUMMARY
# ============================================================

st.header("📋 Security Summary")


summary_col1, summary_col2 = st.columns(2)


with summary_col1:

    st.write(
        f"**Security Score:** "
        f"{security_score}/100"
    )

    st.write(
        f"**Total Findings:** "
        f"{len(findings)}"
    )

    st.write(
        f"**Critical Findings:** "
        f"{critical_count}"
    )

    st.write(
        f"**High Findings:** "
        f"{high_count}"
    )


with summary_col2:

    st.write(
        f"**Medium Findings:** "
        f"{medium_count}"
    )

    st.write(
        f"**Low Findings:** "
        f"{low_count}"
    )

    st.write(
        f"**Cloud Resources:** "
        f"{resource_count}"
    )

    st.write(
        f"**Network Connections:** "
        f"{connection_count}"
    )


st.divider()


# ============================================================
# FOOTER
# ============================================================

st.caption(
    "AeroDrift • Agentic Cloud Security • "
    "Drift Detection • Automated Remediation"
)