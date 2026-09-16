import streamlit as st
import networkx as nx

from core.aws_ingestion import load_mock_aws_data
from core.topology import build_topology, get_topology_diff
from detection.drift_detector import detect_database_exposure
from detection.rules import run_security_rules

from remediation.engine import (
    build_remediation_plan,
    execute_remediation_plan
)


# ============================================================
# PAGE CONFIGURATION
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
        font-size: 20px;
        margin-bottom: 25px;
    }

    .status-box {
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
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
    '<div class="main-title">🛡️ AeroDrift Security Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Agentic Cloud Topology & Remediation Graph</div>',
    unsafe_allow_html=True
)

st.divider()


# ============================================================
# LOAD MOCK CLOUD DATA
# ============================================================

data = load_mock_aws_data()


# ============================================================
# BUILD ORIGINAL TOPOLOGY
# ============================================================

before_graph = build_topology(data)


# ============================================================
# DETECT SECURITY DRIFT
# ============================================================

result = detect_database_exposure(
    before_graph
)


# ============================================================
# RUN SECURITY RULES
# ============================================================

findings = run_security_rules(
    before_graph
)


# ============================================================
# DASHBOARD METRICS
# ============================================================

critical_count = sum(
    1
    for finding in findings
    if finding["severity"] == "CRITICAL"
)

resource_count = len(data["resources"])

connection_count = len(
    before_graph.edges()
)


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        label="Security Findings",
        value=len(findings)
    )


with col2:

    st.metric(
        label="Critical",
        value=critical_count
    )


with col3:

    st.metric(
        label="Drift Detected",
        value="YES" if result["drift_detected"] else "NO"
    )


with col4:

    st.metric(
        label="Resources",
        value=resource_count
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
        Private database is not reachable from the internet.
        </p>

        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# SECURITY FINDINGS
# ============================================================

st.header("🔍 Security Findings")


if findings:

    for finding in findings:

        severity = finding["severity"]

        if severity == "CRITICAL":

            st.error(
                f"🔴 {finding['rule']} — {severity}"
            )

        elif severity == "HIGH":

            st.warning(
                f"🟠 {finding['rule']} — {severity}"
            )

        else:

            st.info(
                f"🔵 {finding['rule']} — {severity}"
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
    "Visual representation of the current cloud network."
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
        label="🌐 Internet",
        fillcolor="#E3F2FD"
    ];

    subnet_public [
        label="📦 Public Subnet",
        fillcolor="#E8F5E9"
    ];

    web_server [
        label="🖥️ Web Server",
        fillcolor="#E8F5E9"
    ];

    subnet_private [
        label="🔒 Private Subnet",
        fillcolor="#E8F5E9"
    ];

    database [
        label="🗄️ Database",
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


st.caption(
    f"Resources: {resource_count} | "
    f"Connections: {connection_count}"
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
            f"**Rule:** {item['rule']}\n\n"
            f"**Severity:** {item['severity']}\n\n"
            f"**Action:** {item['action']}"
        )

else:

    st.success(
        "No remediation required."
    )


# ============================================================
# AUTO REMEDIATION
# ============================================================

st.header("🚀 Auto Remediation")


if remediation_plan:

    if st.button(
        "🚀 Run Auto Remediation",
        use_container_width=True
    ):

        execution_results = execute_remediation_plan(
            data,
            remediation_plan
        )

        st.success(
            "Remediation executed successfully."
        )


        # ====================================================
        # SHOW EXECUTION RESULTS
        # ====================================================

        for execution in execution_results:

            if execution.get("fixed"):

                st.success(
                    f"✅ {execution['action']}"
                )

            else:

                st.error(
                    f"❌ Remediation failed for "
                    f"{execution['rule']}"
                )


        # ====================================================
        # BUILD FIXED TOPOLOGY
        # ====================================================

        fixed_graph = build_topology(
            data
        )


        # ====================================================
        # VERIFY REMEDIATION
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


        col1, col2 = st.columns(2)


        with col1:

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


        with col2:

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


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AeroDrift • Agentic Cloud Security • "
    "Drift Detection • Automated Remediation"
)