"""ForensiX analyst review interface (M6-02).

Minimal Streamlit UI - no complex front-end framework, per the project's
original scope decision. Displays pending detections with their full risk
assessment and justification chain, and lets the analyst approve or
correct the conclusion via M6-01's apply_analyst_override().
"""

import streamlit as st

from forensix.db import SessionLocal
from forensix.interface.data_access import list_pending_detections
from forensix.risk.override import VALID_PRIORITIES, VALID_RISK_CATEGORIES, apply_analyst_override

st.set_page_config(page_title="ForensiX - Analyst Review", layout="wide")
st.title("ForensiX - Analyst Review")

session = SessionLocal()

pending = list_pending_detections(session)

if not pending:
    st.info("No pending detections awaiting review.")
else:
    st.subheader(f"Pending detections ({len(pending)})")

    labels = [
        f"{item.risk.risk_category.upper()} / {item.risk.priority} - "
        f"{item.event.host} - {', '.join(item.techniques) or 'no technique mapped'}"
        for item in pending
    ]
    selected_index = st.selectbox(
        "Select a detection to review", range(len(pending)), format_func=lambda i: labels[i]
    )
    selected = pending[selected_index]

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Event")
        st.write(f"**Host:** {selected.event.host}")
        st.write(f"**Timestamp:** {selected.event.timestamp}")
        st.write(f"**Process:** {selected.event.process_name or '-'}")
        st.write(f"**Command line:** {selected.event.process_command_line or '-'}")
        st.write(f"**ATT&CK techniques:** {', '.join(selected.techniques) or 'none mapped'}")

    with col2:
        st.markdown("### ForensiX Assessment (original, immutable)")
        st.write(f"**Confidence:** {selected.risk.confidence:.3f}")
        st.write(f"**Severity:** {selected.risk.severity}")
        st.write(f"**Host criticality:** {selected.risk.host_criticality}")
        st.write(f"**Risk score:** {selected.risk.risk_score:.3f}")
        st.write(f"**Risk category:** {selected.risk.risk_category}")
        st.write(f"**Priority:** {selected.risk.priority}")

    st.divider()
    st.markdown("### Analyst decision")

    action = st.radio("Action", ["Approve as-is", "Correct risk assessment"])

    if action == "Approve as-is":
        if st.button("Confirm approval"):
            apply_analyst_override(
                session,
                selected.risk,
                selected.risk.risk_category,
                selected.risk.priority,
                "Approved as-is by analyst",
            )
            st.success("Detection approved. Refresh to see the next pending item.")
    else:
        new_category = st.selectbox("Corrected risk category", sorted(VALID_RISK_CATEGORIES))
        new_priority = st.selectbox("Corrected priority", sorted(VALID_PRIORITIES))
        reason = st.text_area("Reason (required)")

        if st.button("Confirm correction"):
            if not reason.strip():
                st.error("A reason is required to override the risk assessment.")
            else:
                apply_analyst_override(session, selected.risk, new_category, new_priority, reason)
                st.success("Override recorded. Refresh to see the next pending item.")
