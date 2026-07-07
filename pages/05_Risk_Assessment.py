import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import os
from utils import SEVERITY_MAPPING, calculate_risk_score, get_risk_action

st.set_page_config(page_title="Risk Assessment", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

if 'attack_labels' not in st.session_state:
    st.warning("Please run the Attack Classification module first.")
    st.stop()

st.title("Risk Assessment Engine")
st.markdown("Calculates dynamic risk scores based on Threat Severity, Prediction Confidence, and Attack Frequency.")

attack_labels = st.session_state['attack_labels']
attack_probs = st.session_state['attack_probabilities']
total_traffic = len(st.session_state['processed_df'])

# Calculate risks for each unique attack detected
unique_attacks, counts = np.unique(attack_labels, return_counts=True)
risk_data = []

for attack, count in zip(unique_attacks, counts):
    if attack == "Benign Traffic":
        continue
        
    # Get indices for this attack to find average confidence
    indices = np.where(attack_labels == attack)[0]
    avg_conf = np.mean(np.max(attack_probs[indices], axis=1))
    
    severity = SEVERITY_MAPPING.get(attack, 0)
    freq_ratio = count / total_traffic if total_traffic > 0 else 0
    
    risk_score = calculate_risk_score(severity, avg_conf, freq_ratio)
    action = get_risk_action(risk_score)
    
    risk_data.append({
        "Attack": attack,
        "Severity": severity,
        "Confidence": f"{avg_conf*100:.1f}%",
        "Frequency %": f"{freq_ratio*100:.2f}%",
        "Risk Score": risk_score,
        "Recommended Action": action
    })

if not risk_data:
    st.success("No risks to assess.")
    st.stop()

risk_df = pd.DataFrame(risk_data).sort_values(by="Risk Score", ascending=False)

st.markdown("### Top Risks Identified")

for i, (_, row) in enumerate(risk_df.iterrows()):
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        st.markdown(f"**{row['Attack']}**")
        if row['Recommended Action'] == "BLOCK TRAFFIC":
            st.error(f"ACTION: {row['Recommended Action']}")
        elif row['Recommended Action'] == "QUARANTINE DEVICE":
            st.warning(f"ACTION: {row['Recommended Action']}")
        elif row['Recommended Action'] == "MONITOR DEVICE":
            st.info(f"ACTION: {row['Recommended Action']}")
        else:
            st.success(f"ACTION: {row['Recommended Action']}")
            
    with col2:
        fig_risk = go.Figure(go.Indicator(
            mode="gauge+number",
            value=row['Risk Score'],
            number={'font': {'color': '#1e293b', 'size': 32}},
            gauge={
                'axis': {'range': [0, 10], 'tickcolor': "#475569"},
                'bar': {'color': "#dc2626" if row['Risk Score'] > 8 else "#d97706" if row['Risk Score'] > 4 else "#16a34a"},
                'bgcolor': "#e2e8f0",
                'borderwidth': 1,
                'bordercolor': "#cbd5e1",
                'steps': [
                    {'range': [0, 2], 'color': "rgba(22, 163, 74, 0.1)"},    # Allow
                    {'range': [2, 6], 'color': "rgba(37, 99, 235, 0.1)"},   # Monitor
                    {'range': [6, 8], 'color': "rgba(217, 119, 6, 0.1)"},   # Quarantine
                    {'range': [8, 10], 'color': "rgba(220, 38, 38, 0.1)"}    # Block
                ]
            }
        ))
        fig_risk.update_layout(
            height=180,
            margin=dict(l=20, r=20, t=30, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            font={'color': "#1e293b"}
        )
        st.plotly_chart(fig_risk, use_container_width=True, key=f"risk_gauge_{i}")
        
    with col3:
        st.write(f"- **Severity:** {row['Severity']}/10")
        st.write(f"- **Confidence:** {row['Confidence']}")
        st.write(f"- **Frequency:** {row['Frequency %']}")
        
    st.markdown("---")

st.markdown("### Risk Categories Legend")
st.markdown("""
- **0–2 (Allow):** Low risk, normal operation.
- **3–6 (Monitor):** Suspicious, requires logging and monitoring.
- **7–8 (Quarantine):** High risk, isolate the affected device.
- **9–10 (Block):** Critical risk, immediately block traffic at the firewall.
""")
