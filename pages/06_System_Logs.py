import streamlit as st
import pandas as pd
import numpy as np
import datetime
import os
from utils import SEVERITY_MAPPING, calculate_risk_score, get_risk_action

st.set_page_config(page_title="System Logs", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

if 'attack_labels' not in st.session_state:
    st.warning("Please run the Attack Classification module first to generate logs.")
    st.stop()

st.title("SOC Event Log")
st.markdown("Detailed log of all processed malicious events.")

attack_labels = st.session_state['attack_labels']
attack_probs = st.session_state['attack_probabilities']
malicious_indices = st.session_state['malicious_indices']
total_traffic = len(st.session_state['processed_df'])

unique_attacks, counts = np.unique(attack_labels, return_counts=True)
freq_dict = {atk: count / total_traffic for atk, count in zip(unique_attacks, counts)}

logs = []
current_time = datetime.datetime.now()

for i, (idx, attack) in enumerate(zip(malicious_indices, attack_labels)):
    if attack == "Benign Traffic":
        continue
        
    conf = np.max(attack_probs[i])
    severity = SEVERITY_MAPPING.get(attack, 0)
    freq = freq_dict.get(attack, 0)
    risk_score = calculate_risk_score(severity, conf, freq)
    action = get_risk_action(risk_score)
    
    logs.append({
        "Timestamp": (current_time - datetime.timedelta(seconds=len(malicious_indices)-i)).strftime("%Y-%m-%d %H:%M:%S"),
        "Event ID": f"EVT-{idx}",
        "Attack Type": attack,
        "Severity": severity,
        "Risk Score": risk_score,
        "Action Taken": action
    })

if not logs:
    st.success("No events to log.")
    st.stop()

log_df = pd.DataFrame(logs)

st.markdown(f"### Recent Incidents ({len(log_df)} records)")

# Function to color code rows (light modes compatible)
def color_action(val):
    color = ''
    if val == 'BLOCK TRAFFIC': color = '#fee2e2'
    elif val == 'QUARANTINE DEVICE': color = '#fef3c7'
    elif val == 'MONITOR DEVICE': color = '#dbeafe'
    return f'background-color: {color}'

st.dataframe(log_df.style.map(color_action, subset=['Action Taken']), use_container_width=True)

csv = log_df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="Download Event Log (CSV)",
    data=csv,
    file_name='soc_event_logs.csv',
    mime='text/csv',
)
