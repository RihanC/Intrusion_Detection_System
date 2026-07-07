import streamlit as st
import pandas as pd
import numpy as np
import os
from utils import SEVERITY_MAPPING, FAMILY_MAPPING, IMPACT_MAPPING

st.set_page_config(page_title="Threat Intelligence", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

if 'attack_labels' not in st.session_state:
    st.warning("Please run the Attack Classification module first.")
    st.stop()

attack_labels = st.session_state['attack_labels']
unique_attacks = np.unique(attack_labels)

st.title("Threat Intelligence Engine")
st.markdown("Provides detailed contextual analysis of the detected threats based on internal severity mappings.")

st.markdown("---")

if len(unique_attacks) == 0:
    st.success("No active threats to analyze.")
else:
    for attack in unique_attacks:
        if attack == "Benign Traffic":
            continue
            
        severity = SEVERITY_MAPPING.get(attack, 0)
        family = FAMILY_MAPPING.get(attack, "Unknown")
        impact = IMPACT_MAPPING.get(attack, "Unknown impact.")
        
        # Color coding for severity (professional light mode colors)
        sev_color = "#dc2626" if severity >= 8 else "#d97706" if severity >= 4 else "#16a34a"
        
        with st.expander(f"Threat Profile: {attack} (Severity: {severity}/10)", expanded=True):
            col1, col2 = st.columns([1, 3])
            
            with col1:
                st.markdown(f"**Severity Score:** <span style='color:{sev_color}; font-size:1.5rem; font-weight:bold;'>{severity}/10</span>", unsafe_allow_html=True)
                st.markdown(f"**Attack Family:** `{family}`")
            
            with col2:
                st.markdown("**Potential Impact:**")
                st.info(impact)
                
            st.progress(severity / 10.0)
