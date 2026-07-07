import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import os
from utils import load_models, FAMILY_MAPPING

st.set_page_config(page_title="Attack Classification", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

if 'data_loaded' not in st.session_state or not st.session_state['data_loaded']:
    st.warning("Please upload a CSV file in the sidebar to begin analysis.")
    st.stop()

# Ensure binary predictions exist
if 'binary_predictions' not in st.session_state:
    st.error("Please run the Binary IDS module first to identify malicious traffic.")
    st.stop()

st.title("Attack Classification")
st.markdown("This module analyzes **only malicious traffic** to identify specific attack types.")

feature_names, attack_label_encoder, binary_ids_model, multiclass_ids_model = load_models()
processed_df = st.session_state['processed_df']
binary_predictions = st.session_state['binary_predictions']

# Filter only malicious
malicious_indices = np.where(binary_predictions == 1)[0]

if len(malicious_indices) == 0:
    st.success("No malicious traffic detected! The network is secure.")
    st.stop()

malicious_df = processed_df.iloc[malicious_indices]

with st.spinner("Running Multi-Class IDS Model..."):
    attack_predictions = multiclass_ids_model.predict(malicious_df)
    attack_probabilities = multiclass_ids_model.predict_proba(malicious_df)
    
    # Map predictions back to labels
    attack_labels = attack_label_encoder.inverse_transform(attack_predictions)
    
    # Save to session for subsequent pages
    st.session_state['attack_labels'] = attack_labels
    st.session_state['attack_probabilities'] = attack_probabilities
    st.session_state['malicious_indices'] = malicious_indices

# Calculate stats
unique_attacks, counts = np.unique(attack_labels, return_counts=True)
attack_dist = pd.DataFrame({'Attack Type': unique_attacks, 'Count': counts}).sort_values(by='Count', ascending=False)
attack_dist['Family'] = attack_dist['Attack Type'].map(FAMILY_MAPPING)

most_frequent = attack_dist.iloc[0]['Attack Type']
st.markdown("### Attack Trend Summary")

col1, col2 = st.columns(2)
with col1:
    st.metric("Total Malicious Flows Processed", f"{len(malicious_df):,}")
with col2:
    st.metric("Most Frequent Attack", most_frequent)

st.markdown("---")
st.markdown("### Attack Distribution")

col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    fig_bar = px.bar(
        attack_dist, 
        x='Count', 
        y='Attack Type', 
        orientation='h',
        color='Family',
        title="Attack Counts by Type"
    )
    fig_bar.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#1e293b",
        legend=dict(font=dict(color="#1e293b"))
    )
    st.plotly_chart(fig_bar, use_container_width=True)

with col_chart2:
    family_dist = attack_dist.groupby('Family')['Count'].sum().reset_index()
    fig_pie = px.pie(
        family_dist, 
        values='Count', 
        names='Family', 
        title="Attack Families",
        hole=0.4
    )
    fig_pie.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#1e293b",
        legend=dict(font=dict(color="#1e293b"))
    )
    st.plotly_chart(fig_pie, use_container_width=True)

st.markdown("### Attack Ranking Table")
st.dataframe(attack_dist.style.background_gradient(cmap='Reds', subset=['Count']), use_container_width=True)
