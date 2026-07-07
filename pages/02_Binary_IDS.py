import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from utils import load_models, process_dataframe

st.set_page_config(page_title="Binary IDS", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

if 'data_loaded' not in st.session_state or not st.session_state['data_loaded']:
    st.warning("Please upload a CSV file in the sidebar to begin analysis.")
    st.stop()

df = st.session_state['df']
feature_names, attack_label_encoder, binary_ids_model, multiclass_ids_model = load_models()

st.title("Binary Intrusion Detection")
st.markdown("This module analyzes network traffic to classify it broadly into **Benign** or **Malicious** flows.")

with st.spinner("Running Binary IDS Model..."):
    processed_df = process_dataframe(df, feature_names)
    predictions = binary_ids_model.predict(processed_df)
    probabilities = binary_ids_model.predict_proba(processed_df)

    # Save to session state so other pages can use it without recomputing
    st.session_state['binary_predictions'] = predictions
    st.session_state['binary_probabilities'] = probabilities
    st.session_state['processed_df'] = processed_df

total_flows = len(df)
malicious_count = sum(predictions)
benign_count = total_flows - malicious_count

# Calculate Health Score (0-100%)
health_score = (benign_count / total_flows) * 100 if total_flows > 0 else 100

st.markdown("### Prediction Summary")
col1, col2 = st.columns(2)
with col1:
    st.metric("Total Benign Flows", f"{benign_count:,}", delta=f"{(benign_count/total_flows)*100:.1f}%")
with col2:
    st.metric("Total Malicious Flows", f"{malicious_count:,}", delta=f"{(malicious_count/total_flows)*100:.1f}%", delta_color="inverse")

st.markdown("---")
st.markdown("### Traffic Health & Confidence")

col_gauge1, col_gauge2 = st.columns(2)

with col_gauge1:
    fig_health = go.Figure(go.Indicator(
        mode="gauge+number",
        value=health_score,
        title={'text': "Traffic Health Score", 'font': {'color': '#1e293b', 'size': 16}},
        number={'suffix': "%", 'font': {'color': '#1e293b', 'size': 36}},
        gauge={
            'axis': {'range': [None, 100], 'tickcolor': "#475569"},
            'bar': {'color': "#16a34a" if health_score > 80 else "#d97706" if health_score > 50 else "#dc2626"},
            'bgcolor': "#e2e8f0",
            'borderwidth': 1,
            'bordercolor': "#cbd5e1",
            'steps': [
                {'range': [0, 50], 'color': "rgba(220, 38, 38, 0.1)"},
                {'range': [50, 80], 'color': "rgba(217, 119, 6, 0.1)"},
                {'range': [80, 100], 'color': "rgba(22, 163, 74, 0.1)"}
            ]
        }
    ))
    fig_health.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#1e293b"},
        margin=dict(l=30, r=30, t=50, b=30),
        height=280
    )
    st.plotly_chart(fig_health, use_container_width=True)

with col_gauge2:
    avg_confidence = probabilities.max(axis=1).mean() * 100
    fig_conf = go.Figure(go.Indicator(
        mode="gauge+number",
        value=avg_confidence,
        title={'text': "Average Model Confidence", 'font': {'color': '#1e293b', 'size': 16}},
        number={'suffix': "%", 'font': {'color': '#1e293b', 'size': 36}},
        gauge={
            'axis': {'range': [None, 100], 'tickcolor': "#475569"},
            'bar': {'color': "#4f46e5"},
            'bgcolor': "#e2e8f0",
            'borderwidth': 1,
            'bordercolor': "#cbd5e1"
        }
    ))
    fig_conf.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#1e293b"},
        margin=dict(l=30, r=30, t=50, b=30),
        height=280
    )
    st.plotly_chart(fig_conf, use_container_width=True)
