import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from utils import load_models, process_dataframe

st.set_page_config(page_title="SOC Overview", page_icon=None, layout="wide")

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

# Check if data is loaded
if 'data_loaded' not in st.session_state or not st.session_state['data_loaded']:
    st.warning("Please upload a CSV file in the sidebar to begin analysis.")
    st.stop()

df = st.session_state['df']
feature_names, attack_label_encoder, binary_ids_model, multiclass_ids_model = load_models()

st.title("Dashboard Overview")

if binary_ids_model is None:
    st.error("Models failed to load. Please ensure the .pkl files are present in the directory.")
    st.stop()

with st.spinner("Processing traffic data..."):
    # Preprocess dataframe
    processed_df = process_dataframe(df, feature_names)
    
    # Run Binary IDS
    predictions = binary_ids_model.predict(processed_df)
    
    # Calculate Metrics
    total_flows = len(df)
    malicious_count = sum(predictions)
    benign_count = total_flows - malicious_count
    detection_rate = (malicious_count / total_flows) * 100 if total_flows > 0 else 0

st.markdown("### Traffic Statistics")

# KPI Cards
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Traffic Flows", f"{total_flows:,}")
col2.metric("Benign Traffic", f"{benign_count:,}")
col3.metric("Malicious Traffic", f"{malicious_count:,}")
col4.metric("Detection Rate", f"{detection_rate:.2f}%")

st.markdown("---")
st.markdown("### Current Security Status")

if malicious_count == 0:
    st.markdown("<h2 class='status-green'>GREEN: No Threats Detected</h2>", unsafe_allow_html=True)
elif detection_rate < 5:
    st.markdown("<h2 class='status-yellow'>YELLOW: Suspicious Activity Detected</h2>", unsafe_allow_html=True)
else:
    st.markdown("<h2 class='status-red'>RED: Significant Threat Detected!</h2>", unsafe_allow_html=True)

st.markdown("---")

col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.markdown("#### Traffic Distribution")
    fig_pie = px.pie(
        values=[benign_count, malicious_count],
        names=["Benign", "Malicious"],
        color=["Benign", "Malicious"],
        color_discrete_map={"Benign": "#16a34a", "Malicious": "#dc2626"},
        hole=0.4
    )
    fig_pie.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#1e293b",
        legend=dict(font=dict(color="#1e293b"))
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with col_chart2:
    st.markdown("#### Detection Volume")
    fig_bar = px.bar(
        x=["Benign", "Malicious"],
        y=[benign_count, malicious_count],
        color=["Benign", "Malicious"],
        color_discrete_map={"Benign": "#16a34a", "Malicious": "#dc2626"},
        text_auto=True
    )
    fig_bar.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#1e293b",
        xaxis_title="Traffic Type",
        yaxis_title="Count",
        showlegend=False
    )
    st.plotly_chart(fig_bar, use_container_width=True)
