import streamlit as st
import pandas as pd
import os
import numpy as np

# Set page config
st.set_page_config(
    page_title="Explainability (XAI) Layer",
    page_icon="🛡️",
    layout="wide"
)

# Load CSS custom style rules
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

# --- Title Header ---
st.title("Explainable AI (XAI) Dashboard")
st.markdown(
    "<p style='color:#64748b;margin-top:-0.8rem;margin-bottom:1.5rem;font-size:0.9rem;'>"
    "Global Interpretability and Feature Importance Analysis for Intrusion Detection Models."
    "</p>",
    unsafe_allow_html=True
)

# --- Section 1: What is Explainable AI ---
st.markdown("### 1. Explainable AI (XAI) Framework")
with st.expander("🛡️ What is Explainable AI & SHAP in cybersecurity operations?", expanded=True):
    st.markdown("""
    Explainable AI (XAI) is a set of processes and methods that allows human users to comprehend and trust the results and outputs created by machine learning algorithms. In cybersecurity, XAI is essential because traditional "black-box" models can make predictions without providing any reasoning, leaving analysts in the dark about **why** a specific alert was triggered.

    #### Key Concepts of XAI in the Security Operations Center (SOC)
    * **SHAP (SHapley Additive exPlanations):** A game theoretic approach to explain the output of any machine learning model. It connects optimal local attribution with classical Shapley values from game theory, assigning each feature an importance score representing its contribution to a model prediction.
    * **Why Explainability Matters:** 
      * **Trust & Verification:** Analysts must verify that models are making decisions based on legitimate security indicators (like packet behavior) rather than random noise or coincidental correlation.
      * **Root Cause Analysis:** Knowing which features triggered an alert helps incident responders identify the exact type of scan or attack footprint.
      * **False Positive Reduction:** Understanding feature contributions allows security engineers to fine-tune network sensors and reduce alert fatigue.
    """)

# --- Helper Functions for Loading Data ---
def load_importance_csv(filepath):
    if os.path.exists(filepath):
        try:
            df = pd.read_csv(filepath)
            # Ensure columns are named correctly
            if len(df.columns) >= 2:
                df.columns = ["Feature", "Importance"]
            df["Importance"] = df["Importance"].astype(float)
            return df.sort_values(by="Importance", ascending=False)
        except Exception as e:
            st.error(f"Error reading {filepath}: {e}")
            return None
    return None

# Load CSV files
binary_df = load_importance_csv("binary_feature_importance.csv")
multiclass_df = load_importance_csv("multiclass_feature_importance.csv")

# Dynamic analyst insights generator
def generate_analyst_insights(df, model_type="Binary"):
    if df is None or df.empty:
        return [f"The {model_type} model importance dataset is not available to generate insights."]
    
    top_features = df["Feature"].tolist()
    
    top_1 = top_features[0] if len(top_features) > 0 else "N/A"
    top_2 = top_features[1] if len(top_features) > 1 else "N/A"
    top_3 = top_features[2] if len(top_features) > 2 else "N/A"
    
    insights = []
    
    if model_type == "Binary":
        insights.append(
            f"The **Binary IDS** relies heavily on **{top_1}** and **{top_2}** when determining whether traffic is malicious."
        )
        # Check domain focus
        categories = []
        for f in top_features[:6]:
            fl = f.lower()
            if 'iat' in fl or 'duration' in fl or 'idle' in fl or 'active' in fl:
                categories.append("traffic timing / inter-arrival behaviors")
            elif 'length' in fl or 'bytes' in fl or 'size' in fl or 'packet' in fl or 'volume' in fl:
                categories.append("traffic volume / packet behavior characteristics")
            elif 'flag' in fl or 'count' in fl or 'flags' in fl:
                categories.append("TCP flag structures and handshake controls")
            elif 'port' in fl:
                categories.append("targeted network service ports")
        
        unique_cats = list(dict.fromkeys(categories))
        if len(unique_cats) >= 2:
            insights.append(
                f"The model appears to focus primarily on **{unique_cats[0]}** and **{unique_cats[1]}**."
            )
        else:
            insights.append("The model appears to focus on traffic volume and packet behaviour characteristics.")
    else:
        insights.append(
            f"The **Multi-Class IDS** model relies on **{top_1}** and **{top_2}** to distinguish between attack categories."
        )
        insights.append(
            "Certain network flow statistics appear highly influential when differentiating between MQTT, Reconnaissance, DoS, and MITM attacks."
        )
        
    return insights

# --- Section 2 & 3: Binary IDS Explainability & Insights ---
st.markdown("---")
st.markdown("### 2. Binary IDS Explainability")

col_bin_l, col_bin_r = st.columns([1.2, 1.0], gap="large")

with col_bin_l:
    st.markdown("#### Model SHAP Plots")
    # SHAP Summary Plot
    st.markdown("**SHAP Summary Plot (Global Feature Impact)**")
    if os.path.exists("binary_shap_summary.png"):
        st.image("binary_shap_summary.png", caption="Binary IDS SHAP Summary Plot", use_column_width=True)
    else:
        st.warning("⚠️ File 'binary_shap_summary.png' not found. Ensure it is placed in the project root directory.")
        
    # Feature Bar Plot
    st.markdown("**Feature Importance Bar Plot**")
    if os.path.exists("binary_feature_bar.png"):
        st.image("binary_feature_bar.png", caption="Binary IDS Feature Importance Bar Chart", use_column_width=True)
    else:
        st.warning("⚠️ File 'binary_feature_bar.png' not found. Ensure it is placed in the project root directory.")

with col_bin_r:
    st.markdown("#### Feature Influence & Analyst Insights")
    
    if binary_df is not None:
        # Metrics
        most_imp_feature = binary_df.iloc[0]["Feature"]
        num_features = len(binary_df)
        
        met1, met2 = st.columns(2)
        with met1:
            st.metric("Most Important Feature", most_imp_feature)
        with met2:
            st.metric("Number of Features Analyzed", f"{num_features}")
            
        # Top 10 Table
        st.markdown("**Top 10 Most Important Features**")
        top_10_bin = binary_df.head(10).reset_index(drop=True)
        st.dataframe(top_10_bin, use_container_width=True)
        
        # Section 3: Analyst Insights (Binary)
        st.markdown("#### Analyst Insights")
        insights = generate_analyst_insights(binary_df, "Binary")
        for insight in insights:
            st.info(insight)
    else:
        st.warning("⚠️ File 'binary_feature_importance.csv' not found. Unable to render metrics and insights.")

# --- Section 4 & 5: Multi-Class IDS Explainability & Insights ---
st.markdown("---")
st.markdown("### 3. Multi-Class IDS Explainability")

col_multi_l, col_multi_r = st.columns([1.2, 1.0], gap="large")

with col_multi_l:
    st.markdown("#### Model SHAP Plots")
    # SHAP Summary Plot
    st.markdown("**SHAP Summary Plot (Global Feature Impact)**")
    if os.path.exists("multiclass_shap_summary.png"):
        st.image("multiclass_shap_summary.png", caption="Multi-Class IDS SHAP Summary Plot", use_column_width=True)
    else:
        st.warning("⚠️ File 'multiclass_shap_summary.png' not found. Ensure it is placed in the project root directory.")
        
    # Feature Bar Plot
    st.markdown("**Feature Importance Bar Plot**")
    if os.path.exists("multiclass_feature_bar.png"):
        st.image("multiclass_feature_bar.png", caption="Multi-Class IDS Feature Importance Bar Chart", use_column_width=True)
    else:
        st.warning("⚠️ File 'multiclass_feature_bar.png' not found. Ensure it is placed in the project root directory.")

with col_multi_r:
    st.markdown("#### Feature Influence & Analyst Insights")
    
    if multiclass_df is not None:
        # Metrics
        most_imp_multiclass = multiclass_df.iloc[0]["Feature"]
        num_features_multi = len(multiclass_df)
        
        met_m1, met_m2 = st.columns(2)
        with met_m1:
            st.metric("Most Important Feature", most_imp_multiclass)
        with met_m2:
            st.metric("Total Features", f"{num_features_multi}")
            
        # Top 10 Table
        st.markdown("**Top 10 Most Important Features**")
        top_10_multi = multiclass_df.head(10).reset_index(drop=True)
        st.dataframe(top_10_multi, use_container_width=True)
        
        # Section 5: Attack Classification Insights
        st.markdown("#### Attack Classification Insights")
        m_insights = generate_analyst_insights(multiclass_df, "Multi-Class")
        for m_insight in m_insights:
            st.info(m_insight)
    else:
        st.warning("⚠️ File 'multiclass_feature_importance.csv' not found. Unable to render metrics and insights.")

# --- Section 6: Model Comparison ---
st.markdown("---")
st.markdown("### 4. Model Comparison: Detection vs. Classification")
st.markdown(
    "To help analysts understand the difference between **Attack Detection** (Binary IDS) and **Attack Classification** (Multi-Class IDS), "
    "the card below compares the top features that guide each decision."
)

col_comp1, col_comp2 = st.columns(2)

with col_comp1:
    st.markdown("""
    <div style="background-color: #ffffff; padding: 1.5rem; border: 1px solid #e2e8f0; border-radius: 12px; border-top: 3px solid #4f46e5; height: 100%;">
        <h4 style="margin-top:0; color:#0f172a;">Binary IDS Focus</h4>
        <p style="font-size:0.875rem; color:#475569;">
            Responsible for dividing network records cleanly into <strong>Benign</strong> or <strong>Malicious</strong> categories.
        </p>
        <hr style="margin: 0.75rem 0;"/>
        <ul style="font-size:0.875rem; padding-left:1.2rem; color:#475569;">
            <li><strong>Rank 1 Feature:</strong> {}</li>
            <li><strong>Rank 2 Feature:</strong> {}</li>
            <li><strong>Rank 3 Feature:</strong> {}</li>
        </ul>
        <p style="font-size:0.85rem; margin-top: 1rem; color:#64748b; font-style: italic;">
            Decision boundary is typically optimized for identifying baseline shifts, timing variations, and abnormal session lengths.
        </p>
    </div>
    """.format(
        binary_df.iloc[0]["Feature"] if binary_df is not None else "N/A",
        binary_df.iloc[1]["Feature"] if binary_df is not None and len(binary_df) > 1 else "N/A",
        binary_df.iloc[2]["Feature"] if binary_df is not None and len(binary_df) > 2 else "N/A"
    ), unsafe_allow_html=True)

with col_comp2:
    st.markdown("""
    <div style="background-color: #ffffff; padding: 1.5rem; border: 1px solid #e2e8f0; border-radius: 12px; border-top: 3px solid #6366f1; height: 100%;">
        <h4 style="margin-top:0; color:#0f172a;">Multi-Class IDS Focus</h4>
        <p style="font-size:0.875rem; color:#475569;">
            Responsible for pinpointing the exact signature footprint of <strong>14 distinct attack types</strong> (e.g., DoS, MQTT, MITM).
        </p>
        <hr style="margin: 0.75rem 0;"/>
        <ul style="font-size:0.875rem; padding-left:1.2rem; color:#475569;">
            <li><strong>Rank 1 Feature:</strong> {}</li>
            <li><strong>Rank 2 Feature:</strong> {}</li>
            <li><strong>Rank 3 Feature:</strong> {}</li>
        </ul>
        <p style="font-size:0.85rem; margin-top: 1rem; color:#64748b; font-style: italic;">
            Requires fine-grained inspection of protocol flag configurations, packet ratios, and specific destination ports to categorize threats accurately.
        </p>
    </div>
    """.format(
        multiclass_df.iloc[0]["Feature"] if multiclass_df is not None else "N/A",
        multiclass_df.iloc[1]["Feature"] if multiclass_df is not None and len(multiclass_df) > 1 else "N/A",
        multiclass_df.iloc[2]["Feature"] if multiclass_df is not None and len(multiclass_df) > 2 else "N/A"
    ), unsafe_allow_html=True)

# --- Section 7: Cybersecurity Interpretation ---
st.markdown("---")
st.markdown("### 5. Cybersecurity Feature Interpretation")
st.markdown(
    "Understanding why specific features correlate with network attacks is key for analysts validating AI detections. "
    "Below is an educational breakdown of standard network attributes."
)

col_feat_1, col_feat_2 = st.columns(2, gap="medium")

with col_feat_1:
    st.markdown("""
    ##### 🕒 Flow Duration
    * **Cybersecurity Relevance:** The duration of a connection is highly useful for isolating automated processes. Large floods (UDP, ICMP) typically complete in milliseconds as packets are sent in massive parallel bursts. Conversely, stealthy reconnaissance (port scans or OS sweeps) or command and control (C2) channels are designed to linger over hours.
    
    ##### 📦 Packet Length
    * **Cybersecurity Relevance:** Benign network sessions typically follow structured protocol payload sizes (e.g., standard HTTP headers or MQTT publishing values). An attack like **MQTT Malformed** or **DoS TCP Flood** often exhibits highly unusual packet sizes—either zero-byte packets containing only control flags, or oversized payloads trying to exhaust memory storage.
    
    ##### 📊 Flow Bytes/s
    * **Cybersecurity Relevance:** Represents network bandwidth volume. A high Flow Bytes/s rate is a hallmark signature of volumetric attacks (like UDP and TCP flood DoS/DDoS), where the goal is to fully saturate the target server's communication channel and block legitimate queries.
    """)

with col_feat_2:
    st.markdown("""
    ##### 📈 Packet Rate
    * **Cybersecurity Relevance:** Indicates packet injection density. While normal operations are governed by user-triggered requests and sensor reporting frequencies, malicious scripts trigger automated loops, generating high packet-per-second rates. This is crucial for detecting SYN floods and scanning sweeps.
    
    ##### 🌐 Protocol
    * **Cybersecurity Relevance:** Different attack families target specific protocol boundaries. For example, MQTT attacks are confined to TCP protocol pipelines on port 1883 or 8883. ICMP flood attacks strictly use the ICMP protocol to request echo replies. Correlating the feature importance of the protocol ensures the classifier correctly separates TCP-based spoofing from UDP-based volumetric floods.
    """)
