import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os

# Define severity mappings for Threat Intelligence
SEVERITY_MAPPING = {
    "MITM ARP Spoofing": 8,
    "Recon Ping Sweep": 3,
    "Recon Port Scan": 4,
    "Recon OS Scan": 4,
    "Recon Vulnerability Scan": 5,
    "MQTT DoS Connect Flood": 7,
    "MQTT DoS Publish Flood": 7,
    "MQTT DDoS Publish Flood": 9,
    "MQTT Malformed": 6,
    "DoS TCP Flood": 8,
    "DoS UDP Flood": 7,
    "DoS ICMP Flood": 7,
    "DDoS UDP Flood": 9,
    "DDoS ICMP Flood": 9,
    "Benign Traffic": 0
}

FAMILY_MAPPING = {
    "MITM ARP Spoofing": "Man-in-the-Middle",
    "Recon Ping Sweep": "Reconnaissance",
    "Recon Port Scan": "Reconnaissance",
    "Recon OS Scan": "Reconnaissance",
    "Recon Vulnerability Scan": "Reconnaissance",
    "MQTT DoS Connect Flood": "MQTT DoS",
    "MQTT DoS Publish Flood": "MQTT DoS",
    "MQTT DDoS Publish Flood": "MQTT DDoS",
    "MQTT Malformed": "MQTT Malformed",
    "DoS TCP Flood": "DoS",
    "DoS UDP Flood": "DoS",
    "DoS ICMP Flood": "DoS",
    "DDoS UDP Flood": "DDoS",
    "DDoS ICMP Flood": "DDoS",
    "Benign Traffic": "None"
}

IMPACT_MAPPING = {
    "MITM ARP Spoofing": "Traffic interception and data manipulation.",
    "Recon Ping Sweep": "Identification of active hosts on the network.",
    "Recon Port Scan": "Identification of open ports and potential attack vectors.",
    "Recon OS Scan": "Gathering OS information to find specific vulnerabilities.",
    "Recon Vulnerability Scan": "Active searching for exploitable flaws.",
    "MQTT DoS Connect Flood": "Broker resource exhaustion, preventing legitimate connections.",
    "MQTT DoS Publish Flood": "Broker overload, message delays, and system lag.",
    "MQTT DDoS Publish Flood": "Severe broker failure and network congestion.",
    "MQTT Malformed": "Protocol parsing errors, potential broker crash.",
    "DoS TCP Flood": "Server resource exhaustion, denial of service.",
    "DoS UDP Flood": "Network bandwidth exhaustion.",
    "DoS ICMP Flood": "Network bandwidth exhaustion.",
    "DDoS UDP Flood": "Massive network bandwidth exhaustion, complete outage.",
    "DDoS ICMP Flood": "Massive network bandwidth exhaustion, complete outage.",
    "Benign Traffic": "Normal network operation."
}

@st.cache_resource
def load_models():
    """Loads and caches the ML models and preprocessing objects."""
    try:
        feature_names = joblib.load("feature_names.pkl")
        attack_label_encoder = joblib.load("attack_label_encoder.pkl")
        binary_ids_model = joblib.load("binary_ids_model.pkl")
        multiclass_ids_model = joblib.load("multiclass_ids_model.pkl")
        return feature_names, attack_label_encoder, binary_ids_model, multiclass_ids_model
    except Exception as e:
        st.error(f"Error loading models: {e}")
        return None, None, None, None

def calculate_risk_score(severity, confidence, frequency_ratio):
    """
    Risk Score = Severity + Prediction Confidence + Attack Frequency
    Normalized to 1-10.
    """
    # Severity is already 0-10
    # Confidence is 0.0 - 1.0 -> map to 0-2? Let's say:
    # frequency_ratio is 0.0 - 1.0 (percent of total traffic) -> map to 0-2?
    # Simple formula: 
    # Weighted: Severity (up to 10) * 0.6 + Confidence (0-1) * 2 + Frequency (0-1) * 2
    # Let's adjust to max 10.
    risk = (severity * 0.6) + (confidence * 2) + (frequency_ratio * 2)
    risk = min(max(risk, 1), 10) # Bound between 1 and 10
    return round(risk, 1)

def get_risk_action(risk_score):
    if risk_score <= 2:
        return "ALLOW TRAFFIC"
    elif risk_score <= 6:
        return "MONITOR DEVICE"
    elif risk_score <= 8:
        return "QUARANTINE DEVICE"
    else:
        return "BLOCK TRAFFIC"

def process_dataframe(df, feature_names):
    """Ensures dataframe matches expected features and handles missing."""
    # Check if we have missing features
    missing_cols = [col for col in feature_names if col not in df.columns]
    
    if missing_cols:
        st.warning(f"Warning: {len(missing_cols)} columns are missing from the uploaded CSV. Filling with zeros.")
        for col in missing_cols:
            df[col] = 0
            
    # Return dataframe with columns exactly as expected by the model
    return df[feature_names]
