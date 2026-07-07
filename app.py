import streamlit as st
import streamlit.components.v1 as components
import os

st.set_page_config(
    page_title="AI-Powered IoT SOC Dashboard",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

# --- Sidebar ---
with st.sidebar:
    st.markdown("## IoT SOC Dashboard")
    st.markdown("---")
    
    if 'data_loaded' not in st.session_state:
        st.session_state['data_loaded'] = False
        
    st.markdown("### Model Status")
    
    try:
        from utils import load_models
        feature_names, attack_label_encoder, binary_ids_model, multiclass_ids_model = load_models()
        if feature_names is not None:
            st.markdown("Binary IDS: <span class='status-green'>Active</span>", unsafe_allow_html=True)
            st.markdown("Multi-Class IDS: <span class='status-green'>Active</span>", unsafe_allow_html=True)
        else:
            st.markdown("Binary IDS: <span class='status-red'>Offline</span>", unsafe_allow_html=True)
            st.markdown("Multi-Class IDS: <span class='status-red'>Offline</span>", unsafe_allow_html=True)
    except Exception as e:
        st.markdown("Models: <span class='status-red'>Error Loading</span>", unsafe_allow_html=True)
        
    st.markdown("---")
    
    # Traffic Data Upload with Analyze button and 5s loader
    st.markdown("### Traffic Data Upload")
    uploaded_file = st.file_uploader("Upload Network CSV", type=["csv"])
    
    if uploaded_file is not None:
        # Check if we have already analyzed this specific file
        file_already_analyzed = (
            st.session_state.get('data_loaded', False) and 
            st.session_state.get('file_name') == uploaded_file.name
        )
        
        if not file_already_analyzed:
            if st.button("Analyze", use_container_width=True):
                import time
                import pandas as pd
                
                # Show loader for 5 seconds
                with st.spinner("Evaluating network traffic..."):
                    time.sleep(5)
                
                # Clear old session state variables from previous uploads
                for key in ['binary_predictions', 'binary_probabilities', 'processed_df', 'attack_labels', 'attack_probabilities', 'malicious_indices']:
                    if key in st.session_state:
                        del st.session_state[key]
                
                df = pd.read_csv(uploaded_file)
                st.session_state['df'] = df
                st.session_state['file_name'] = uploaded_file.name
                st.session_state['data_loaded'] = True
                st.success(f"Analysis complete. Loaded: {uploaded_file.name}")
                st.rerun()
        else:
            st.success(f"Loaded: {st.session_state['file_name']}")
        
    st.markdown("---")
    st.markdown("*Use the navigation above to explore the SOC modules.*")

# --- Home Page ---
st.title("AI-Powered IoT SOC Dashboard")
st.markdown(
    "<p style='color:#64748b;margin-top:-0.8rem;margin-bottom:1.5rem;font-size:0.9rem;'>"
    "Real-time network intrusion detection and threat intelligence for IoT environments."
    "</p>",
    unsafe_allow_html=True
)

components.html("""
<!DOCTYPE html>
<html>
<head>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
  body { background: transparent; padding: 4px; }

  .card {
    background: #151f32;
    border: 1px solid #1e293b;
    border-radius: 16px;
    padding: 2.2rem;
    box-shadow: 0 1px 4px rgba(0,0,0,0.2), 0 6px 24px rgba(0,0,0,0.3);
    position: relative;
    overflow: hidden;
  }

  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, #4f46e5, #6366f1);
  }

  .header { margin-bottom: 1.5rem; }

  .badge {
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em; color: #818cf8; margin-bottom: 0.4rem;
  }

  .title {
    font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-bottom: 0.25rem;
  }

  .sub { font-size: 0.85rem; color: #94a3b8; }

  .content {
    color: #cbd5e1; line-height: 1.7; font-size: 0.875rem;
  }

  .content p { margin-bottom: 1rem; }
  .content p:last-child { margin-bottom: 0; }
  
  .content ul {
    margin-left: 1.5rem; margin-top: 0.5rem; margin-bottom: 1rem;
    list-style-type: disc;
  }
  
  .content li {
    margin-bottom: 0.4rem;
  }

  .content strong { color: #ffffff; font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="badge">AI-Powered IoT Security Operations Center</div>
    <h2 class="title">Network Traffic Analysis Gateway</h2>
    <div class="sub">Intelligent Threat Detection and Real-Time Risk Assessment</div>
  </div>

  <div class="content">
    <p>
      To begin analysis, please <strong>upload a network traffic CSV file</strong> using the upload panel located in the sidebar on the left.
    </p>
    <p>
      Once uploaded, the dataset will be processed by our machine learning pipelines to evaluate and catalog network behavior:
    </p>
    <ul>
      <li><strong>Intrusion Detection:</strong> Scan traffic records to distinguish benign activities from malicious attacks.</li>
      <li><strong>Attack Classification:</strong> Automatically categorize identified threats into specific attack families (e.g., DDoS, MITM, Reconnaissance).</li>
      <li><strong>Risk Assessment:</strong> Dynamically compute risk severity scores and recommend corresponding response actions to safeguard the IoT infrastructure.</li>
    </ul>
  </div>
</div>
</body>
</html>
""", height=370)
