![Research](https://img.shields.io/badge/Research-IIIT_Dharwad-blue?style=for-the-badge)
![Machine Learning](https://img.shields.io/badge/Machine-Learning-orange?style=for-the-badge)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-IoT-red?style=for-the-badge)
![Explainable AI](https://img.shields.io/badge/Explainable-AI-success?style=for-the-badge)

<div align="center">

# 🛡️ AI-Powered IoT Security Operations Center (SOC)

### Explainable Intrusion Detection using Machine Learning & SHAP

**Research Internship Project @ IIIT Dharwad**

<img src="https://img.shields.io/badge/Python-3.10-blue?style=for-the-badge&logo=python"/>
<img src="https://img.shields.io/badge/Scikit--Learn-ML-orange?style=for-the-badge&logo=scikitlearn"/>
<img src="https://img.shields.io/badge/Streamlit-Dashboard-red?style=for-the-badge&logo=streamlit"/>
<img src="https://img.shields.io/badge/SHAP-Explainable_AI-success?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge"/>

</div>

---

# 📖 Overview

The rapid growth of **Internet of Things (IoT)** devices has significantly increased the attack surface for modern cyber threats. Traditional Intrusion Detection Systems (IDS) can detect malicious activities but often fail to explain *why* a prediction was made or provide intelligent threat analysis.

This project presents an **AI-Powered IoT Security Operations Center (SOC)** that combines **Machine Learning**, **Explainable AI (SHAP)**, and an interactive **Streamlit Dashboard** to detect, classify, and analyze cyberattacks in IoT environments.

---

# ✨ Key Features

- 🔍 Binary Intrusion Detection (Benign vs Malicious)
- 🎯 Multi-Class Attack Classification
- 📊 Explainable AI using SHAP
- 📈 Interactive Streamlit Dashboard
- 📂 CSV-based Network Traffic Analysis
- 🧠 Threat Intelligence Foundation
- ⚠️ Risk Assessment Framework
- 🔬 Research-Oriented Architecture

---

# 🎯 Attack Categories

| Category | Supported Attacks |
|-----------|------------------|
| **DoS** | TCP Flood, UDP Flood, ICMP Flood |
| **DDoS** | UDP Flood, ICMP Flood |
| **MQTT** | Connect Flood, Publish Flood, DDoS Publish Flood, Malformed |
| **Reconnaissance** | Ping Sweep, Port Scan, OS Scan, Vulnerability Scan |
| **MITM** | ARP Spoofing |
| **Normal** | Benign Traffic |

---

# 🏗️ Project Architecture

```text
                Network Traffic
                       │
                       ▼
              Feature Extraction
                       │
                       ▼
        Binary Intrusion Detection
         (Benign / Malicious)
                       │
          ┌────────────┴────────────┐
          │                         │
      Benign                  Malicious
          │                         │
          ▼                         ▼
   Allow Traffic        Multi-Class IDS
                                │
                                ▼
                 Attack Classification
                                │
                                ▼
                   SHAP Explainability
                                │
                                ▼
               Threat Intelligence Engine
                                │
                                ▼
                  Risk Assessment Engine
                                │
                                ▼
                 Streamlit SOC Dashboard
```

---

# 🤖 Machine Learning Models

## Binary IDS

| Model | Task |
|--------|------|
| Random Forest | Benign vs Malicious |

---

## Multi-Class IDS

| Model | Task |
|--------|------|
| Random Forest | Attack Type Classification |

**Overall Accuracy:** **98.53%**

---

# 🧠 Explainable AI (XAI)

The project integrates **SHAP (SHapley Additive Explanations)** to improve model transparency.

### Generated Outputs

- SHAP Summary Plot
- Global Feature Importance
- Feature Ranking
- Binary IDS Explainability
- Multi-Class IDS Explainability

These insights help security analysts understand **why** an attack was detected instead of simply viewing the prediction.

---

# 🖥️ Streamlit SOC Dashboard

The dashboard provides:

- CSV Upload
- Binary IDS Prediction
- Multi-Class Prediction
- Threat Statistics
- Security Metrics
- SHAP Explainability
- Feature Importance Analysis
- Interactive Data Exploration

---

# 🛠️ Technology Stack

| Category | Technologies |
|-----------|--------------|
| Programming | Python |
| Machine Learning | Scikit-learn |
| Explainable AI | SHAP |
| Dashboard | Streamlit |
| Data Processing | Pandas, NumPy |
| Visualization | Matplotlib |
| Model Persistence | Joblib |

---

# 📂 Dataset

**Dataset:** CIC-BCCC-NRC TabularIoTAttack-2024

### Includes

- Millions of IoT Network Traffic Records
- 79+ Network Features
- Multiple Attack Categories
- Benign Traffic Samples

---

# ⚙️ Workflow

```text
Dataset
      │
      ▼
Data Preprocessing
      │
      ▼
Binary IDS Training
      │
      ▼
Multi-Class IDS Training
      │
      ▼
Model Persistence
      │
      ▼
SHAP Explainability
      │
      ▼
Streamlit SOC Dashboard
      │
      ▼
Threat Intelligence Foundation
```

---

# 📈 Results

- ✅ Binary Intrusion Detection
- ✅ Multi-Class IDS (**98.53% Accuracy**)
- ✅ SHAP Explainability
- ✅ Interactive SOC Dashboard
- ✅ Research-based IoT Security Framework

---

# 🚀 Future Roadmap

- 📡 Live Packet Capture (PyShark/Scapy)
- 🤖 LLM-powered Threat Intelligence
- 🎯 MITRE ATT&CK Mapping
- 📊 Dynamic Risk Assessment
- 🔐 Adaptive Response Engine
- 🗄️ Quarantine & Recovery Framework
- ⚡ FastAPI Backend
- 🐳 Docker Deployment
- ☁️ Cloud Deployment

---

# 📁 Project Structure

```text
AI-IoT-SOC/
│
├── app.py
├── pages/
├── models/
├── explainability/
├── dataset/
├── notebooks/
├── requirements.txt
└── README.md
```

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/<your-username>/<repository-name>.git
```

Navigate to the project

```bash
cd <repository-name>
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run Streamlit

```bash
streamlit run app.py
```

---

# 🎓 Research Contribution

This project was developed as part of a **Research Internship at IIIT Dharwad**.

The project combines:

- Machine Learning
- Explainable AI
- Security Operations Center (SOC)
- Threat Intelligence

to build an intelligent cybersecurity platform for IoT environments. It also serves as a foundation for future work on **autonomous SOCs**, **LLM-assisted threat analysis**, and **adaptive cyber defense**.

---

# 👨‍💻 Author

## **Rihan Riyaj Chougule**

**Research Intern — IIIT Dharwad**

B.Tech Computer Science & Engineering  
Walchand College of Engineering, Sangli

---

<div align="center">

### ⭐ If you found this project helpful, consider giving it a Star!

</div>
