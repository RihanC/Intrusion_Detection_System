import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import os

class MockBinaryModel:
    def predict(self, X):
        return np.random.choice([0, 1], size=len(X), p=[0.7, 0.3])
        
    def predict_proba(self, X):
        probs = np.random.rand(len(X))
        preds = self.predict(X)
        for i in range(len(X)):
            if preds[i] == 1:
                probs[i] = np.random.uniform(0.5, 1.0)
            else:
                probs[i] = np.random.uniform(0.0, 0.49)
        return np.column_stack((1-probs, probs))

class MockMultiClassModel:
    def __init__(self, num_classes):
        self.num_classes = num_classes
        
    def predict(self, X):
        return np.random.randint(1, self.num_classes, size=len(X))
        
    def predict_proba(self, X):
        probs = np.random.rand(len(X), self.num_classes)
        probs = probs / probs.sum(axis=1, keepdims=True)
        return probs

def create_dummy_artifacts():
    print("Creating dummy models and datasets for testing...")
    
    feature_names = [f"feature_{i}" for i in range(80)]
    joblib.dump(feature_names, "feature_names.pkl")
    
    attacks = [
        "Benign Traffic",
        "DoS TCP Flood", "DoS UDP Flood", "DoS ICMP Flood",
        "DDoS UDP Flood", "DDoS ICMP Flood",
        "MQTT DoS Connect Flood", "MQTT DoS Publish Flood", 
        "MQTT DDoS Publish Flood", "MQTT Malformed",
        "Recon OS Scan", "Recon Port Scan", "Recon Ping Sweep", "Recon Vulnerability Scan",
        "MITM ARP Spoofing"
    ]
    le = LabelEncoder()
    le.fit(attacks)
    joblib.dump(le, "attack_label_encoder.pkl")
    
    joblib.dump(MockBinaryModel(), "binary_ids_model.pkl")
    joblib.dump(MockMultiClassModel(len(attacks)), "multiclass_ids_model.pkl")
    
    num_samples = 1500
    df = pd.DataFrame(np.random.randn(num_samples, 80), columns=feature_names)
    df.to_csv("sample_traffic.csv", index=False)
    
    print("Done! Created artifacts.")

if __name__ == "__main__":
    create_dummy_artifacts()
