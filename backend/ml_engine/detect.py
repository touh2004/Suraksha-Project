import pandas as pd
import numpy as np
import joblib
import json
import time
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# ── Load all trained models ───────────────────────────────────
print("Loading models...")
iso_forest    = joblib.load('models/isolation_forest.pkl')
rf_binary     = joblib.load('models/random_forest_binary.pkl')
rf_multi      = joblib.load('models/random_forest_multiclass.pkl')
plc_iso       = joblib.load('models/plc_isolation_forest.pkl')
scaler        = joblib.load('models/network_scaler.pkl')
plc_scaler    = joblib.load('models/plc_scaler.pkl')
label_enc     = joblib.load('models/label_encoder.pkl')
proto_enc     = joblib.load('models/protocol_encoder.pkl')
feature_cols  = joblib.load('models/feature_cols.pkl')
plc_feat_cols = joblib.load('models/plc_feature_cols.pkl')
print("All models loaded.\n")

SEVERITY = {
    'Normal'   : 'INFO',
    'ip-scan'  : 'LOW',
    'port-scan': 'MEDIUM',
    'replay'   : 'HIGH',
    'mitm'     : 'HIGH',
    'ddos'     : 'CRITICAL'
}

MITRE_MAP = {
    'ip-scan'  : 'T0846 — Remote System Discovery',
    'port-scan': 'T0846 — Network Service Scanning',
    'replay'   : 'T0843 — Program Download / Replay',
    'mitm'     : 'T0830 — Man in the Middle',
    'ddos'     : 'T0814 — Denial of Service',
    'Normal'   : 'None'
}

RISK_MAP = {
    'ip-scan'  : 'Attacker mapping ICS device locations',
    'port-scan': 'Attacker scanning for open Modbus/DNP3 ports',
    'replay'   : 'Recorded commands being replayed — PLC state may change',
    'mitm'     : 'Commands may be intercepted and modified in transit',
    'ddos'     : 'Network flooding — PLCs may become unreachable',
    'Normal'   : 'No risk'
}

def detect_network_flow(flow_dict):
    """
    Analyze a single network flow and return detection result.
    flow_dict should have the same keys as Dataset.csv feature columns.
    """
    try:
        # Build feature vector
        row = {}
        for col in feature_cols:
            row[col] = flow_dict.get(col, 0)

        X = pd.DataFrame([row])
        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        X_scaled = scaler.transform(X)

        # Model 1 — Isolation Forest score
        iso_score = iso_forest.decision_function(X_scaled)[0]
        iso_pred  = iso_forest.predict(X_scaled)[0]
        is_anomaly = (iso_pred == -1)

        # Model 2 — Binary classification
        rf_binary_pred = rf_binary.predict(X_scaled)[0]
        rf_binary_prob = rf_binary.predict_proba(X_scaled)[0]
        confidence = max(rf_binary_prob) * 100

        # Model 3 — Attack type
        rf_multi_pred = rf_multi.predict(X_scaled)[0]
        attack_type   = label_enc.inverse_transform([rf_multi_pred])[0]

        # Final verdict — if both models agree it's an attack
        is_attack = (rf_binary_pred == 1)

        result = {
            'timestamp'    : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_attack'    : bool(is_attack),
            'is_anomaly'   : bool(is_anomaly),
            'attack_type'  : attack_type if is_attack else 'Normal',
            'severity'     : SEVERITY.get(attack_type if is_attack else 'Normal', 'LOW'),
            'confidence'   : round(confidence, 2),
            'anomaly_score': round(float(iso_score), 4),
            'mitre'        : MITRE_MAP.get(attack_type if is_attack else 'Normal'),
            'risk'         : RISK_MAP.get(attack_type if is_attack else 'Normal'),
        }
        return result

    except Exception as e:
        return {'error': str(e)}


def detect_plc_reading(plc_dict):
    """
    Analyze a PLC sensor reading for physical process anomalies.
    plc_dict keys: current_loop, loop_latency, tank_level_value, etc.
    """
    try:
        row = {}
        for col in plc_feat_cols:
            row[col] = plc_dict.get(col, 0)

        X = pd.DataFrame([row])
        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        X_scaled = plc_scaler.transform(X)

        pred  = plc_iso.predict(X_scaled)[0]
        score = plc_iso.decision_function(X_scaled)[0]

        is_anomaly = (pred == -1)

        # Physical risk rules based on tank data
        tank_level    = plc_dict.get('tank_level_value(2)', 0)
        tank_min      = plc_dict.get('tank_level_min(3)', 0)
        tank_max      = plc_dict.get('tank_level_max(4)', 100)
        valve_status  = plc_dict.get('tank_input_valve_status(0)', 0)

        physical_risk = 'Normal operation'
        if tank_level > tank_max * 0.95:
            physical_risk = '⚠ CRITICAL: Tank near overflow'
        elif tank_level < tank_min * 1.05:
            physical_risk = '⚠ WARNING: Tank level critically low'
        elif is_anomaly:
            physical_risk = '⚠ Abnormal PLC sensor reading detected'

        return {
            'timestamp'    : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_anomaly'   : bool(is_anomaly),
            'anomaly_score': round(float(score), 4),
            'tank_level'   : tank_level,
            'valve_status' : int(valve_status),
            'physical_risk': physical_risk,
            'severity'     : 'CRITICAL' if is_anomaly else 'NORMAL'
        }

    except Exception as e:
        return {'error': str(e)}


def run_demo():
    """
    Run detection demo using real rows from the dataset.
    This simulates what real-time detection looks like.
    """
    print("=" * 60)
    print("  SURAKSHA ICS-IDS — LIVE DETECTION DEMO")
    print("=" * 60)

    # Load a sample of real data for demo
    print("\nLoading sample data for demo...")
    df = pd.read_csv('dataset/extracted/Dataset.csv')

    # Encode protocol
    df['protocol'] = proto_enc.transform(df['protocol'].astype(str))

    # Pick 5 normal + 5 attack samples
    normal_samples = df[df['IT_B_Label'] == 0].sample(5, random_state=1)
    attack_samples = df[df['IT_B_Label'] == 1].sample(5, random_state=1)
    samples = pd.concat([normal_samples, attack_samples]).sample(frac=1, random_state=42)

    print(f"\nRunning detection on 10 sample flows...\n")
    print("-" * 60)

    correct = 0
    total   = len(samples)

    for idx, row in samples.iterrows():
        true_label  = 'Normal' if row['IT_B_Label'] == 0 else row['IT_M_Label']
        flow        = row[feature_cols].to_dict()
        result      = detect_network_flow(flow)

        predicted   = result.get('attack_type', 'Unknown')
        is_correct  = (result['is_attack'] == (row['IT_B_Label'] == 1))
        if is_correct:
            correct += 1

        status_icon = '✓' if is_correct else '✗'
        sev_color   = {
            'INFO'    : '',
            'LOW'     : '',
            'MEDIUM'  : '',
            'HIGH'    : '',
            'CRITICAL': ''
        }.get(result['severity'], '')

        print(f"  [{status_icon}] True: {true_label:<12} "
              f"Predicted: {predicted:<12} "
              f"Severity: {result['severity']:<8} "
              f"Confidence: {result['confidence']:.1f}%")

        if result['is_attack']:
            print(f"      MITRE: {result['mitre']}")
            print(f"      Risk : {result['risk']}")
        print()

        time.sleep(0.3)  # simulate real-time feed

    print("-" * 60)
    print(f"\n  Demo accuracy: {correct}/{total} ({correct/total*100:.1f}%)")

    # PLC Demo
    print("\n" + "=" * 60)
    print("  PLC PHYSICAL PROCESS DEMO")
    print("=" * 60)

    plc_df = pd.read_csv('dataset/extracted/snapshots_PLC1.csv')
    plc_df.columns = plc_df.columns.str.strip()
    plc_df = plc_df[plc_feat_cols].fillna(0)

    print("\nChecking 5 PLC sensor readings...\n")
    for i in range(5):
        reading = plc_df.iloc[i].to_dict()
        result  = detect_plc_reading(reading)

        print(f"  Reading #{i+1}")
        print(f"  Tank Level : {result['tank_level']}")
        print(f"  Anomaly    : {'YES ⚠' if result['is_anomaly'] else 'No'}")
        print(f"  Risk       : {result['physical_risk']}")
        print(f"  Score      : {result['anomaly_score']}")
        print()

    print("=" * 60)
    print("  Detection engine ready for live packet integration")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()