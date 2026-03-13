# make sure dependencies are available; show helpful message if not
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
    import joblib
except ImportError as e:
    missing = str(e).split()[-1].strip("'\"")
    print(f"ERROR: could not import {missing}.\n" \
          "Please install the required packages:\n" \
          "    python -m pip install -r requirements.txt\n" \
          "and make sure the correct Python interpreter/venv is selected in VS Code.")
    raise

import os
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("  SURAKSHA ICS-IDS — MODEL TRAINING")
print("=" * 60)

# ── Create models folder ──────────────────────────────────────
os.makedirs("models", exist_ok=True)
# note: this script assumes dataset files live under dataset/extracted
def check_datasets():
    required = [
        "dataset/extracted/Dataset.csv",
        "dataset/extracted/snapshots_PLC1.csv",
        "dataset/extracted/snapshots_PLC2.csv",
    ]
    for path in required:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Required input file not found: {path}")

check_datasets()

# ════════════════════════════════════════════════════════════════
# PART 1 — NETWORK TRAFFIC MODEL (Dataset.csv)
# ════════════════════════════════════════════════════════════════
print("\n[1/4] Loading network traffic dataset...")
df = pd.read_csv("dataset/extracted/Dataset.csv")
print(f"      Rows: {len(df):,}  |  Columns: {len(df.columns)}")

# Check attack distribution
print("\n[2/4] Attack distribution:")
print(df['IT_M_Label'].value_counts())

# ── Drop non-numeric / identifier columns ────────────────────
drop_cols = ['sAddress', 'rAddress', 'sMACs', 'rMACs',
             'sIPs', 'rIPs', 'startDate', 'endDate',
             'start', 'end', 'startOffset', 'endOffset',
             'IT_B_Label', 'IT_M_Label', 'NST_B_Label', 'NST_M_Label']

# ── Encode protocol column ────────────────────────────────────
le_protocol = LabelEncoder()
df['protocol'] = le_protocol.fit_transform(df['protocol'].astype(str))
joblib.dump(le_protocol, 'models/protocol_encoder.pkl')

# ── Features and labels ───────────────────────────────────────
feature_cols = [c for c in df.columns if c not in drop_cols]
X = df[feature_cols].copy()
y_binary = df['IT_B_Label']          # 0 = normal, 1 = attack
y_multi  = df['IT_M_Label']          # Normal / specific attack type

# ── Handle missing values ─────────────────────────────────────
X = X.fillna(0)
X = X.replace([np.inf, -np.inf], 0)

# ── Scale features ────────────────────────────────────────────
print("\n[3/4] Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'models/network_scaler.pkl')
joblib.dump(feature_cols, 'models/feature_cols.pkl')

# ── Train/test split ──────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)

# ────────────────────────────────────────────────────────────────
# MODEL 1 — Isolation Forest (Unsupervised anomaly detection)
# Best for: detecting unknown/zero-day attacks
# ────────────────────────────────────────────────────────────────
print("\n[4/4] Training models...")
print("\n  ▶ Model 1: Isolation Forest (anomaly detection)...")

attack_ratio = y_binary.mean()
iso = IsolationForest(
    n_estimators=100,
    contamination=float(attack_ratio),
    random_state=42,
    n_jobs=-1
)
iso.fit(X_scaled)
joblib.dump(iso, 'models/isolation_forest.pkl')

# Evaluate Isolation Forest
iso_preds_raw = iso.predict(X_test)
iso_preds = [1 if p == -1 else 0 for p in iso_preds_raw]
iso_acc = accuracy_score(y_test, iso_preds)
print(f"     Accuracy : {iso_acc * 100:.2f}%")
print(f"     Anomalies detected: {sum(iso_preds)} / {len(iso_preds)}")

# ────────────────────────────────────────────────────────────────
# MODEL 2 — Random Forest (Supervised binary classification)
# Best for: detecting known attack types with high accuracy
# ────────────────────────────────────────────────────────────────
print("\n  ▶ Model 2: Random Forest (binary — normal vs attack)...")
rf_binary = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
rf_binary.fit(X_train, y_train)
joblib.dump(rf_binary, 'models/random_forest_binary.pkl')

rf_preds = rf_binary.predict(X_test)
rf_acc = accuracy_score(y_test, rf_preds)
print(f"     Accuracy : {rf_acc * 100:.2f}%")
print("\n     Classification Report:")
print(classification_report(y_test, rf_preds, target_names=["Normal", "Attack"]))

# ────────────────────────────────────────────────────────────────
# MODEL 3 — Random Forest Multi-class (attack type classifier)
# Best for: identifying WHAT type of attack is happening
# ────────────────────────────────────────────────────────────────
print("\n  ▶ Model 3: Random Forest (multi-class — attack type)...")

le_label = LabelEncoder()
y_multi_encoded = le_label.fit_transform(y_multi)
joblib.dump(le_label, 'models/label_encoder.pkl')

X_train_m, X_test_m, y_train_m, y_test_m = train_test_split(
    X_scaled, y_multi_encoded, test_size=0.2, random_state=42
)

rf_multi = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
rf_multi.fit(X_train_m, y_train_m)
joblib.dump(rf_multi, 'models/random_forest_multiclass.pkl')

rf_multi_preds = rf_multi.predict(X_test_m)
rf_multi_acc = accuracy_score(y_test_m, rf_multi_preds)
print(f"     Accuracy : {rf_multi_acc * 100:.2f}%")
print(f"     Attack classes: {list(le_label.classes_)}")

# ── Feature importance (useful for dashboard) ─────────────────
print("\n  ▶ Top 10 most important features:")
importances = rf_binary.feature_importances_
feat_importance = pd.Series(importances, index=feature_cols)
top10 = feat_importance.nlargest(10)
for feat, score in top10.items():
    print(f"     {feat:<30} {score:.4f}")

# ════════════════════════════════════════════════════════════════
# PART 2 — PLC SENSOR MODEL (snapshots_PLC1.csv)
# ════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  PART 2 — PLC PHYSICAL PROCESS ANOMALY DETECTION")
print("=" * 60)

print("\n[1/3] Loading PLC snapshot data...")
plc1 = pd.read_csv("dataset/extracted/snapshots_PLC1.csv")
plc2 = pd.read_csv("dataset/extracted/snapshots_PLC2.csv")

# Clean column names (they have leading spaces)
plc1.columns = plc1.columns.str.strip()
plc2.columns = plc2.columns.str.strip()

print(f"      PLC1 rows: {len(plc1):,}")
print(f"      PLC2 rows: {len(plc2):,}")
print(f"      PLC1 columns: {plc1.columns.tolist()}")

# ── PLC feature engineering ───────────────────────────────────
print("\n[2/3] Engineering PLC features...")

# Drop time and non-numeric columns
plc1_features = plc1.drop(columns=['time'], errors='ignore')
plc1_features = plc1_features.select_dtypes(include=[np.number])
plc1_features = plc1_features.fillna(0)
plc1_features = plc1_features.replace([np.inf, -np.inf], 0)

# Remove empty trailing columns
plc1_features = plc1_features.loc[:, (plc1_features != 0).any(axis=0)]

print(f"      PLC features used: {plc1_features.columns.tolist()}")

# ── Scale PLC features ────────────────────────────────────────
plc_scaler = StandardScaler()
plc1_scaled = plc_scaler.fit_transform(plc1_features)
joblib.dump(plc_scaler, 'models/plc_scaler.pkl')
joblib.dump(list(plc1_features.columns), 'models/plc_feature_cols.pkl')

# ────────────────────────────────────────────────────────────────
# MODEL 4 — Isolation Forest on PLC sensor data
# Best for: detecting physical process manipulation
# (e.g. tank overflow, valve forced open, abnormal flow)
# ────────────────────────────────────────────────────────────────
print("\n[3/3] Training PLC anomaly detector (Isolation Forest)...")
plc_iso = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # assume 5% of PLC readings are anomalous
    random_state=42,
    n_jobs=-1
)
plc_iso.fit(plc1_scaled)
joblib.dump(plc_iso, 'models/plc_isolation_forest.pkl')

# Test on sample
sample_preds = plc_iso.predict(plc1_scaled[:500])
anomaly_count = sum(1 for p in sample_preds if p == -1)
print(f"     Anomalies in first 500 PLC readings: {anomaly_count}")
print("     PLC model saved.")

# ════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  TRAINING COMPLETE — MODELS SAVED")
print("=" * 60)
print(f"""
  Models saved to /models/:
  
  ┌─────────────────────────────────────────────────────┐
  │  isolation_forest.pkl      → network anomaly        │
  │  random_forest_binary.pkl  → normal vs attack       │
  │  random_forest_multiclass  → attack type classifier │
  │  plc_isolation_forest.pkl  → PLC process anomaly    │
  │  network_scaler.pkl        → feature scaler         │
  │  plc_scaler.pkl            → PLC scaler             │
  │  label_encoder.pkl         → attack label decoder   │
  │  protocol_encoder.pkl      → protocol encoder       │
  │  feature_cols.pkl          → feature list           │
  └─────────────────────────────────────────────────────┘

  Accuracy Summary:
  Isolation Forest (network) : {iso_acc * 100:.2f}%
  Random Forest (binary)     : {rf_acc * 100:.2f}%
  Random Forest (multi-class): {rf_multi_acc * 100:.2f}%
""")