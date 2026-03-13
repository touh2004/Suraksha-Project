import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

print("Loading models and data...")
rf_binary    = joblib.load('models/random_forest_binary.pkl')
rf_multi     = joblib.load('models/random_forest_multiclass.pkl')
iso_forest   = joblib.load('models/isolation_forest.pkl')
scaler       = joblib.load('models/network_scaler.pkl')
label_enc    = joblib.load('models/label_encoder.pkl')
proto_enc    = joblib.load('models/protocol_encoder.pkl')
feature_cols = joblib.load('models/feature_cols.pkl')

df = pd.read_csv('dataset/extracted/Dataset.csv')
df['protocol'] = proto_enc.transform(df['protocol'].astype(str))

X        = df[feature_cols].fillna(0).replace([np.inf, -np.inf], 0)
y_binary = df['IT_B_Label']
y_multi  = df['IT_M_Label']
X_scaled = scaler.transform(X)

# ── Random Forest Binary ──────────────────────────────────────
rf_pred = rf_binary.predict(X_scaled)
print()
print("=" * 45)
print("  RANDOM FOREST BINARY")
print("=" * 45)
print(f"  Accuracy  : {accuracy_score(y_binary, rf_pred)*100:.2f}%")
print(f"  Precision : {precision_score(y_binary, rf_pred)*100:.2f}%")
print(f"  Recall    : {recall_score(y_binary, rf_pred)*100:.2f}%")
print(f"  F1 Score  : {f1_score(y_binary, rf_pred)*100:.2f}%")
cm = confusion_matrix(y_binary, rf_pred)
print()
print("  Confusion Matrix:")
print(f"  True Normal  → Normal  : {cm[0][0]}  ✓ Correct")
print(f"  True Normal  → Attack  : {cm[0][1]}  ← False Positives")
print(f"  True Attack  → Normal  : {cm[1][0]}  ← Missed Attacks")
print(f"  True Attack  → Attack  : {cm[1][1]}  ✓ Correct")

# ── Isolation Forest ─────────────────────────────────────────
iso_raw  = iso_forest.predict(X_scaled)
iso_pred = [1 if p == -1 else 0 for p in iso_raw]
print()
print("=" * 45)
print("  ISOLATION FOREST (Unsupervised)")
print("=" * 45)
print(f"  Accuracy  : {accuracy_score(y_binary, iso_pred)*100:.2f}%")
print(f"  Precision : {precision_score(y_binary, iso_pred)*100:.2f}%")
print(f"  Recall    : {recall_score(y_binary, iso_pred)*100:.2f}%")
print(f"  F1 Score  : {f1_score(y_binary, iso_pred)*100:.2f}%")

# ── Ensemble ─────────────────────────────────────────────────
ensemble_pred = [
    1 if (iso_pred[i] == 1 and rf_pred[i] == 1) else 0
    for i in range(len(rf_pred))
]
print()
print("=" * 45)
print("  ENSEMBLE (ISO + RF must both agree)")
print("=" * 45)
print(f"  Accuracy  : {accuracy_score(y_binary, ensemble_pred)*100:.2f}%")
print(f"  Precision : {precision_score(y_binary, ensemble_pred)*100:.2f}%")
print(f"  Recall    : {recall_score(y_binary, ensemble_pred)*100:.2f}%")
print(f"  F1 Score  : {f1_score(y_binary, ensemble_pred)*100:.2f}%")

# ── Multi-class ───────────────────────────────────────────────
y_multi_enc   = label_enc.transform(y_multi)
rf_multi_pred = rf_multi.predict(X_scaled)
print()
print("=" * 45)
print("  RANDOM FOREST MULTI-CLASS")
print("=" * 45)
print(f"  Accuracy  : {accuracy_score(y_multi_enc, rf_multi_pred)*100:.2f}%")
print(f"  F1 Score  : {f1_score(y_multi_enc, rf_multi_pred, average='weighted')*100:.2f}%")
print(f"  Classes   : {list(label_enc.classes_)}")

# ── Per-class breakdown ───────────────────────────────────────
print()
print("=" * 45)
print("  PER ATTACK TYPE ACCURACY")
print("=" * 45)
from sklearn.metrics import classification_report
print(classification_report(
    y_multi_enc, rf_multi_pred,
    target_names=list(label_enc.classes_)
))

print("=" * 45)
print("  EVALUATION COMPLETE")
print("=" * 45)