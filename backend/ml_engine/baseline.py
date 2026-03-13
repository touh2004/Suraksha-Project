# baseline.py — SURAKSHA Self-Learning Baseline
# MODE 1 — LEARN: Watch network for N minutes, build YOUR normal profile
# MODE 2 — DETECT: Compare live traffic to YOUR baseline, flag deviations
# This eliminates false positives from the lab-trained model

import json
import os
import time
import numpy as np
from datetime import datetime
from collections import defaultdict

BASELINE_FILE = 'models/network_baseline.json'


class SelfLearningBaseline:
    """
    Builds a statistical profile of YOUR network's normal behavior.
    Uses mean + standard deviation to define normal range.
    Anything outside 2.5 standard deviations = anomaly.
    """

    def __init__(self):
        self.baseline    = {}
        self.learning    = []   # raw samples collected during learning
        self.is_trained  = False
        self._load()

    def _load(self):
        if os.path.exists(BASELINE_FILE):
            with open(BASELINE_FILE) as f:
                data = json.load(f)
                self.baseline   = data.get('baseline', {})
                self.is_trained = data.get('is_trained', False)
                trained_at      = data.get('trained_at', 'never')
            if self.is_trained:
                print(f"  ✅ Baseline loaded — trained at {trained_at}")
                print(f"     {len(self.baseline)} features profiled")
        else:
            print("  ℹ️  No baseline found — run in LEARN mode first")

    def _save(self):
        os.makedirs('models', exist_ok=True)
        with open(BASELINE_FILE, 'w') as f:
            json.dump({
                'baseline'   : self.baseline,
                'is_trained' : self.is_trained,
                'trained_at' : datetime.now().isoformat(),
                'sample_count': len(self.learning),
            }, f, indent=2)

    def add_sample(self, flow_features):
        """
        Call during LEARNING mode with each flow's features.
        flow_features = dict of {feature_name: value}
        """
        self.learning.append(flow_features)

    def train(self):
        """
        After collecting samples, compute mean + std for each feature.
        This becomes YOUR network's normal profile.
        """
        if len(self.learning) < 10:
            print(f"  ⚠️  Only {len(self.learning)} samples — need at least 10")
            return False

        print(f"\n  Training baseline on {len(self.learning)} samples...")

        # Get all feature names
        all_features = set()
        for sample in self.learning:
            all_features.update(sample.keys())

        for feature in all_features:
            values = [
                s[feature] for s in self.learning
                if feature in s and isinstance(s[feature], (int, float))
            ]
            if len(values) < 2:
                continue

            arr = np.array(values)
            self.baseline[feature] = {
                'mean'  : float(np.mean(arr)),
                'std'   : float(np.std(arr)),
                'min'   : float(np.min(arr)),
                'max'   : float(np.max(arr)),
                'p95'   : float(np.percentile(arr, 95)),
                'p99'   : float(np.percentile(arr, 99)),
            }

        self.is_trained = True
        self._save()

        print(f"  ✅ Baseline trained — {len(self.baseline)} features profiled")
        print(f"  Key baselines:")
        key_features = ['sPackets', 'sBytesSum', 'duration', 'sLoad', 'sSynRate']
        for f in key_features:
            if f in self.baseline:
                b = self.baseline[f]
                print(f"     {f:<20} mean={b['mean']:.3f}  std={b['std']:.3f}")
        return True

    def check_flow(self, flow_features, threshold_std=2.5):
        """
        Compare a live flow against the baseline.
        Returns anomaly score and which features are abnormal.

        threshold_std: how many standard deviations = anomaly
          2.5 = strict (fewer false positives, may miss some attacks)
          2.0 = balanced
          1.5 = sensitive (more detections, more false positives)
        """
        if not self.is_trained:
            return {
                'is_anomaly'      : False,
                'score'           : 0,
                'anomalous_features': [],
                'reason'          : 'baseline not trained yet',
            }

        anomalous = []
        total_score = 0

        for feature, value in flow_features.items():
            if feature not in self.baseline:
                continue
            if not isinstance(value, (int, float)):
                continue

            b   = self.baseline[feature]
            std = b['std']

            if std < 0.0001:
                continue  # feature has no variance in baseline

            z_score = abs(value - b['mean']) / std
            if z_score > threshold_std:
                anomalous.append({
                    'feature'  : feature,
                    'value'    : round(value, 4),
                    'baseline' : round(b['mean'], 4),
                    'z_score'  : round(z_score, 2),
                    'direction': 'HIGH' if value > b['mean'] else 'LOW',
                })
                total_score += z_score

        is_anomaly   = len(anomalous) >= 3  # 3+ features abnormal = anomaly
        anomaly_score = round(total_score / max(len(self.baseline), 1), 4)

        return {
            'is_anomaly'        : is_anomaly,
            'score'             : anomaly_score,
            'anomalous_count'   : len(anomalous),
            'anomalous_features': sorted(anomalous, key=lambda x: -x['z_score'])[:5],
            'reason'            : f"{len(anomalous)} features deviate from YOUR network baseline",
        }

    def learn_from_dataset(self, csv_path, n_rows=5000):
        """
        Bootstrap learning using your ICS dataset normal flows.
        Use only Normal-labeled rows to build the baseline.
        """
        import pandas as pd
        import joblib

        print(f"\n  Loading normal flows from dataset for baseline training...")
        df         = pd.read_csv(csv_path, nrows=n_rows * 3)
        normal_df  = df[df['IT_M_Label'] == 'Normal'].head(n_rows)

        print(f"  Using {len(normal_df)} normal ICS flows for baseline")

        feature_cols = joblib.load('models/feature_cols.pkl')
        proto_enc    = joblib.load('models/protocol_encoder.pkl')

        # Encode protocol BEFORE filtering normal rows
        df['protocol'] = proto_enc.transform(df['protocol'].astype(str))

        # Re-filter normal rows AFTER encoding
        normal_df = df[df['IT_M_Label'] == 'Normal'].head(n_rows)

        for _, row in normal_df.iterrows():
            sample = {}
            for col in feature_cols:
                if col not in row.index:
                    continue
                try:
                    sample[col] = float(row[col])
                except (ValueError, TypeError):
                    sample[col] = 0.0   # skip non-numeric safely
            self.add_sample(sample)

        return self.train()

    def print_status(self):
        if not self.is_trained:
            print("  Baseline: NOT TRAINED")
            return
        print(f"\n{'='*55}")
        print(f"  SELF-LEARNING BASELINE STATUS")
        print(f"{'='*55}")
        print(f"  Status   : ✅ TRAINED")
        print(f"  Features : {len(self.baseline)}")
        print()
        print(f"  {'Feature':<22} {'Mean':>10} {'Std':>10} {'P95':>10}")
        print(f"  {'─'*52}")
        show = ['sPackets','sBytesSum','duration','sLoad',
                'sSynRate','sAckDelayAvg','sInterPacketAvg']
        for f in show:
            if f in self.baseline:
                b = self.baseline[f]
                print(f"  {f:<22} {b['mean']:>10.3f} {b['std']:>10.3f} {b['p95']:>10.3f}")
        print(f"{'='*55}\n")


# ── Standalone: train from your ICS dataset ───────────────────
if __name__ == '__main__':
    bl = SelfLearningBaseline()

    # Train from your real ICS dataset (normal flows only)
    dataset_path = 'dataset/extracted/Dataset.csv'
    if os.path.exists(dataset_path):
        print("\nTraining baseline from ICS dataset normal flows...\n")
        bl.learn_from_dataset(dataset_path, n_rows=5000)
        bl.print_status()

        # Test: check a normal-looking flow
        print("\nTesting a quiet ICS flow (should be NORMAL):")
        quiet = {
            'sPackets': 5, 'sBytesSum': 300, 'duration': 2.0,
            'sLoad': 150, 'sSynRate': 0.05, 'sAckDelayAvg': 0.03,
        }
        result = bl.check_flow(quiet)
        print(f"  Is anomaly : {result['is_anomaly']}")
        print(f"  Score      : {result['score']}")

        print("\nTesting a high-traffic flow (should be ANOMALY):")
        busy = {
            'sPackets': 800, 'sBytesSum': 950000, 'duration': 0.5,
            'sLoad': 1900000, 'sSynRate': 0.9, 'sAckDelayAvg': 0.001,
        }
        result = bl.check_flow(busy)
        print(f"  Is anomaly : {result['is_anomaly']}")
        print(f"  Score      : {result['score']}")
        if result['anomalous_features']:
            print(f"  Top anomalous features:")
            for f in result['anomalous_features'][:3]:
                print(f"    {f['feature']:<20} value={f['value']} "
                      f"baseline={f['baseline']} z={f['z_score']}")
    else:
        print("Dataset not found. Run from ml_engine directory.")