from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import json
import joblib
import numpy as np
import pandas as pd
from detect import detect_network_flow

# ── Load models for ensemble voting ──────────────────────────
print("Loading models...")
iso_forest   = joblib.load('models/isolation_forest.pkl')
rf_binary    = joblib.load('models/random_forest_binary.pkl')
rf_multi     = joblib.load('models/random_forest_multiclass.pkl')
scaler       = joblib.load('models/network_scaler.pkl')
label_enc    = joblib.load('models/label_encoder.pkl')
feature_cols = joblib.load('models/feature_cols.pkl')
print("All models loaded.\n")

# ── Improvement 2: Whitelist — known safe IPs ─────────────────
WHITELIST = [
    '8.8.8.8', '8.8.4.4',          # Google DNS
    '192.168.1.1', '127.0.0.1',     # local
    '224.0.0.251', '224.0.0.252',   # mDNS multicast — NOT attacks
    '239.255.255.250',               # SSDP multicast
]

# ── Improvement 3: ICS port filter ───────────────────────────
ICS_PORTS = [
    502,    # Modbus TCP
    20000,  # DNP3
    44818,  # EtherNet/IP
    102,    # Siemens S7
    47808,  # BACnet
    4840,   # OPC-UA
    2404,   # IEC 60870-5-104
]

# ── Flow tracker ──────────────────────────────────────────────
flows = defaultdict(lambda: {
    'sPackets': 0, 'rPackets': 0,
    'sBytesSum': 0, 'rBytesSum': 0,
    'sBytesMax': 0, 'rBytesMax': 0,
    'sBytesMin': float('inf'), 'rBytesMin': float('inf'),
    'sSynRate': 0, 'rSynRate': 0,
    'sFinRate': 0, 'rFinRate': 0,
    'sRstRate': 0, 'rRstRate': 0,
    'sPshRate': 0, 'rPshRate': 0,
    'sAckRate': 0, 'rAckRate': 0,
    'protocol': 6,
    'duration': 0,
    'start_time': time.time(),
    'last_time': time.time(),
    'src': '', 'dst': '',
    'sttl': 0, 'rttl': 0,
})

alert_log = []


# ── Improvement 3: Port filter applied here ───────────────────
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    # Improvement 3 — skip non-ICS ports entirely
    # Comment out these 4 lines if you want to monitor ALL traffic
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport not in ICS_PORTS and sport not in ICS_PORTS:
            return  # not an ICS port — ignore

    size = len(packet)
    ttl  = packet[IP].ttl
    key  = f"{src}-{dst}"

    flow = flows[key]
    flow['src']      = src
    flow['dst']      = dst
    flow['sPackets'] += 1
    flow['sBytesSum']+= size
    flow['sBytesMax'] = max(flow['sBytesMax'], size)
    flow['sBytesMin'] = min(flow['sBytesMin'], size)
    flow['sttl']      = ttl
    flow['duration']  = time.time() - flow['start_time']
    flow['last_time'] = time.time()

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        flow['protocol'] = 6
        if flags & 0x02: flow['sSynRate'] += 1
        if flags & 0x01: flow['sFinRate'] += 1
        if flags & 0x04: flow['sRstRate'] += 1
        if flags & 0x08: flow['sPshRate'] += 1
        if flags & 0x10: flow['sAckRate'] += 1
    elif packet.haslayer(UDP):
        flow['protocol'] = 17

    # Analyze every 20 packets per flow
    if flow['sPackets'] % 20 == 0:
        analyze_flow(key, flow)


def analyze_flow(key, flow):
    """
    Improvement 4 — Ensemble voting:
    Both Isolation Forest AND Random Forest must agree
    before raising an alert. This reduces false positives.
    """
    total = max(flow['sPackets'], 1)

    flow_features = {
        'duration'       : flow['duration'],
        'sPackets'       : flow['sPackets'],
        'rPackets'       : flow['rPackets'],
        'sBytesSum'      : flow['sBytesSum'],
        'rBytesSum'      : flow['rBytesSum'],
        'sBytesMax'      : flow['sBytesMax'],
        'rBytesMax'      : flow['rBytesMax'],
        'sBytesMin'      : flow['sBytesMin'] if flow['sBytesMin'] != float('inf') else 0,
        'rBytesMin'      : 0,
        'sBytesAvg'      : flow['sBytesSum'] / total,
        'rBytesAvg'      : 0,
        'sLoad'          : flow['sBytesSum'] / max(flow['duration'], 0.001),
        'rLoad'          : 0,
        'sSynRate'       : flow['sSynRate'] / total,
        'rSynRate'       : 0,
        'sFinRate'       : flow['sFinRate'] / total,
        'rFinRate'       : 0,
        'sRstRate'       : flow['sRstRate'] / total,
        'rRstRate'       : 0,
        'sPshRate'       : flow['sPshRate'] / total,
        'rPshRate'       : 0,
        'sAckRate'       : flow['sAckRate'] / total,
        'rAckRate'       : 0,
        'protocol'       : flow['protocol'],
        'sttl'           : flow['sttl'],
        'rttl'           : flow['rttl'],
        'sInterPacketAvg': flow['duration'] / total,
        'rInterPacketAvg': 0,
        'sAckDelayAvg'   : flow['duration'] / max(flow['sAckRate'], 1),
        'rAckDelayAvg'   : 0,
        'sAckDelayMax'   : 0,
        'rAckDelayMax'   : 0,
        'sAckDelayMin'   : 0,
        'rAckDelayMin'   : 0,
        'sPayloadSum'    : flow['sBytesSum'],
        'rPayloadSum'    : 0,
        'sPayloadAvg'    : flow['sBytesSum'] / total,
        'rPayloadAvg'    : 0,
        'sPayloadMax'    : flow['sBytesMax'],
        'rPayloadMax'    : 0,
        'sPayloadMin'    : flow['sBytesMin'] if flow['sBytesMin'] != float('inf') else 0,
        'rPayloadMin'    : 0,
        'sUrgRate'       : 0,
        'rUrgRate'       : 0,
        'sWinTCP'        : 0,
        'rWinTCP'        : 0,
        'sFragmentRate'  : 0,
        'rFragmentRate'  : 0,
    }

    try:
        X = pd.DataFrame([flow_features])
        X = X.fillna(0).replace([float('inf'), float('-inf')], 0)
        # Fix — reorder columns to exactly match training order
        X = X.reindex(columns=feature_cols, fill_value=0)
        X_scaled = scaler.transform(X)

        # ── Improvement 4: Ensemble voting ───────────────────
        iso_pred   = iso_forest.predict(X_scaled)[0]   # -1=anomaly, 1=normal
        rf_pred    = rf_binary.predict(X_scaled)[0]    #  1=attack,  0=normal
        rf_prob    = rf_binary.predict_proba(X_scaled)[0]
        confidence = max(rf_prob) * 100

        # Both models must agree it's an attack
        both_agree = (iso_pred == -1) and (rf_pred == 1)

        # Get attack type
        rf_multi_pred = rf_multi.predict(X_scaled)[0]
        attack_type   = label_enc.inverse_transform([rf_multi_pred])[0]

        # MITRE mapping
        MITRE_MAP = {
            'ip-scan'  : 'T0846 — Remote System Discovery',
            'port-scan': 'T0846 — Network Service Scanning',
            'replay'   : 'T0843 — Program Download / Replay',
            'mitm'     : 'T0830 — Man in the Middle',
            'ddos'     : 'T0814 — Denial of Service',
        }
        RISK_MAP = {
            'ip-scan'  : 'Attacker mapping ICS device locations',
            'port-scan': 'Attacker scanning for open Modbus/DNP3 ports',
            'replay'   : 'Recorded commands being replayed — PLC state may change',
            'mitm'     : 'Commands may be intercepted and modified in transit',
            'ddos'     : 'Network flooding — PLCs may become unreachable',
        }
        SEVERITY_MAP = {
            'ip-scan'  : 'LOW',
            'port-scan': 'MEDIUM',
            'replay'   : 'HIGH',
            'mitm'     : 'HIGH',
            'ddos'     : 'CRITICAL',
        }

        # ── Improvement 1: Confidence threshold ──────────────
        # ── Improvement 2: Whitelist check ───────────────────
        # ── Improvement 4: Both models must agree ────────────
        if (both_agree
        and confidence > 85.0    # raised from 70 to 85
        and flow['src'] not in WHITELIST
        and flow['dst'] not in WHITELIST
        and attack_type != 'Normal'):
            alert = {
                'src'        : flow['src'],
                'dst'        : flow['dst'],
                'attack_type': attack_type,
                'severity'   : SEVERITY_MAP.get(attack_type, 'MEDIUM'),
                'confidence' : round(confidence, 2),
                'mitre'      : MITRE_MAP.get(attack_type, 'Unknown'),
                'risk'       : RISK_MAP.get(attack_type, 'Unknown'),
            }
            alert_log.append(alert)

            print(f"\n{'='*55}")
            print(f"  ⚠  ATTACK DETECTED  [ENSEMBLE CONFIRMED]")
            print(f"{'='*55}")
            print(f"  Source      : {flow['src']}")
            print(f"  Destination : {flow['dst']}")
            print(f"  Attack Type : {attack_type}")
            print(f"  Severity    : {SEVERITY_MAP.get(attack_type, 'MEDIUM')}")
            print(f"  Confidence  : {round(confidence, 2)}%")
            print(f"  ISO Score   : {round(float(iso_forest.decision_function(X_scaled)[0]), 4)}")
            print(f"  MITRE       : {MITRE_MAP.get(attack_type, 'Unknown')}")
            print(f"  Risk        : {RISK_MAP.get(attack_type, 'Unknown')}")
            print(f"  Both models : ISO={iso_pred} RF={rf_pred} ✓")
            print(f"{'='*55}\n")

        else:
            # Silent — normal traffic, just log count
            pass

    except Exception as e:
        print(f"  [ERROR] {e}")


def start_capture(interface=None, packet_count=0):
    print("=" * 55)
    print("  SURAKSHA — LIVE PACKET CAPTURE STARTED")
    print("  All 4 improvements active:")
    print("  ✓ Confidence threshold > 70%")
    print("  ✓ IP whitelist active")
    print("  ✓ ICS port filter active")
    print("  ✓ Ensemble voting (ISO + RF must agree)")
    print("  Press Ctrl+C to stop")
    print("=" * 55)

    try:
        if interface:
            sniff(iface=interface, prn=process_packet,
                  store=False, count=packet_count)
        else:
            sniff(prn=process_packet, store=False, count=packet_count)

    except KeyboardInterrupt:
        print(f"\n\nCapture stopped.")
        print(f"Total confirmed alerts : {len(alert_log)}")
        if alert_log:
            with open('models/alerts.json', 'w') as f:
                json.dump(alert_log, f, indent=2)
            print("Alerts saved to models/alerts.json")


if __name__ == "__main__":
    start_capture()