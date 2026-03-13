# prevent.py — SURAKSHA Preventive Engine
# Does 4 things:
#   1. Tracks attack sequences (ip-scan → port-scan → attack)
#   2. Predicts attack BEFORE it happens
#   3. Finds geographic origin of attacker IP
#   4. Recommends specific blocking action

import requests
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict

# ── GeoIP lookup — finds country/city from IP ────────────────
def get_ip_location(ip):
    """
    Uses free ip-api.com to find where an IP is physically located.
    Returns country, city, ISP, latitude, longitude.
    No API key needed.
    """
    # Skip private/local IPs — these are inside your network
    private_ranges = [
        '10.', '192.168.', '172.16.', '172.17.',
        '172.18.', '172.19.', '172.20.', '172.21.',
        '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '127.', '0.',
        '224.', '239.',
    ]
    for prefix in private_ranges:
        if ip.startswith(prefix):
            return {
                'country' : 'Internal Network',
                'city'    : 'LAN',
                'isp'     : 'Private',
                'lat'     : 0,
                'lon'     : 0,
                'flag'    : '🏠',
                'risk'    : 'insider threat or compromised internal device',
            }

    try:
        # Free API — 45 requests/minute, no key needed
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            f"regionName,city,isp,org,lat,lon,proxy,hosting",
            timeout=3
        )
        data = r.json()

        if data.get('status') == 'success':
            # Extra risk signals
            risk_signals = []
            if data.get('proxy'):
                risk_signals.append("using VPN/proxy — hiding identity")
            if data.get('hosting'):
                risk_signals.append("datacenter/VPS IP — likely automated attack")

            # Country risk classification
            # (based on known high-origin attack countries for ICS)
            HIGH_RISK_COUNTRIES = [
                'CN', 'RU', 'KP', 'IR', 'BY',   # nation-state threat actors
            ]
            MEDIUM_RISK_COUNTRIES = [
                'BR', 'UA', 'RO', 'NG', 'PK',   # high cybercrime activity
            ]

            cc = data.get('countryCode', '')
            if cc in HIGH_RISK_COUNTRIES:
                risk_signals.append("HIGH-RISK nation-state origin")
            elif cc in MEDIUM_RISK_COUNTRIES:
                risk_signals.append("medium-risk origin country")

            return {
                'country' : data.get('country', 'Unknown'),
                'city'    : data.get('city', 'Unknown'),
                'region'  : data.get('regionName', ''),
                'isp'     : data.get('isp', 'Unknown'),
                'org'     : data.get('org', ''),
                'lat'     : data.get('lat', 0),
                'lon'     : data.get('lon', 0),
                'flag'    : get_flag(cc),
                'risk'    : ' | '.join(risk_signals) if risk_signals else 'standard risk',
                'is_proxy': data.get('proxy', False),
                'is_vps'  : data.get('hosting', False),
            }
    except Exception as e:
        pass

    return {
        'country': 'Unknown', 'city': 'Unknown',
        'isp': 'Unknown', 'lat': 0, 'lon': 0,
        'flag': '🌐', 'risk': 'could not resolve',
    }


def get_flag(country_code):
    """Converts country code to emoji flag."""
    if not country_code or len(country_code) != 2:
        return '🌐'
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)


# ── Attack Sequence Tracker ───────────────────────────────────
class AttackSequenceTracker:
    """
    Tracks sequences of events per source IP.
    
    Known ICS attack kill chains:
    
    Chain 1 — Reconnaissance → Exploitation
        ip-scan → port-scan → mitm/ddos
        
    Chain 2 — Access → Control
        port-scan → replay
        
    Chain 3 — Full APT chain
        ip-scan → port-scan → mitm → replay
    
    If we see steps 1+2, we PREDICT step 3 before it happens.
    This is what makes it PREVENTIVE.
    """

    # Known attack kill chains (order matters)
    KILL_CHAINS = {
        'recon_to_exploit': {
            'sequence'   : ['ip-scan', 'port-scan'],
            'predicts'   : 'MITM or DDoS imminent',
            'severity'   : 'CRITICAL',
            'action'     : 'Block source IP immediately. Isolate target segment.',
            'mitre_chain': 'T0846 → T0843 → T0830',
        },
        'scan_to_replay': {
            'sequence'   : ['port-scan', 'replay'],
            'predicts'   : 'PLC command injection in progress',
            'severity'   : 'CRITICAL',
            'action'     : 'Freeze PLC write permissions. Alert plant operator.',
            'mitre_chain': 'T0846 → T0843',
        },
        'full_apt_chain': {
            'sequence'   : ['ip-scan', 'port-scan', 'mitm'],
            'predicts'   : 'Full APT compromise — data exfiltration + control takeover',
            'severity'   : 'CRITICAL',
            'action'     : 'EMERGENCY: Isolate entire OT network segment immediately.',
            'mitre_chain': 'T0846 → T0843 → T0830 → T0836',
        },
        'ddos_pattern': {
            'sequence'   : ['ddos', 'ddos'],
            'predicts'   : 'Sustained DDoS — PLC availability at risk',
            'severity'   : 'HIGH',
            'action'     : 'Rate-limit source. Verify PLC heartbeat continuity.',
            'mitre_chain': 'T0814 → T0814',
        },
    }

    def __init__(self, window_minutes=10):
        # Per-IP event history
        self.history       = defaultdict(list)
        self.window        = timedelta(minutes=window_minutes)
        self.predictions   = []
        self.blocked_ips   = set()

    def add_event(self, src_ip, attack_type, confidence, dst_ip=''):
        """Call this every time an attack is detected."""
        now = datetime.now()

        # Clean old events outside the time window
        self.history[src_ip] = [
            e for e in self.history[src_ip]
            if now - e['time'] < self.window
        ]

        # Add new event
        self.history[src_ip].append({
            'type'      : attack_type,
            'time'      : now,
            'confidence': confidence,
            'dst'       : dst_ip,
        })

        # Check for kill chain matches
        return self._check_kill_chains(src_ip, now)

    def _check_kill_chains(self, src_ip, now):
        """Check if recent events from this IP match a known kill chain."""
        recent_types = [
            e['type'] for e in self.history[src_ip]
        ]
        predictions_triggered = []

        for chain_name, chain in self.KILL_CHAINS.items():
            seq = chain['sequence']
            # Check if sequence appears in recent history
            if self._sequence_in_list(seq, recent_types):
                prediction = {
                    'src_ip'     : src_ip,
                    'chain'      : chain_name,
                    'detected_at': now.strftime('%H:%M:%S'),
                    'predicts'   : chain['predicts'],
                    'severity'   : chain['severity'],
                    'action'     : chain['action'],
                    'mitre_chain': chain['mitre_chain'],
                    'events_seen': len(self.history[src_ip]),
                }
                self.predictions.insert(0, prediction)
                predictions_triggered.append(prediction)

        return predictions_triggered

    def _sequence_in_list(self, seq, lst):
        """Check if seq appears as a subsequence in lst."""
        it = iter(lst)
        return all(s in it for s in seq)

    def recommend_action(self, src_ip, attack_type):
        """Generate specific prevention action for this attack."""
        actions = {
            'ip-scan': [
                f"1. Log {src_ip} — reconnaissance in progress",
                f"2. Add {src_ip} to watchlist",
                f"3. If followed by port-scan, block immediately",
                f"4. Check if {src_ip} belongs to a known asset",
            ],
            'port-scan': [
                f"1. BLOCK {src_ip} at firewall — active probing",
                f"2. Identify which Modbus/DNP3 ports were probed",
                f"3. Close all non-essential OT ports",
                f"4. Alert network admin",
            ],
            'mitm': [
                f"1. EMERGENCY: Enable packet signing on all PLC comms",
                f"2. Flush ARP cache on all switches",
                f"3. Identify compromised switch/router",
                f"4. Verify PLC register values manually",
            ],
            'ddos': [
                f"1. Rate-limit {src_ip} to max 10 packets/sec",
                f"2. Verify PLC heartbeat is still responding",
                f"3. Activate backup communication path",
                f"4. Contact upstream ISP for null-routing if external IP",
            ],
            'replay': [
                f"1. CRITICAL: Check PLC for unauthorized state changes",
                f"2. Compare current PLC values to last known good state",
                f"3. Enable command timestamping and sequence numbers",
                f"4. Rollback PLC program if state has changed",
            ],
        }
        return actions.get(attack_type, [f"Investigate {src_ip} immediately."])


# ── Main prevention analysis ──────────────────────────────────
def analyze_prevention(alerts):
    """
    Takes a list of alerts and runs full prevention analysis.
    Call this with your alerts from capture.py or detect.py.
    """
    tracker = AttackSequenceTracker(window_minutes=10)

    print("=" * 60)
    print("  SURAKSHA — PREVENTIVE ANALYSIS ENGINE")
    print("=" * 60)

    for alert in alerts:
        src        = alert.get('src', 'unknown')
        attack     = alert.get('attack_type', 'unknown')
        confidence = alert.get('confidence', 0)
        dst        = alert.get('dst', '')

        print(f"\n{'─'*60}")
        print(f"  Analyzing: {attack.upper()} from {src}")
        print(f"{'─'*60}")

        # ── Step 1: GeoIP ─────────────────────────────────────
        print(f"\n  📍 GEOGRAPHIC ORIGIN")
        loc = get_ip_location(src)
        print(f"     Country  : {loc['flag']}  {loc['country']}")
        print(f"     City     : {loc['city']}, {loc.get('region', '')}")
        print(f"     ISP/Org  : {loc['isp']}")
        print(f"     Risk     : {loc['risk']}")
        print(f"     Lat/Lon  : {loc['lat']}, {loc['lon']}")

        # ── Step 2: Specific action ───────────────────────────
        print(f"\n  🛡️  PREVENTION STEPS")
        steps = tracker.recommend_action(src, attack)
        for step in steps:
            print(f"     {step}")

        # ── Step 3: Kill chain tracking ───────────────────────
        predictions = tracker.add_event(src, attack, confidence, dst)
        if predictions:
            for pred in predictions:
                print(f"\n  ⚠️  KILL CHAIN DETECTED — PREDICTIVE ALERT")
                print(f"     Chain    : {pred['chain']}")
                print(f"     Predicts : {pred['predicts']}")
                print(f"     Severity : {pred['severity']}")
                print(f"     MITRE    : {pred['mitre_chain']}")
                print(f"  🚨 ACTION  : {pred['action']}")

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  PREVENTION SUMMARY")
    print(f"{'='*60}")
    unique_sources = set(a.get('src') for a in alerts)
    print(f"  Unique attacker IPs : {len(unique_sources)}")
    print(f"  Kill chains matched : {len(tracker.predictions)}")
    print(f"  Total events tracked: {sum(len(v) for v in tracker.history.values())}")

    if tracker.predictions:
        print(f"\n  PREDICTED NEXT ATTACKS:")
        for p in tracker.predictions[:3]:
            print(f"  → {p['src_ip']} likely to attempt {p['predicts']}")

    print(f"{'='*60}\n")

    return tracker


# ── Test with sample alerts ───────────────────────────────────
if __name__ == "__main__":

    # Sample alerts simulating a real attack sequence
    # In production these come from capture.py or alerts.json
    sample_alerts = [
        {
            'src'        : '45.33.32.156',    # Scanme.nmap.org — safe test IP
            'dst'        : '10.10.11.13',
            'attack_type': 'ip-scan',
            'confidence' : 85.0,
        },
        {
            'src'        : '45.33.32.156',
            'dst'        : '10.10.11.13',
            'attack_type': 'port-scan',
            'confidence' : 91.0,
        },
        {
            'src'        : '8.8.8.8',         # Google — will show as internal/known
            'dst'        : '10.10.11.13',
            'attack_type': 'ddos',
            'confidence' : 76.0,
        },
    ]

    # If alerts.json exists from capture.py, use that instead
    import os
    if os.path.exists('models/alerts.json'):
        print("Loading real alerts from models/alerts.json...")
        with open('models/alerts.json') as f:
            sample_alerts = json.load(f)
        print(f"Loaded {len(sample_alerts)} real alerts.\n")

    analyze_prevention(sample_alerts)