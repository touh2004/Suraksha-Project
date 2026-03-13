# suraksha.py — SURAKSHA Master Runner
# Ties all 5 modules together in one command
# Usage:
#   python suraksha.py learn    → build YOUR network baseline
#   python suraksha.py scan     → run all checks on alerts.json
#   python suraksha.py status   → show full system status
#   python suraksha.py test     → run all module tests

import sys
import os
import json

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ███████╗██╗   ██╗██████╗  █████╗ ██╗  ██╗███████╗    ║
║   ██╔════╝██║   ██║██╔══██╗██╔══██╗██║ ██╔╝██╔════╝    ║
║   ███████╗██║   ██║██████╔╝███████║█████╔╝ ███████╗     ║
║   ╚════██║██║   ██║██╔══██╗██╔══██║██╔═██╗ ╚════██║    ║
║   ███████║╚██████╔╝██║  ██║██║  ██║██║  ██╗███████║    ║
║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ║
║                                                          ║
║          ICS / OT Intrusion Detection System             ║
║          Detection + Prevention + Intelligence           ║
╚══════════════════════════════════════════════════════════╝
    """)


def cmd_learn():
    """Train self-learning baseline from your ICS dataset."""
    print("\n[ MODE: LEARN — Building network baseline ]\n")
    from baseline import SelfLearningBaseline
    bl = SelfLearningBaseline()
    dataset = 'dataset/extracted/Dataset.csv'
    if os.path.exists(dataset):
        bl.learn_from_dataset(dataset, n_rows=5000)
        bl.print_status()
    else:
        print("Dataset not found at dataset/extracted/Dataset.csv")


def cmd_scan():
    """Full scan: load alerts, run all 5 modules."""
    print("\n[ MODE: SCAN — Full analysis on captured alerts ]\n")

    alerts_file = 'models/alerts.json'
    if not os.path.exists(alerts_file):
        print("No alerts.json found.")
        print("Run capture.py first to generate alerts.\n")
        print("Using sample alerts for demo...\n")
        alerts = [
            {'src': '45.33.32.156', 'dst': '10.10.11.13',
             'attack_type': 'ip-scan',   'confidence': 85.0, 'sev': 'LOW'},
            {'src': '45.33.32.156', 'dst': '10.10.11.13',
             'attack_type': 'port-scan', 'confidence': 91.0, 'sev': 'MEDIUM'},
            {'src': '103.21.244.0', 'dst': '10.10.11.13',
             'attack_type': 'ddos',      'confidence': 95.0, 'sev': 'CRITICAL'},
        ]
    else:
        with open(alerts_file) as f:
            alerts = json.load(f)
        print(f"Loaded {len(alerts)} real alerts from alerts.json\n")

    src_ips = list(set(a.get('src', '') for a in alerts if a.get('src')))

    # ── Module 1: Asset Inventory ─────────────────────────────
    print("=" * 60)
    print("  MODULE 1 — ASSET INVENTORY")
    print("=" * 60)
    from assets import AssetInventory
    inv = AssetInventory()
    for a in alerts:
        inv.see_device(
            a.get('src', ''),
            'Modbus TCP',
            is_attack=True,
        )
    inv.print_registry()

    # ── Module 2: Threat Intelligence ────────────────────────
    print("=" * 60)
    print("  MODULE 2 — THREAT INTELLIGENCE")
    print("=" * 60)
    from threat_intel import ThreatIntel
    ti = ThreatIntel()
    ti.bulk_check(src_ips)

    # ── Module 3: Prevention + Kill Chain ────────────────────
    print("=" * 60)
    print("  MODULE 3 — KILL CHAIN + PREVENTION")
    print("=" * 60)
    from prevent import analyze_prevention
    tracker = analyze_prevention(alerts)

    # ── Module 4: Auto Blocker ────────────────────────────────
    print("=" * 60)
    print("  MODULE 4 — AUTO BLOCKER")
    print("=" * 60)
    from blocker import AutoBlocker
    bl = AutoBlocker()
    for a in alerts:
        src        = a.get('src', '')
        atype      = a.get('attack_type', 'unknown')
        sev        = a.get('sev', a.get('severity', 'MEDIUM'))
        confidence = a.get('confidence', 0)
        if bl.should_auto_block(atype, confidence, sev):
            bl.block_ip(
                src,
                reason     =f"{atype} detected with {confidence}% confidence",
                attack_type=atype,
                severity   =sev,
            )
    bl.print_blocklist()

    # ── Module 5: Baseline Check ──────────────────────────────
    print("=" * 60)
    print("  MODULE 5 — BASELINE STATUS")
    print("=" * 60)
    from baseline import SelfLearningBaseline
    base = SelfLearningBaseline()
    base.print_status()
    if not base.is_trained:
        print("  Run: python suraksha.py learn")
        print("  to train baseline on your network\n")

    # ── Summary ───────────────────────────────────────────────
    print("=" * 60)
    print("  FULL SCAN COMPLETE")
    print("=" * 60)
    print(f"  Alerts analyzed     : {len(alerts)}")
    print(f"  Unique source IPs   : {len(src_ips)}")
    print(f"  Kill chains matched : {len(tracker.predictions)}")
    blocked = sum(
        1 for a in alerts
        if bl.is_blocked(a.get('src', ''))
    )
    print(f"  IPs blocked         : {blocked}")
    print("=" * 60 + "\n")


def cmd_status():
    """Show status of all models and modules."""
    print("\n[ MODE: STATUS ]\n")

    print("=" * 55)
    print("  ML MODELS")
    print("=" * 55)
    models = [
        'models/isolation_forest.pkl',
        'models/random_forest_binary.pkl',
        'models/random_forest_multiclass.pkl',
        'models/plc_isolation_forest.pkl',
        'models/network_scaler.pkl',
        'models/plc_scaler.pkl',
        'models/label_encoder.pkl',
        'models/feature_cols.pkl',
    ]
    for m in models:
        status = '✅' if os.path.exists(m) else '❌'
        size   = f"{os.path.getsize(m)//1024}KB" if os.path.exists(m) else '—'
        print(f"  {status}  {m:<42} {size}")

    print("\n  PREVENTION MODULES")
    print("=" * 55)
    files = [
        ('assets.py',       'Asset Inventory'),
        ('blocker.py',      'Auto Blocker'),
        ('threat_intel.py', 'Threat Intelligence'),
        ('baseline.py',     'Self-Learning Baseline'),
        ('dpi.py',          'Deep Packet Inspection'),
        ('prevent.py',      'Kill Chain Prevention'),
    ]
    for fname, desc in files:
        status = '✅' if os.path.exists(fname) else '❌'
        print(f"  {status}  {fname:<20} {desc}")

    print("\n  DATA FILES")
    print("=" * 55)
    data_files = [
        ('models/alerts.json',            'Captured alerts'),
        ('models/blocklist.json',         'IP blocklist'),
        ('models/asset_registry.json',    'Device registry'),
        ('models/network_baseline.json',  'Network baseline'),
        ('models/threat_intel_cache.json','TI cache'),
    ]
    for fpath, desc in data_files:
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            print(f"  ✅  {fpath:<38} {desc} ({size}B)")
        else:
            print(f"  ⬜  {fpath:<38} {desc} (not created yet)")

    print("=" * 55 + "\n")


def cmd_test():
    """Run standalone tests for all modules."""
    print("\n[ MODE: TEST — Running all module tests ]\n")

    print("─" * 55)
    print("  Testing assets.py...")
    os.system("python assets.py")

    print("─" * 55)
    print("  Testing blocker.py...")
    os.system("python blocker.py")

    print("─" * 55)
    print("  Testing threat_intel.py...")
    os.system("python threat_intel.py")

    print("─" * 55)
    print("  Testing baseline.py...")
    os.system("python baseline.py")

    print("─" * 55)
    print("  Testing dpi.py...")
    os.system("python dpi.py")

    print("─" * 55)
    print("  Testing prevent.py...")
    os.system("python prevent.py")

    print("\n  All module tests complete.")


# ── Entry point ───────────────────────────────────────────────
if __name__ == '__main__':
    print_banner()

    commands = {
        'learn' : cmd_learn,
        'scan'  : cmd_scan,
        'status': cmd_status,
        'test'  : cmd_test,
    }

    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print("Usage:")
        print("  python suraksha.py learn    → build self-learning baseline")
        print("  python suraksha.py scan     → full analysis on captured alerts")
        print("  python suraksha.py status   → show all module status")
        print("  python suraksha.py test     → test all modules individually")
        print()
        # Default: show status
        cmd_status()
    else:
        commands[sys.argv[1]]()