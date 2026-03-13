# blocker.py — SURAKSHA Automated Blocking Engine
# Level 1: Soft blocklist (safe, always)
# Level 2: Windows Firewall block (requires admin)
# Safety rule: NEVER auto-block internal IPs without confirmation

import json
import os
import subprocess
import platform
from datetime import datetime

BLOCKLIST_FILE = 'models/blocklist.json'

# IPs that should NEVER be blocked no matter what
# Add your PLCs, HMIs, SCADA servers here
NEVER_BLOCK = {
    '127.0.0.1', '0.0.0.0',
    '192.168.1.10',   # PLC-01
    '192.168.1.11',   # PLC-02
    '192.168.1.20',   # HMI-01
    '192.168.1.2',    # SCADA Server
    '8.8.8.8',        # Google DNS
    '8.8.4.4',        # Google DNS
}

# Internal ranges — require manual confirmation before blocking
INTERNAL_RANGES = ['192.168.', '10.', '172.16.', '172.17.']


def is_internal(ip):
    return any(ip.startswith(r) for r in INTERNAL_RANGES)


def is_safe_to_block(ip):
    if ip in NEVER_BLOCK:
        return False, "IP is in NEVER_BLOCK safety list"
    if is_internal(ip):
        return False, "Internal IP — requires manual confirmation"
    return True, "Safe to block"


class AutoBlocker:
    def __init__(self):
        self.blocklist = {}
        self.block_log = []
        self._load()

    def _load(self):
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE) as f:
                data = json.load(f)
                self.blocklist = data.get('blocklist', {})
                self.block_log = data.get('log', [])

    def _save(self):
        os.makedirs('models', exist_ok=True)
        with open(BLOCKLIST_FILE, 'w') as f:
            json.dump({
                'blocklist': self.blocklist,
                'log'      : self.block_log[-200:],
            }, f, indent=2)

    def block_ip(self, ip, reason, attack_type, severity, auto=True):
        """
        Main blocking function.
        auto=True  → block without asking (only for external IPs)
        auto=False → print warning and skip internal IPs
        """
        # Safety check first — always
        safe, msg = is_safe_to_block(ip)

        if not safe:
            print(f"  ⛔ BLOCK SKIPPED: {ip} — {msg}")
            return False

        if ip in self.blocklist:
            print(f"  ℹ️  {ip} already blocked")
            return True

        now = datetime.now().isoformat()

        # Level 1 — Add to soft blocklist
        self.blocklist[ip] = {
            'reason'     : reason,
            'attack_type': attack_type,
            'severity'   : severity,
            'blocked_at' : now,
            'auto'       : auto,
        }

        log_entry = {
            'ip'         : ip,
            'action'     : 'BLOCKED',
            'reason'     : reason,
            'attack_type': attack_type,
            'time'       : now,
        }
        self.block_log.append(log_entry)
        self._save()

        print(f"\n  {'='*55}")
        print(f"  🚫 IP BLOCKED")
        print(f"  {'='*55}")
        print(f"  IP          : {ip}")
        print(f"  Reason      : {reason}")
        print(f"  Attack Type : {attack_type}")
        print(f"  Severity    : {severity}")
        print(f"  Time        : {now}")

        # Level 2 — Windows Firewall block (needs admin)
        fw_success = self._windows_firewall_block(ip, reason)
        if fw_success:
            print(f"  Firewall    : ✅ Windows Firewall rule added")
        else:
            print(f"  Firewall    : ⚠️  Soft block only (run as Admin for firewall)")

        print(f"  {'='*55}\n")
        return True

    def _windows_firewall_block(self, ip, reason):
        """Add Windows Firewall inbound block rule."""
        if platform.system() != 'Windows':
            return False
        try:
            rule_name = f"SURAKSHA_BLOCK_{ip.replace('.', '_')}"
            cmd = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name}" '
                f'dir=in action=block '
                f'remoteip={ip} '
                f'description="Auto-blocked by SURAKSHA: {reason}"'
            )
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def unblock_ip(self, ip):
        """Manually unblock an IP."""
        if ip not in self.blocklist:
            print(f"  {ip} is not in blocklist")
            return

        del self.blocklist[ip]
        self.block_log.append({
            'ip'    : ip,
            'action': 'UNBLOCKED',
            'time'  : datetime.now().isoformat(),
        })
        self._save()

        # Remove firewall rule too
        if platform.system() == 'Windows':
            rule_name = f"SURAKSHA_BLOCK_{ip.replace('.', '_')}"
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                shell=True, capture_output=True
            )
        print(f"  ✅ {ip} unblocked")

    def is_blocked(self, ip):
        return ip in self.blocklist

    def print_blocklist(self):
        print(f"\n{'='*55}")
        print(f"  BLOCKLIST — {len(self.blocklist)} IPs blocked")
        print(f"{'='*55}")
        if not self.blocklist:
            print("  No IPs currently blocked.")
        for ip, info in self.blocklist.items():
            print(f"  🚫 {ip:<20} {info['attack_type']:<12} "
                  f"{info['severity']:<10} {info['blocked_at'][:19]}")
        print(f"{'='*55}\n")

    def should_auto_block(self, attack_type, confidence, severity):
        """
        Decision logic — when to auto-block vs alert only.
        OT safety rule: be conservative.
        """
        # Always auto-block high confidence critical attacks
        if severity == 'CRITICAL' and confidence >= 85:
            return True
        # Auto-block confirmed DDoS at any confidence
        if attack_type == 'ddos' and confidence >= 80:
            return True
        # Auto-block port-scan + ip-scan (reconnaissance)
        if attack_type in ('port-scan', 'ip-scan') and confidence >= 90:
            return True
        # For MITM and replay — alert only, don't auto-block
        # because these could be false positives affecting production
        return False


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    blocker = AutoBlocker()

    test_blocks = [
        ('45.33.32.156', 'port-scan detected', 'port-scan', 'MEDIUM'),
        ('103.21.244.0',  'DDoS confirmed',     'ddos',      'CRITICAL'),
        ('192.168.1.10',  'false positive test', 'mitm',     'HIGH'),   # should be blocked by safety
        ('8.8.8.8',       'false positive test', 'ddos',     'CRITICAL'), # never block
    ]

    print("Testing auto-blocker...\n")
    for ip, reason, atype, sev in test_blocks:
        blocker.block_ip(ip, reason, atype, sev)

    blocker.print_blocklist()