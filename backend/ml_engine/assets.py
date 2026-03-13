# assets.py — SURAKSHA Asset Inventory
# Tracks every device seen on the network
# Flags rogue/unknown devices instantly
# Saves registry to asset_registry.json

import json
import os
from datetime import datetime
from collections import defaultdict

REGISTRY_FILE = 'models/asset_registry.json'

# Known legitimate devices — add your real devices here
KNOWN_DEVICES = {
    '192.168.1.1'  : {'name': 'Gateway Router',    'type': 'router',    'protocol': 'TCP/IP'},
    '192.168.1.2'  : {'name': 'SCADA Server',       'type': 'scada',     'protocol': 'Modbus TCP'},
    '192.168.1.10' : {'name': 'PLC-01 (Tank)',       'type': 'plc',       'protocol': 'Modbus TCP'},
    '192.168.1.11' : {'name': 'PLC-02 (Valve)',      'type': 'plc',       'protocol': 'Modbus TCP'},
    '192.168.1.20' : {'name': 'HMI-01',              'type': 'hmi',       'protocol': 'EtherNet/IP'},
    '192.168.1.100': {'name': 'Engineering Workstation', 'type': 'workstation', 'protocol': 'TCP/IP'},
    '10.10.11.13'  : {'name': 'OT Network Gateway',  'type': 'gateway',   'protocol': 'TCP/IP'},
}

DEVICE_TYPE_ICONS = {
    'plc'        : '⚙️ ',
    'scada'      : '🖥️ ',
    'hmi'        : '📟',
    'router'     : '🔀',
    'gateway'    : '🔀',
    'workstation': '💻',
    'unknown'    : '❓',
    'rogue'      : '🚨',
}

class AssetInventory:
    def __init__(self):
        self.registry  = {}
        self.alerts    = []
        self._load()

    def _load(self):
        if os.path.exists(REGISTRY_FILE):
            with open(REGISTRY_FILE) as f:
                self.registry = json.load(f)
        else:
            # Seed with known devices
            for ip, info in KNOWN_DEVICES.items():
                self.registry[ip] = {
                    **info,
                    'status'    : 'known',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen' : datetime.now().isoformat(),
                    'packet_count': 0,
                    'attack_count': 0,
                    'protocols_seen': [info['protocol']],
                }
            self._save()

    def _save(self):
        os.makedirs('models', exist_ok=True)
        with open(REGISTRY_FILE, 'w') as f:
            json.dump(self.registry, f, indent=2)

    def see_device(self, ip, protocol='unknown', is_attack=False):
        """
        Call this every time a packet is seen from an IP.
        Returns alert dict if rogue device detected, else None.
        """
        now    = datetime.now().isoformat()
        alert  = None

        if ip not in self.registry:
            # Brand new device never seen before
            is_known = ip in KNOWN_DEVICES
            status   = 'known' if is_known else 'rogue'

            self.registry[ip] = {
                'name'          : KNOWN_DEVICES.get(ip, {}).get('name', f'Unknown-{ip}'),
                'type'          : KNOWN_DEVICES.get(ip, {}).get('type', 'unknown'),
                'protocol'      : protocol,
                'status'        : status,
                'first_seen'    : now,
                'last_seen'     : now,
                'packet_count'  : 1,
                'attack_count'  : 1 if is_attack else 0,
                'protocols_seen': [protocol],
            }

            if not is_known:
                alert = {
                    'type'      : 'ROGUE_DEVICE',
                    'ip'        : ip,
                    'time'      : now,
                    'severity'  : 'HIGH',
                    'message'   : f'Unknown device {ip} appeared on OT network',
                    'action'    : f'Verify physically. If unrecognized, isolate {ip} immediately.',
                }
                self.alerts.append(alert)
                print(f"\n  {'='*55}")
                print(f"  🚨 ROGUE DEVICE DETECTED")
                print(f"  {'='*55}")
                print(f"  IP         : {ip}")
                print(f"  Protocol   : {protocol}")
                print(f"  First seen : {now}")
                print(f"  Action     : Verify and isolate if unrecognized")
                print(f"  {'='*55}\n")

        else:
            # Update existing device
            self.registry[ip]['last_seen']    = now
            self.registry[ip]['packet_count'] += 1
            if is_attack:
                self.registry[ip]['attack_count'] += 1
                if self.registry[ip]['attack_count'] > 5:
                    self.registry[ip]['status'] = 'compromised'
            if protocol not in self.registry[ip].get('protocols_seen', []):
                self.registry[ip]['protocols_seen'].append(protocol)
                # New protocol from known device is suspicious
                if self.registry[ip]['status'] == 'known':
                    alert = {
                        'type'    : 'PROTOCOL_CHANGE',
                        'ip'      : ip,
                        'time'    : now,
                        'severity': 'MEDIUM',
                        'message' : f'{ip} using new protocol {protocol} — unexpected',
                        'action'  : 'Verify device has not been compromised or replaced.',
                    }
                    self.alerts.append(alert)

        self._save()
        return alert

    def print_registry(self):
        print(f"\n{'='*65}")
        print(f"  ASSET REGISTRY — {len(self.registry)} devices")
        print(f"{'='*65}")

        known      = [d for d in self.registry.values() if d['status'] == 'known']
        rogue      = [d for d in self.registry.values() if d['status'] == 'rogue']
        compromised= [d for d in self.registry.values() if d['status'] == 'compromised']

        print(f"  ✅ Known     : {len(known)}")
        print(f"  🚨 Rogue     : {len(rogue)}")
        print(f"  ⚠️  Compromised: {len(compromised)}")
        print(f"{'─'*65}")

        for ip, d in sorted(self.registry.items()):
            icon = DEVICE_TYPE_ICONS.get(d['type'], '❓')
            status_color = {
                'known'      : '✅',
                'rogue'      : '🚨',
                'compromised': '⚠️ ',
            }.get(d['status'], '❓')

            print(f"  {status_color} {icon} {ip:<18} {d['name']:<28} {d['status'].upper()}")
            print(f"       Protocol: {d['protocol']:<15} "
                  f"Packets: {d['packet_count']:<8} "
                  f"Attacks: {d['attack_count']}")
            print(f"       First: {d['first_seen'][:19]}  "
                  f"Last: {d['last_seen'][:19]}")
            print()

        print(f"{'='*65}\n")
        return {
            'total'      : len(self.registry),
            'known'      : len(known),
            'rogue'      : len(rogue),
            'compromised': len(compromised),
        }

    def get_summary(self):
        return {
            ip: {
                'name'        : d['name'],
                'type'        : d['type'],
                'status'      : d['status'],
                'last_seen'   : d['last_seen'],
                'attack_count': d['attack_count'],
                'packet_count': d['packet_count'],
            }
            for ip, d in self.registry.items()
        }


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    inv = AssetInventory()

    # Simulate seeing devices
    test_events = [
        ('192.168.1.10', 'Modbus TCP', False),   # known PLC — normal
        ('192.168.1.20', 'EtherNet/IP', False),  # known HMI — normal
        ('192.168.1.99', 'Modbus TCP', True),    # UNKNOWN — rogue!
        ('10.0.0.55',    'DNP3', True),          # UNKNOWN external — rogue!
        ('192.168.1.10', 'DNP3', False),         # known PLC using new protocol
    ]

    print("Simulating device sightings...\n")
    for ip, proto, is_attack in test_events:
        inv.see_device(ip, proto, is_attack)

    inv.print_registry()