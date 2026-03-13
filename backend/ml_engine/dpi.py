# dpi.py — SURAKSHA Deep Packet Inspection
# Looks INSIDE ICS protocol packets — not just flow stats
# Supports: Modbus TCP, DNP3, Siemens S7
# Detects dangerous function codes that cause physical harm

from scapy.all import IP, TCP, UDP, Raw
import struct

# ── Modbus TCP ────────────────────────────────────────────────
# Function codes ranked by danger level
MODBUS_FC = {
    0x01: {'name': 'Read Coils',              'risk': 'LOW',      'safe': True},
    0x02: {'name': 'Read Discrete Inputs',    'risk': 'LOW',      'safe': True},
    0x03: {'name': 'Read Holding Registers',  'risk': 'LOW',      'safe': True},
    0x04: {'name': 'Read Input Registers',    'risk': 'LOW',      'safe': True},
    0x05: {'name': 'Write Single Coil',       'risk': 'HIGH',     'safe': False},
    0x06: {'name': 'Write Single Register',   'risk': 'HIGH',     'safe': False},
    0x08: {'name': 'Diagnostics',             'risk': 'MEDIUM',   'safe': False},
    0x0F: {'name': 'Write Multiple Coils',    'risk': 'CRITICAL', 'safe': False},
    0x10: {'name': 'Write Multiple Registers','risk': 'CRITICAL', 'safe': False},
    0x11: {'name': 'Report Slave ID',         'risk': 'MEDIUM',   'safe': False},
    0x14: {'name': 'Read File Record',        'risk': 'MEDIUM',   'safe': False},
    0x15: {'name': 'Write File Record',       'risk': 'CRITICAL', 'safe': False},
    0x16: {'name': 'Mask Write Register',     'risk': 'CRITICAL', 'safe': False},
    0x17: {'name': 'R/W Multiple Registers',  'risk': 'CRITICAL', 'safe': False},
    0x2B: {'name': 'Read Device ID',          'risk': 'MEDIUM',   'safe': False},
}

# ── DNP3 Function Codes ───────────────────────────────────────
DNP3_FC = {
    0x00: {'name': 'Confirm',           'risk': 'LOW'},
    0x01: {'name': 'Read',              'risk': 'LOW'},
    0x02: {'name': 'Write',             'risk': 'HIGH'},
    0x03: {'name': 'Select',            'risk': 'HIGH'},
    0x04: {'name': 'Operate',           'risk': 'CRITICAL'},   # actually operates output
    0x05: {'name': 'Direct Operate',    'risk': 'CRITICAL'},   # bypasses select-before-operate
    0x06: {'name': 'Direct Operate NR', 'risk': 'CRITICAL'},
    0x07: {'name': 'Freeze',            'risk': 'MEDIUM'},
    0x09: {'name': 'Freeze Clear',      'risk': 'HIGH'},
    0x0D: {'name': 'Cold Restart',      'risk': 'CRITICAL'},   # restarts device
    0x0E: {'name': 'Warm Restart',      'risk': 'CRITICAL'},
    0x81: {'name': 'Response',          'risk': 'LOW'},
    0x82: {'name': 'Unsolicited Response','risk': 'MEDIUM'},
}

# ── Siemens S7 Function Codes ─────────────────────────────────
S7_FC = {
    0x00: {'name': 'CPU Services',       'risk': 'LOW'},
    0x04: {'name': 'Read Variable',      'risk': 'LOW'},
    0x05: {'name': 'Write Variable',     'risk': 'HIGH'},
    0x1A: {'name': 'Request Download',   'risk': 'CRITICAL'},  # upload program to PLC
    0x1B: {'name': 'Download Block',     'risk': 'CRITICAL'},  # Stuxnet used this
    0x1C: {'name': 'Download Ended',     'risk': 'CRITICAL'},
    0x1D: {'name': 'Start Upload',       'risk': 'HIGH'},
    0x1E: {'name': 'Upload Block',       'risk': 'HIGH'},
    0x28: {'name': 'PLC Stop',           'risk': 'CRITICAL'},  # halts the PLC
    0x29: {'name': 'CPU Start',          'risk': 'HIGH'},
}


class DeepPacketInspector:

    def inspect(self, packet):
        """
        Main entry point. Pass any scapy packet.
        Returns inspection result or None if not an ICS packet.
        """
        if not packet.haslayer(IP):
            return None

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport

            # Modbus TCP — port 502
            if dport == 502 or sport == 502:
                return self._inspect_modbus(packet, src, dst)

            # Siemens S7 — port 102
            if dport == 102 or sport == 102:
                return self._inspect_s7(packet, src, dst)

            # DNP3 over TCP — port 20000
            if dport == 20000 or sport == 20000:
                return self._inspect_dnp3(packet, src, dst)

        if packet.haslayer(UDP):
            dport = packet[UDP].dport
            # DNP3 over UDP
            if dport == 20000:
                return self._inspect_dnp3(packet, src, dst)

        return None

    def _inspect_modbus(self, packet, src, dst):
        """
        Modbus TCP frame structure:
        [Transaction ID 2B][Protocol ID 2B][Length 2B][Unit ID 1B][FC 1B][Data...]
        MBAP header = 6 bytes, then unit id + FC
        """
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)
        if len(payload) < 8:
            return None

        try:
            transaction_id = struct.unpack('>H', payload[0:2])[0]
            protocol_id    = struct.unpack('>H', payload[2:4])[0]
            length         = struct.unpack('>H', payload[4:6])[0]
            unit_id        = payload[6]
            fc             = payload[7]

            # Protocol ID must be 0 for Modbus
            if protocol_id != 0:
                return None

            fc_info = MODBUS_FC.get(fc, {
                'name': f'Unknown FC 0x{fc:02X}',
                'risk': 'HIGH',  # unknown FC is always suspicious
                'safe': False,
            })

            result = {
                'protocol'      : 'Modbus TCP',
                'src'           : src,
                'dst'           : dst,
                'function_code' : f'0x{fc:02X}',
                'fc_name'       : fc_info['name'],
                'risk'          : fc_info['risk'],
                'is_safe'       : fc_info.get('safe', False),
                'unit_id'       : unit_id,
                'transaction_id': transaction_id,
            }

            # Extract register address for write commands
            if fc in (0x05, 0x06) and len(payload) >= 10:
                address = struct.unpack('>H', payload[8:10])[0]
                value   = struct.unpack('>H', payload[10:12])[0] if len(payload) >= 12 else None
                result['register_address'] = f'0x{address:04X}'
                result['register_value']   = value

                # Flag dangerous addresses
                if address == 0x0001:
                    result['physical_warning'] = '⚠️  Address 0x0001 — may be emergency shutoff'
                elif address == 0x0000:
                    result['physical_warning'] = '⚠️  Address 0x0000 — may be master enable/disable'

            if fc in (0x0F, 0x10) and len(payload) >= 10:
                address  = struct.unpack('>H', payload[8:10])[0]
                quantity = struct.unpack('>H', payload[10:12])[0] if len(payload) >= 12 else None
                result['register_address'] = f'0x{address:04X}'
                result['quantity']         = quantity
                result['physical_warning'] = f'⚠️  Writing {quantity} registers from 0x{address:04X}'

            self._print_dpi_result(result)
            return result

        except Exception:
            return None

    def _inspect_dnp3(self, packet, src, dst):
        """
        DNP3 frame: [Start 2B=0x0564][Length 1B][Control 1B][Dest 2B][Src 2B][CRC 2B]
        Application layer has function code
        """
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)
        if len(payload) < 10:
            return None

        try:
            # DNP3 start bytes
            if payload[0] != 0x05 or payload[1] != 0x64:
                return None

            # Application layer starts at offset 10 typically
            if len(payload) > 11:
                fc = payload[11]
            else:
                return None

            fc_info = DNP3_FC.get(fc, {
                'name': f'Unknown FC 0x{fc:02X}',
                'risk': 'HIGH',
            })

            result = {
                'protocol'     : 'DNP3',
                'src'          : src,
                'dst'          : dst,
                'function_code': f'0x{fc:02X}',
                'fc_name'      : fc_info['name'],
                'risk'         : fc_info['risk'],
                'is_safe'      : fc_info['risk'] == 'LOW',
            }

            if fc in (0x04, 0x05, 0x06):
                result['physical_warning'] = (
                    '🚨 CRITICAL: Direct Operate command — '
                    'physically actuates field device output'
                )
            elif fc in (0x0D, 0x0E):
                result['physical_warning'] = (
                    '🚨 CRITICAL: Restart command — '
                    'will reboot DNP3 device, causing outage'
                )

            self._print_dpi_result(result)
            return result

        except Exception:
            return None

    def _inspect_s7(self, packet, src, dst):
        """
        Siemens S7 over ISO-TSAP (port 102).
        S7 header starts after TPKT (4B) + COTP (variable).
        S7 magic bytes: 0x32
        """
        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)
        if len(payload) < 10:
            return None

        try:
            # Look for S7 magic byte 0x32
            s7_offset = None
            for i in range(min(20, len(payload) - 1)):
                if payload[i] == 0x32:
                    s7_offset = i
                    break

            if s7_offset is None or s7_offset + 10 > len(payload):
                return None

            msg_type = payload[s7_offset + 1]
            fc       = payload[s7_offset + 7] if len(payload) > s7_offset + 7 else 0

            fc_info = S7_FC.get(fc, {
                'name': f'Unknown FC 0x{fc:02X}',
                'risk': 'MEDIUM',
            })

            result = {
                'protocol'     : 'Siemens S7',
                'src'          : src,
                'dst'          : dst,
                'function_code': f'0x{fc:02X}',
                'fc_name'      : fc_info['name'],
                'risk'         : fc_info['risk'],
                'msg_type'     : msg_type,
                'is_safe'      : fc_info['risk'] == 'LOW',
            }

            if fc in (0x1A, 0x1B, 0x1C):
                result['physical_warning'] = (
                    '🚨 STUXNET-PATTERN: S7 program download detected — '
                    'PLC logic may be replaced with malicious code'
                )
            elif fc == 0x28:
                result['physical_warning'] = (
                    '🚨 CRITICAL: S7 Stop CPU command — '
                    'will halt PLC immediately'
                )

            self._print_dpi_result(result)
            return result

        except Exception:
            return None

    def _print_dpi_result(self, r):
        """Print DPI result — only for non-safe/suspicious commands."""
        if r.get('is_safe', False) and r.get('risk') == 'LOW':
            return  # don't spam console with safe read commands

        risk_icons = {
            'CRITICAL': '🚨', 'HIGH': '⚠️ ',
            'MEDIUM'  : '🔶', 'LOW' : '✅',
        }
        icon = risk_icons.get(r['risk'], '❓')

        print(f"\n  {icon} DPI ALERT — {r['protocol']}")
        print(f"     {r['src']} → {r['dst']}")
        print(f"     FC: {r['function_code']} — {r['fc_name']}")
        print(f"     Risk: {r['risk']}")
        if 'register_address' in r:
            print(f"     Register: {r['register_address']}", end='')
            if 'register_value' in r and r['register_value'] is not None:
                print(f"  Value: {r['register_value']}", end='')
            print()
        if 'physical_warning' in r:
            print(f"     {r['physical_warning']}")


# ── Standalone test with simulated packets ────────────────────
if __name__ == '__main__':
    from scapy.all import Ether

    dpi = DeepPacketInspector()

    print("=" * 60)
    print("  SURAKSHA DPI — Testing ICS Protocol Inspection")
    print("=" * 60)

    # Test 1: Modbus Read (safe)
    print("\n[TEST 1] Modbus Read Coils (FC=0x01) — should be SAFE")
    modbus_read = (
        IP(src="192.168.1.100", dst="192.168.1.10") /
        TCP(sport=12345, dport=502) /
        Raw(load=bytes([
            0x00, 0x01,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x01,         # FC 0x01 Read Coils
            0x00, 0x00,   # Start address
            0x00, 0x10,   # Quantity
        ]))
    )
    result = dpi.inspect(modbus_read)
    if result:
        print(f"  FC: {result['fc_name']} | Risk: {result['risk']}")
    else:
        print("  Not flagged (safe read command)")

    # Test 2: Modbus Write Single Register (dangerous)
    print("\n[TEST 2] Modbus Write Single Register (FC=0x06) — should be HIGH RISK")
    modbus_write = (
        IP(src="10.0.0.55", dst="192.168.1.10") /
        TCP(sport=54321, dport=502) /
        Raw(load=bytes([
            0x00, 0x02,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x06,         # FC 0x06 Write Single Register
            0x00, 0x01,   # Address 0x0001 (emergency shutoff)
            0x00, 0xFF,   # Value 0xFF
        ]))
    )
    result = dpi.inspect(modbus_write)
    if result:
        print(f"  FC: {result['fc_name']} | Risk: {result['risk']}")

    # Test 3: Modbus Write Multiple Registers (critical)
    print("\n[TEST 3] Modbus Write Multiple Registers (FC=0x10) — CRITICAL")
    modbus_multi = (
        IP(src="10.0.0.55", dst="192.168.1.10") /
        TCP(sport=54321, dport=502) /
        Raw(load=bytes([
            0x00, 0x03, 0x00, 0x00, 0x00, 0x09,
            0x01, 0x10,         # FC 0x10 Write Multiple
            0x00, 0x00,         # Start address
            0x00, 0x03,         # Quantity 3 registers
            0x06,               # Byte count
            0x00, 0x01,
            0x00, 0x02,
            0x00, 0x03,
        ]))
    )
    result = dpi.inspect(modbus_multi)

    print("\n" + "=" * 60)
    print("  DPI test complete.")
    print("  In production, dpi.inspect(packet) is called")
    print("  inside capture.py for every ICS packet captured.")
    print("=" * 60)