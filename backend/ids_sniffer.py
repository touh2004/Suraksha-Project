# backend/ids_sniffer.py
from scapy.all import sniff, TCP, IP
import requests
import time
import logging

# Disable scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

API_URL = "http://127.0.0.1:8000/api/v1/trigger-attack"
TARGET_PORT = 5020

print(f"🛡️ Suraksha SENTINEL IDS is ONLINE.")
print(f"👁️‍🗨️ Actively sniffing network traffic on Port {TARGET_PORT} (Modbus TCP)...")

def process_packet(packet):
    # Check if packet is TCP and going to our Virtual PLC
    if packet.haslayer(TCP) and packet[TCP].dport == TARGET_PORT:
        
        # Get raw data payload from the packet
        raw_data = bytes(packet[TCP].payload)
        
        # Modbus TCP packets have a 7-byte header. The 8th byte is the Function Code.
        if len(raw_data) > 7:
            function_code = raw_data[7]
            
            # FC-05 means "Write Single Coil" (A command to turn a machine ON/OFF)
            if function_code == 5:
                attacker_ip = packet[IP].src if packet.haslayer(IP) else "Unknown IP"
                
                print(f"\n🚨 [ALERT] MALICIOUS MODBUS COMMAND DETECTED!")
                print(f"💀 Attacker IP: {attacker_ip}")
                print(f"⚙️ Target: PLC-01 (Port {TARGET_PORT})")
                print(f"🛡️ Action: Sending trigger to SOC Dashboard...")
                
                # SEND SIGNAL TO FASTAPI BACKEND!
                payload = {
                    "attacker_ip": attacker_ip,
                    "target_device": f"10.0.0.12 (Virtual PLC-01)",
                    "attack_type": "Modbus FC-05 Write Injection"
                }
                
                try:
                    # Trigger the dashboard to turn RED
                    requests.post(API_URL, json=payload)
                    print("✅ Dashboard Updated Successfully!")
                except Exception as e:
                    print("❌ Failed to reach dashboard. Is FastAPI running?")

# Start sniffing the network interface (store=0 means it won't eat your RAM)
sniff(filter=f"tcp port {TARGET_PORT}", prn=process_packet, store=0)