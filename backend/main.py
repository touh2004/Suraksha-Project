# backend/main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import datetime
import os
import sys

# ==========================================
# THE ML WIRE-UP (MAGIC HAPPENS HERE)
# ==========================================
# Shift the working directory to ml_engine so it finds the 'models/' folder perfectly
current_dir = os.path.dirname(os.path.abspath(__file__))
ml_engine_path = os.path.join(current_dir, "ml_engine")
os.chdir(ml_engine_path)
sys.path.append(ml_engine_path)

# Import Soumya's Real ML Engine!
from detect import detect_network_flow

# Initialize FastAPI
app = FastAPI(title="Suraksha SENTINEL API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🧠 THE DEMO STATE
SYSTEM_STATE = {
    "is_under_attack": False,
    "current_threat_ip": None,
    "target_device": None,
    "attack_type": None,
}

ALERT_HISTORY = []
ALERT_COUNTER = 1

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# ==========================================
# APIs
# ==========================================

@app.get("/api/v1/status")
def get_global_status():
    if SYSTEM_STATE["is_under_attack"]:
        # Simulate an attack flow to get real ML output
        synthetic_flow = {
            "sPackets": 5000,
            "sBytesSum": 950000,
            "duration": 0.5
        }
        # 🧠 CALLING REAL ML ENGINE
        ml_result = detect_network_flow(synthetic_flow)
        
        return {
            "is_under_attack": True,
            "devices_online": 6,
            "packets_per_second": 14250, 
            "critical_alerts": len(ALERT_HISTORY),
            "ml_confidence": ml_result.get("confidence", 98.5),
            "baseline_status": "Threat Detected",
            "active_threat": ml_result.get("attack_type", "DDoS")
        }
    else:
        # Simulate normal flow for baseline ML score
        normal_flow = {
            "sPackets": 12,
            "sBytesSum": 785,
            "duration": 0.35
        }
        # 🧠 CALLING REAL ML ENGINE
        ml_result = detect_network_flow(normal_flow)
        
        return {
            "is_under_attack": False,
            "devices_online": 6,
            "packets_per_second": 3420,  
            "critical_alerts": 0,
            "ml_confidence": ml_result.get("confidence", 8.2),       
            "baseline_status": "Monitoring Normal",
            "active_threat": "None"
        }

@app.get("/api/v1/alerts")
def get_alerts():
    return ALERT_HISTORY

@app.get("/api/v1/devices")
def get_devices():
    base_devices = [
        {"ip": "10.0.0.11", "name": "HMI-D1", "status": "ONLINE", "type": "Known"},
        {"ip": "10.0.0.12", "name": "PLC-01", "status": "ONLINE", "type": "Known"},
        {"ip": "10.0.0.13", "name": "Robotic Arm", "status": "ONLINE", "type": "Known"},
        {"ip": "10.0.0.14", "name": "Conveyor Sensor", "status": "ONLINE", "type": "Known"},
        {"ip": "10.0.0.15", "name": "HMI-01", "status": "ONLINE", "type": "Known"},
        {"ip": "10.0.0.16", "name": "PLC-04", "status": "ONLINE", "type": "Known"}
    ]
    if SYSTEM_STATE["is_under_attack"]:
        base_devices.append({
            "ip": SYSTEM_STATE["current_threat_ip"], 
            "name": "Unknown Device", 
            "status": "ROGUE", 
            "type": "Threat"
        })
        for device in base_devices:
            if device["name"] == "PLC-01":
                device["status"] = "COMPROMISED"
    return base_devices

@app.get("/api/v1/incident-details")
def get_incident_details():
    if SYSTEM_STATE["is_under_attack"]:
        return {
            "protocol": "Modbus TCP",
            "transport": "TCP",
            "port": 5020,
            "function_code": "0x05",
            "fc_name": "Write Single Coil",
            "playbook_steps": [
                "Isolate PLC-01 from main VLAN.",
                f"Block IP {SYSTEM_STATE['current_threat_ip']} at perimeter firewall.",
                "Flush Modbus holding registers."
            ]
        }
    return {"message": "System is secure."}

class AttackPayload(BaseModel):
    attacker_ip: str
    target_device: str
    attack_type: str

@app.post("/api/v1/trigger-attack")
async def trigger_attack(payload: AttackPayload):
    global ALERT_COUNTER
    
    # Send a malicious flow to the ML to get exact MITRE tags and Risk
    synthetic_attack_flow = {"sPackets": 10000, "sBytesSum": 999999}
    ml_result = detect_network_flow(synthetic_attack_flow)
    
    SYSTEM_STATE["is_under_attack"] = True
    SYSTEM_STATE["current_threat_ip"] = payload.attacker_ip
    SYSTEM_STATE["target_device"] = payload.target_device
    SYSTEM_STATE["attack_type"] = ml_result.get("attack_type", "Injection")
    
    # Use real ML data for the alert!
    live_alert = {
        "id": f"A-{1000 + ALERT_COUNTER}",
        "source_ip": payload.attacker_ip,
        "destination_ip": payload.target_device,
        "severity": ml_result.get("severity", "CRITICAL"),
        "mitre_tag": ml_result.get("mitre", "T0836"),
        "title": f"AI DETECTED: {SYSTEM_STATE['attack_type']}",
        "description": ml_result.get("risk", "Rogue command detected!"),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    ALERT_HISTORY.insert(0, live_alert)
    ALERT_COUNTER += 1
    
    await manager.broadcast({"type": "alert", "data": live_alert})
    return {"status": "success"}

@app.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/v1/reset")
def reset_system():
    global ALERT_COUNTER
    SYSTEM_STATE["is_under_attack"] = False
    SYSTEM_STATE["current_threat_ip"] = None
    ALERT_HISTORY.clear()
    ALERT_COUNTER = 1
    return {"message": "System reset to secure baseline."}