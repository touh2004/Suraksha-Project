// src/App.jsx
import React, { useState, useEffect, useRef } from 'react';
import apiClient from './services/apiClient';
import './App.css';

// ==========================================
// 🚀 CANVAS RADAR COMPONENT (BLUE/BLACK THEME)
// ==========================================
const NODES = [
  { label: "HMI-D1",         x: 147, y: 141, icon: "🖥",  isTarget: false },
  { label: "PLC-01",         x: 472, y: 140, icon: "⊞",  isTarget: true  }, 
  { label: "Robotic Arm",    x: 120, y: 268, icon: "🦾", isTarget: false },
  { label: "Conveyor Sensor",x: 168, y: 338, icon: "⚙",  isTarget: false },
  { label: "HMI-01",         x: 323, y: 392, icon: "🖥",  isTarget: false },
  { label: "PLC-04",         x: 532, y: 322, icon: "⊞",  isTarget: false },
];

const CX = 340, CY = 237;
const THREAT = { label: "45.X.X.X", x: 578, y: 66 };
const SPEED = 0.012;
const TRAIL = Math.PI * 0.55;

function ScadaTopology({ isUnderAttack }) {
  const canvasRef = useRef(null);
  const attackRef = useRef(isUnderAttack);
  useEffect(() => { attackRef.current = isUnderAttack; }, [isUnderAttack]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");

    if (!ctx.roundRect) {
      ctx.roundRect = function (x, y, w, h, r) {
        this.moveTo(x + r, y); this.lineTo(x + w - r, y);
        this.quadraticCurveTo(x + w, y, x + w, y + r); this.lineTo(x + w, y + h - r);
        this.quadraticCurveTo(x + w, y + h, x + w - r, y + h); this.lineTo(x + r, y + h);
        this.quadraticCurveTo(x, y + h, x, y + h - r); this.lineTo(x, y + r);
        this.quadraticCurveTo(x, y, x + r, y); this.closePath();
      };
    }

    const nodes = NODES.map((n) => ({
      ...n, angle: Math.atan2(n.y - CY, n.x - CX), dist: Math.hypot(n.x - CX, n.y - CY), glow: 0,
    }));

    const ORBIT_R = nodes.reduce((s, n) => s + n.dist, 0) / nodes.length;
    let sweepAngle = -Math.PI;
    let rafId;

    function angleDiff(a, b) { return ((b - a) % (2 * Math.PI) + 2 * Math.PI) % (2 * Math.PI); }

    function draw() {
      const currentAttackStatus = attackRef.current; 

      ctx.clearRect(0, 0, 680, 480);
      ctx.fillStyle = "#050a14"; // Deep black bg
      ctx.fillRect(0, 0, 680, 480);

      ctx.beginPath(); ctx.arc(CX, CY, ORBIT_R, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(0, 210, 255, 0.05)"; // Cyan faint ring
      ctx.lineWidth = 1; ctx.stroke();

      nodes.forEach((n) => {
        const diff = angleDiff(sweepAngle, n.angle);
        if (diff < 0.18 || diff > 2 * Math.PI - 0.18) n.glow = 1.0;
        else n.glow = Math.max(0, n.glow - 0.025);
      });

      const targetNode = nodes.find((n) => n.isTarget);
      const threatGlow = currentAttackStatus ? targetNode.glow : 0; 

      const steps = 40;
      for (let i = 0; i < steps; i++) {
        const t = i / steps;
        const a0 = sweepAngle - TRAIL * (1 - t);
        const a1 = sweepAngle - TRAIL * (1 - t - 1 / steps);
        const alpha = t * 0.35;
        const r = threatGlow > 0.1
            ? `rgba(255,${Math.floor(50 * (1 - threatGlow))},0,${alpha})`
            : `rgba(0,180,255,${alpha})`; // Cyan radar
        ctx.beginPath(); ctx.moveTo(CX, CY); ctx.arc(CX, CY, ORBIT_R, a0, a1); ctx.closePath();
        ctx.fillStyle = r; ctx.fill();
      }

      const sweepColor = threatGlow > 0.1 ? `rgba(255,60,0,${0.7 + threatGlow * 0.3})` : "rgba(0,220,255,0.85)";
      ctx.beginPath(); ctx.moveTo(CX, CY); ctx.lineTo(CX + Math.cos(sweepAngle) * ORBIT_R, CY + Math.sin(sweepAngle) * ORBIT_R);
      ctx.strokeStyle = sweepColor; ctx.lineWidth = 2; ctx.shadowColor = sweepColor; ctx.shadowBlur = 10;
      ctx.stroke(); ctx.shadowBlur = 0;

      nodes.forEach((n) => {
        const isThreatHit = currentAttackStatus && n.isTarget;

        ctx.beginPath(); ctx.moveTo(CX, CY); ctx.lineTo(n.x, n.y);
        ctx.strokeStyle = n.glow > 0.05 ? (isThreatHit ? `rgba(255,60,0,${0.3 + n.glow * 0.7})` : `rgba(0,200,255,${0.3 + n.glow * 0.7})`) : "rgba(0,150,255,0.1)";
        ctx.lineWidth = n.glow > 0.05 ? 1.5 : 1; ctx.stroke();

        if (currentAttackStatus && n.isTarget && n.glow > 0.05) {
          ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(THREAT.x, THREAT.y);
          ctx.strokeStyle = `rgba(255,40,0,${n.glow * 0.9})`; ctx.lineWidth = 2; ctx.setLineDash([8, 5]);
          ctx.shadowColor = "#ff2200"; ctx.shadowBlur = 12 * n.glow; ctx.stroke();
          ctx.setLineDash([]); ctx.shadowBlur = 0;
        }

        const gc = isThreatHit ? "#ff3300" : "#00d2ff"; // Neon blue glow
        ctx.beginPath(); ctx.roundRect(n.x - 32, n.y - 18, 64, 36, 6);
        ctx.fillStyle = n.glow > 0.05 ? (isThreatHit ? `rgba(80,0,0,${0.5 + n.glow * 0.5})` : `rgba(0,40,100,${0.6 + n.glow * 0.4})`) : "rgba(0,50,150,0.1)";
        ctx.shadowColor = n.glow > 0.05 ? gc : "transparent"; ctx.shadowBlur = n.glow > 0.05 ? 18 * n.glow : 0;
        ctx.fill(); ctx.shadowBlur = 0;
        ctx.strokeStyle = n.glow > 0.05 ? gc : "rgba(0,150,255,0.2)"; ctx.lineWidth = n.glow > 0.05 ? 1.5 : 0.8;
        ctx.stroke();

        ctx.font = "14px Inter, sans-serif"; ctx.textAlign = "center"; ctx.fillStyle = "#fff"; ctx.fillText(n.icon, n.x, n.y + 2);
        ctx.font = "10px Inter, sans-serif"; ctx.fillStyle = n.glow > 0.05 ? (isThreatHit ? "#ff8866" : "#88ccff") : "#8b949e"; ctx.fillText(n.label, n.x, n.y + 30);
      });

      ctx.beginPath(); ctx.roundRect(CX - 70, CY - 27, 140, 54, 8);
      ctx.fillStyle = "#0044ff"; // Deep blue server
      ctx.shadowColor = "#0044ff"; ctx.shadowBlur = 20; ctx.fill(); ctx.shadowBlur = 0;
      ctx.fillStyle = "#fff"; ctx.font = "bold 12px Inter, sans-serif"; ctx.textAlign = "center"; ctx.fillText("SCADA SERVER", CX, CY + 4);

      if (currentAttackStatus) {
        const tg = targetNode.glow;
        ctx.beginPath(); ctx.roundRect(THREAT.x - 50, THREAT.y - 26, 100, 48, 8);
        ctx.fillStyle = tg > 0.05 ? `rgba(100,0,0,${0.5 + tg * 0.5})` : "#1a0000";
        ctx.shadowColor = "#ff2200"; ctx.shadowBlur = tg > 0.05 ? 24 * tg : 6;
        ctx.fill(); ctx.shadowBlur = 0;
        ctx.strokeStyle = tg > 0.05 ? `rgba(255,50,0,${0.5 + tg * 0.5})` : "#660000"; ctx.lineWidth = tg > 0.05 ? 2 : 1; ctx.stroke();
        ctx.font = "bold 13px Inter"; ctx.textAlign = "center"; ctx.fillStyle = tg > 0.05 ? `rgba(255,100,80,${0.7 + tg * 0.3})` : "#aa3333"; ctx.fillText("☠", THREAT.x, THREAT.y - 6);
        ctx.font = "11px Inter"; ctx.fillStyle = tg > 0.05 ? `rgba(255,120,100,${0.7 + tg * 0.3})` : "#882222"; ctx.fillText("45.X.X.X", THREAT.x, THREAT.y + 12);
      }

      sweepAngle += SPEED;
      if (sweepAngle > Math.PI * 2) sweepAngle -= Math.PI * 2;
      rafId = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <div style={{ width: '100%', height: '100%', borderRadius: 10, overflow: "hidden", position: 'relative' }}>
       <div style={{position: 'absolute', top: '15px', left: '15px', color: '#e2e8f0', fontSize: '14px', fontWeight: 'bold', zIndex: 10}}>⬩⬩ LIVE NETWORK TOPOLOGY</div>
      <canvas ref={canvasRef} width={680} height={480} style={{ width: "100%", height: "100%", objectFit: "contain", display: "block" }} />
    </div>
  );
}
// ... (Keep the ScadaTopology component exactly as it is above this) ...

// ==========================================
// MAIN APP COMPONENT
// ==========================================
function App() {
  // We rename 'kpis' to 'statusData' to match our new API logic
  const [statusData, setStatusData] = useState(null); 
  const [alerts, setAlerts] = useState([]);
  const [devices, setDevices] = useState([]);
  const [incidentData, setIncidentData] = useState(null);
  
  const [isUnderAttack, setIsUnderAttack] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard'); 

  // Polling logic to keep data fresh
  useEffect(() => {
    const fetchData = async () => {
      const statusRes = await apiClient.getStatus();
      if (statusRes) {
        setStatusData(statusRes);
        // Ensure UI state matches backend state
        if (statusRes.is_under_attack !== isUnderAttack) {
             setIsUnderAttack(statusRes.is_under_attack);
        }
      }
      
      const alertsRes = await apiClient.getAlerts();
      if (alertsRes) setAlerts(alertsRes);

      const devicesRes = await apiClient.getDevices();
      if (devicesRes) setDevices(devicesRes);

      const incidentRes = await apiClient.getIncidentDetails();
      if (incidentRes) setIncidentData(incidentRes);
    };

    // Initial fetch
    fetchData();

    // Poll every 3 seconds to keep UI synced with backend
    const interval = setInterval(fetchData, 3000);

    // Setup Live WebSocket
    // apiClient.connectWebSocket((newAlert) => {
    //   setAlerts((prevAlerts) => [newAlert, ...prevAlerts]);
    //   if (newAlert.severity === 'CRITICAL') {
    //      setIsUnderAttack(true);
    //      // Force an immediate fetch to update all numbers immediately on attack
    //      fetchData(); 
    //   }
    // });
    // Setup Live WebSocket
    apiClient.connectWebSocket((newAlert) => {
      setAlerts((prevAlerts) => [newAlert, ...prevAlerts]);
      
      // 🔥 FIX: Ab kisi bhi severe attack (CRITICAL, HIGH, ya MEDIUM) par dashboard RED hoga aur ML Data update hoga!
      if (newAlert.severity === 'CRITICAL' || newAlert.severity === 'HIGH' || newAlert.severity === 'MEDIUM') {
         setIsUnderAttack(true);
         // Force an immediate fetch to update ML Anomaly numbers immediately
         fetchData(); 
      }
    });

    return () => clearInterval(interval);
  }, []);

  // Show loading screen while waiting for the first backend response
  if (!statusData) return <div className="loading-screen">INITIALIZING SECURE BLUE PROTOCOL...</div>;

  const criticalAlertsCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const calmEqualizer =   [1,2,3,2,4,3,2,1,2,3,4,3,2,1,2,3,2,1,1,1]; 
  const attackEqualizer = [2,2,3,4,6,8,12,18,28,35,35,30,22,14,10,10,10,8,6,4];
  const activeEqualizer = isUnderAttack ? attackEqualizer : calmEqualizer;

  return (
    <div className="app-wrapper">
      
      {/* ================= SIDEBAR ================= */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="logo-shield text-cyan">🛡️</span>
          <h2>SENTINEL <span className="text-cyan">OS</span></h2>
        </div>
        
        <ul className="sidebar-menu">
          <li className={activeTab === 'dashboard' ? 'active' : ''} onClick={() => setActiveTab('dashboard')}>
             📊 Dashboard
          </li>
          <li className={activeTab === 'discovery' ? 'active' : ''} onClick={() => setActiveTab('discovery')}>
             🕸️ Discovery
          </li>
          <li className={activeTab === 'alert_feed' ? 'active' : ''} onClick={() => setActiveTab('alert_feed')}>
             ⚡ Alert Feed
          </li>
          <li className={activeTab === 'device_registry' ? 'active' : ''} onClick={() => setActiveTab('device_registry')}>
             🗄️ Device Registry
          </li>
          <li className={activeTab === 'incident_response' ? 'active' : ''} onClick={() => setActiveTab('incident_response')}>
             🚨 Incident Response
          </li>
          <li className={activeTab === 'ml_engine' ? 'active' : ''} onClick={() => setActiveTab('ml_engine')}>
             🤖 ML Anomaly Engine
          </li>
        </ul>
        
        <div className="sidebar-footer">
          <div className={`status-badge ${isUnderAttack ? 'border-flash text-red' : 'border-cyan text-cyan'}`}>
             <span className={`dot ${isUnderAttack ? 'bg-red' : 'pulse-cyan'}`}></span> 
             {isUnderAttack ? 'COMPROMISED' : 'SECURE'}
          </div>
        </div>
      </aside>

      {/* ================= MAIN CONTENT ================= */}
      <main className="main-content">
        <header className="top-header">
          <h2>{activeTab.replace('_', ' ').toUpperCase()}</h2>
          <div className="header-right">
            <span>Factory: TN Automotive Cluster</span>
            <span className="live-mon">⏱ Live Monitoring</span>
            <span className="user-icon">👤</span>
          </div>
        </header>

        {/* --- TAB 1: DASHBOARD --- */}
        {activeTab === 'dashboard' && (
          <div className="master-grid">
            
            {/* ROW 1: KPIs */}
            <div className="card kpi-card bg-grad-cyan pos-kpi1">
              <div className="kpi-top"><span className="kpi-icon text-cyan">🤖</span><span className="kpi-title">Machines Online</span></div>
              <div className="kpi-value text-white">{statusData.devices_online}</div>
            </div>
            <div className={`card kpi-card ${isUnderAttack ? 'bg-grad-red border-flash' : 'bg-grad-cyan'} pos-kpi2`}>
              <div className="kpi-top"><span className={`kpi-icon ${isUnderAttack ? 'alert-bg text-red' : 'text-cyan'}`}>{isUnderAttack ? '🚨' : '✅'}</span><span className="kpi-title">Network Status</span></div>
              <div className={`kpi-value ${isUnderAttack ? 'text-red' : 'text-cyan'}`}>{isUnderAttack ? 'DANGER' : 'SAFE'}</div>
            </div>
            <div className={`card kpi-card ${isUnderAttack ? 'bg-grad-red border-flash' : 'bg-grad-cyan'} pos-kpi3`}>
              <div className="kpi-top"><span className={`kpi-icon ${isUnderAttack ? 'alert-bg text-red' : 'text-cyan'}`}>⚠️</span><span className="kpi-title">Active Alerts:</span></div>
              <div className={`kpi-value ${isUnderAttack ? 'text-red' : 'text-cyan'}`}>{statusData.critical_alerts}</div>
            </div>

            {/* ROW 2: CHARTS */}
            <div className="card traffic-card pos-traffic">
              <div className="card-title">Network Traffic <span className="subtitle">(Live Feed)</span></div>
              <div className="traffic-content">
                <div className="traffic-chart-wrapper">
                  <div className="y-axis"><span>15k</span><span>12k</span><span>9k</span><span>6k</span><span>3k</span><span>0</span></div>
                  <div className="traffic-graph-area overflow-hidden">
                    <div className="bg-grid-lines"><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div></div>
                    <svg className="animated-wave" viewBox="0 0 800 120" preserveAspectRatio="none">
                      <defs>
                        <linearGradient id="waveFade" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={isUnderAttack ? "#ef4444" : "#00d2ff"} stopOpacity="0.3" />
                          <stop offset="100%" stopColor={isUnderAttack ? "#ef4444" : "#00d2ff"} stopOpacity="0" />
                        </linearGradient>
                      </defs>
                      <path d="M 0 80 Q 50 30, 100 80 T 200 80 T 300 80 T 400 80 T 500 80 T 600 80 T 700 80 T 800 80 L 800 120 L 0 120 Z" fill="url(#waveFade)" />
                      <path d="M 0 80 Q 50 30, 100 80 T 200 80 T 300 80 T 400 80 T 500 80 T 600 80 T 700 80 T 800 80" fill="none" stroke={isUnderAttack ? "#ef4444" : "#00d2ff"} strokeWidth="2" />
                      <path d="M 0 100 Q 50 120, 100 100 T 200 100 T 300 100 T 400 100 T 500 100 T 600 100 T 700 100 T 800 100" fill="none" stroke={isUnderAttack ? "#facc15" : "#0055ff"} strokeWidth="1.5" />
                    </svg>
                  </div>
                </div>
                <div className="traffic-donut-wrapper">
                  <div className="donut-outer-ring border-cyan"></div>
                  <div className="traffic-donut" style={{background: `conic-gradient(${isUnderAttack ? '#ef4444' : '#00d2ff'} 0% 75%, var(--card-border) 75%)`}}>
                     <div className="donut-inner">
                        <span className="d-num text-white" style={{fontSize: '14px'}}>{statusData.packets_per_second}</span>
                        <span className="d-text">Packets/Sec</span>
                     </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="card risk-card pos-risk">
              <div className="card-title">High Risk Areas</div>
              <div className="risk-chart-wrapper">
                 <div className="risk-chart-inner">
                   <div className="y-axis"><span>400</span><span>300</span><span>200</span><span>100</span></div>
                   <div className="bar-chart-area">
                      <div className="bg-grid-lines"><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div></div>
                      <div className="bars-container">
                        <div className="bar-col"><div className="bar bg-cyan" style={{height:'30%'}}></div></div>
                        <div className="bar-col"><div className="bar bg-blue" style={{height:'50%'}}></div></div>
                        <div className="bar-col"><div className={`bar ${isUnderAttack ? 'bg-red border-flash' : 'bg-red'}`} style={{height: isUnderAttack ? '95%' : '80%'}}></div></div>
                      </div>
                   </div>
                 </div>
                 <div className="x-labels-container"><span className="x-label">Zone A</span><span className="x-label">Zone B</span><span className="x-label">Zone C</span></div>
              </div>
            </div>

            {/* ROW 3 & 4: CANVAS LIVE TOPOLOGY */}
            <div className="card pos-topo" style={{ padding: 0, overflow: 'hidden' }}>
              <ScadaTopology isUnderAttack={isUnderAttack} />
            </div>

            {/* --- RIGHT SIDE PANELS --- */}
            <div className="card right-card pos-ai">
              <div className="panel-header">
                <div className="card-title"><span className="kpi-icon text-cyan">🤖</span> AI Threat Detection</div>
                <span className="dots-menu">•••</span>
              </div>
              <div className="panel-body">
                <div className="ai-row"><span className="ai-label">Model Status:</span> <span className="ai-val text-white">{statusData.baseline_status}</span></div>
                <div className="ai-row"><span className="ai-label">Predicted Threat:</span> <span className="ai-val text-white">{statusData.active_threat}</span></div>
                <div className="confidence-area">
                  <div className="conf-text"><span>Confidence: <span className="text-white">{statusData.ml_confidence}%</span></span></div>
                  <div className="progress-bg"><div className={`progress-fill ${isUnderAttack ? 'grad-red-bar' : 'bg-cyan'}`} style={{width: `${statusData.ml_confidence}%`}}><span className="prog-label">HIGH</span></div></div>
                </div>
                <div className={`risk-level ${isUnderAttack ? 'text-red' : 'text-cyan'}`}><span className="risk-bars">|||</span> Risk Level: <span className="risk-badge" style={{color: isUnderAttack ? '#ef4444' : '#00d2ff', borderColor: isUnderAttack ? '#ef4444' : '#00d2ff', background: 'transparent'}}>{isUnderAttack ? 'HIGH' : 'LOW'}</span></div>
              </div>
            </div>

            <div className="card right-card pos-alerts-mid">
              <div className="panel-header">
                <div className="card-title"><span className="icon-plus">⊞</span> Active Alerts</div>
                <button className="view-btn">View All {'>'}</button>
              </div>
              <div className="panel-body flex-row-center">
                 <div className="eq-info">
                   <div className="eq-dev-line"><span className="eq-label">System State:</span> <span className="eq-val text-white">{isUnderAttack ? 'Compromised' : 'Monitoring'}</span></div>
                   <div className="eq-desc">{isUnderAttack ? <span className="text-red">Unauthorized<br/>Command Injection</span> : <>Baseline Traffic<br/>Normal</>}</div>
                 </div>
                 <div className="eq-visual-area">
                   <div className="eq-bars-container">
                     {activeEqualizer.map((h, i) => {
                        let colorClass = 'bg-eq-cyan'; let glowClass = '';
                        if (isUnderAttack) {
                          if (i >= 8 && i <= 10) { colorClass = 'bg-eq-red'; glowClass = 'glow-red'; }
                          else if (i > 10) colorClass = 'bg-eq-darkred'; 
                          else if (i === 7) colorClass = 'bg-eq-orange'; 
                        }
                        return <div key={i} className={`eq-bar ${colorClass} ${glowClass}`} style={{height: `${h}px`}}></div>;
                     })}
                   </div>
                   <div className="eq-axis">
                     <span>10 AM</span><span>11 AM</span><span>12 AM</span><span>12 AM</span><span>2 PM</span><span>4 PM</span><span>5 PM</span><span>6 AM</span>
                   </div>
                 </div>
              </div>
            </div>

            <div className="card right-card pos-timeline">
              <div className="panel-header">
                <div className="card-title">Attack Timeline <span className="subtitle">(Last 24 Hours)</span></div>
                <button className="view-btn">View All {'>'}</button>
              </div>
              <div className="table-responsive">
                <table className="pro-table">
                  <thead><tr><th>Device</th><th>Attack Type</th><th>Severity</th><th>Time</th></tr></thead>
                  <tbody>
                    {alerts.length > 0 ? alerts.slice(0, 3).map((alert, idx) => (
                      <tr key={idx} className={idx === 0 && isUnderAttack ? "flash-bg" : ""}>
                        <td><span className={`status-dot ${alert.severity === 'CRITICAL' ? 'bg-red' : alert.severity === 'HIGH' ? 'bg-red' : alert.severity === 'MEDIUM' ? 'bg-yellow' : 'bg-cyan'}`}></span> <span className="text-white font-bold">{alert.destination_ip}</span></td>
                        <td className="text-dim">{alert.title.substring(0, 25)}</td>
                        <td><span className={`solid-pill ${alert.severity.toLowerCase()}`}>{alert.severity}</span></td>
                        <td className="text-dim">{new Date(alert.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                      </tr>
                    )) : (
                      <>
                        <tr><td colSpan="4" style={{textAlign: "center", color: "#00d2ff", padding: "20px"}}>No Critical Threats Detected</td></tr>
                      </>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* --- TAB 2: DISCOVERY --- */}
        {activeTab === 'discovery' && (
          <div className="tab-grid discovery-grid">
             <div className="card topo-card span-full" style={{ padding: 0, height: '60vh' }}>
                <ScadaTopology isUnderAttack={isUnderAttack} />
             </div>
             <div className="card bg-grad-cyan">
               <div className="card-title">Discovered Protocols</div>
               <p className="text-dim mt-2">Modbus TCP: 4 Devices<br/>DNP3: 1 Device<br/>Profinet: 1 Device</p>
             </div>
             <div className="card bg-grad-cyan">
               <div className="card-title">Shadow IT Scanner</div>
               <p className="text-dim mt-2">{isUnderAttack ? <span className="text-red">Unauthorized Device Detected ({devices.find(d=>d.type==="Threat")?.ip})</span> : 'No unauthorized devices detected in OT network.'}</p>
             </div>
          </div>
        )}

        {/* --- TAB 3: ALERT FEED --- */}
        {activeTab === 'alert_feed' && (
          <div className="tab-grid alert-feed-grid">
             <div className="card traffic-card span-full">
              <div className="card-title">Network Traffic Graph</div>
              <div className="traffic-content" style={{height: '200px'}}>
                <div className="traffic-chart-wrapper">
                  <div className="y-axis"><span>15k</span><span>12k</span><span>9k</span><span>6k</span><span>3k</span><span>0</span></div>
                  <div className="traffic-graph-area overflow-hidden">
                    <div className="bg-grid-lines"><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div></div>
                    <svg className="animated-wave" viewBox="0 0 800 120" preserveAspectRatio="none">
                      <defs>
                        <linearGradient id="waveFadeLg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={isUnderAttack ? "#ef4444" : "#00d2ff"} stopOpacity="0.4" /><stop offset="100%" stopColor={isUnderAttack ? "#ef4444" : "#00d2ff"} stopOpacity="0" /></linearGradient>
                      </defs>
                      <path d="M 0 80 Q 50 30, 100 80 T 200 80 T 300 80 T 400 80 T 500 80 T 600 80 T 700 80 T 800 80 L 800 120 L 0 120 Z" fill="url(#waveFadeLg)" />
                      <path d="M 0 80 Q 50 30, 100 80 T 200 80 T 300 80 T 400 80 T 500 80 T 600 80 T 700 80 T 800 80" fill="none" stroke={isUnderAttack ? "#ef4444" : "#00d2ff"} strokeWidth="2" />
                    </svg>
                  </div>
                </div>
              </div>
            </div>

            <div className="card alerts-mid-card span-full">
              <div className="card-title">Active Alert Explanation (Frequency)</div>
              <div className="panel-body flex-row-center">
                 <div className="eq-info">
                   <div className="eq-dev-line"><span className="eq-label">Target:</span> <span className="eq-val text-white">{isUnderAttack ? 'PLC-02' : 'System'}</span></div>
                   <div className="eq-desc">{isUnderAttack ? <span className="text-red">Exploit: Modbus FC-05 Write Coil</span> : <>Traffic Normal</>}</div>
                 </div>
                 <div className="eq-visual-area">
                   <div className="eq-bars-container">
                     {activeEqualizer.map((h, i) => {
                        let colorClass = 'bg-eq-cyan'; let glowClass = '';
                        if (isUnderAttack) {
                          if (i >= 8 && i <= 10) { colorClass = 'bg-eq-red'; glowClass = 'glow-red'; }
                          else if (i > 10) colorClass = 'bg-eq-darkred'; 
                          else if (i === 7) colorClass = 'bg-eq-orange'; 
                        }
                        return <div key={i} className={`eq-bar ${colorClass} ${glowClass}`} style={{height: `${h*2}px`}}></div>;
                     })}
                   </div>
                 </div>
              </div>
            </div>
          </div>
        )}

        {/* --- TAB 4: DEVICE REGISTRY --- */}
        {activeTab === 'device_registry' && (
          <div className="card span-full">
             <div className="card-title">Connected Devices</div>
             <table className="pro-table mt-4">
                <thead><tr><th>Device Name</th><th>IP Address</th><th>Protocol</th><th>Status</th></tr></thead>
                <tbody>
                  {devices.map((n, i) => (
                    <tr key={i} className={n.type === "Threat" ? "flash-bg" : ""}>
                      <td className={n.type === "Threat" ? "text-red font-bold" : "text-white"}>{n.type === "Threat" ? '☠️ ' : ''}{n.name}</td>
                      <td className="text-dim">{n.ip}</td>
                      <td className="text-dim">TCP/IP</td>
                      <td><span className={`solid-pill ${n.status === 'ONLINE' ? 'low' : 'critical'}`}>{n.status}</span></td>
                    </tr>
                  ))}
                </tbody>
             </table>
          </div>
        )}

        {/* --- TAB 5: INCIDENT RESPONSE --- */}
        {activeTab === 'incident_response' && (
          <div className="tab-grid incident-grid">
             <div className="card bg-grad-cyan">
               <div className="card-title">Attack Probability</div>
               <h2 className="mt-4 kpi-value" style={{color: isUnderAttack ? '#ef4444' : '#00d2ff'}}>{isUnderAttack ? '98.5%' : '2.1%'}</h2>
               <p className="text-dim mt-2">Chances of successful exploitation based on current traffic.</p>
             </div>
             <div className="card bg-grad-cyan">
               <div className="card-title">Network Channel Info</div>
               <div className="mt-4 text-white">
                 <p className="mb-2">Protocol: <span className="text-cyan font-bold">{incidentData?.protocol || 'Modbus TCP'}</span></p>
                 <p className="mb-2">Transport: <span className="text-cyan font-bold">{incidentData?.transport || 'TCP'}</span></p>
                 <p className="mb-2">Port: <span className="text-cyan font-bold">{incidentData?.port || '502'}</span></p>
               </div>
             </div>
             <div className="card span-full">
               <div className="card-title">Response Playbook</div>
               <div className="mt-4">
                 {isUnderAttack ? (
                   <ul className="text-red list-disc pl-5">
                     {incidentData?.playbook_steps?.map((step, i) => (
                         <li key={i} className="mb-2">{step}</li>
                     ))}
                   </ul>
                 ) : (
                   <p className="text-cyan">No active playbooks required. System is secure.</p>
                 )}
               </div>
             </div>
          </div>
        )}

        {/* --- TAB 6: ML ANOMALY ENGINE --- */}
        {activeTab === 'ml_engine' && (
           <div className="tab-grid ml-grid">
             <div className="card right-card">
              <div className="panel-header">
                <div className="card-title"><span className="kpi-icon text-cyan">🤖</span> Prevention & Detection</div>
              </div>
              <div className="panel-body">
                <div className="ai-row"><span className="ai-label">Model:</span> <span className="ai-val text-white">Isolation Forest (v2.1)</span></div>
                <div className="ai-row"><span className="ai-label">Predicted Attack:</span> <span className="ai-val text-white">{statusData.active_threat}</span></div>
                <div className="confidence-area">
                  <div className="conf-text"><span>AI Confidence: <span className="text-white">{statusData.ml_confidence}%</span></span></div>
                  <div className="progress-bg"><div className={`progress-fill ${isUnderAttack ? 'grad-red-bar' : 'bg-cyan'}`} style={{width: `${statusData.ml_confidence}%`}}></div></div>
                </div>
                <div className={`risk-level ${isUnderAttack ? 'text-red' : 'text-cyan'}`}>Risk Level: {isUnderAttack ? 'HIGH' : 'LOW'}</div>
              </div>
            </div>

            <div className="card risk-card">
              <div className="card-title">High Risk Areas (Zones)</div>
              <div className="risk-chart-wrapper" style={{height: '200px'}}>
                 <div className="risk-chart-inner">
                   <div className="y-axis"><span>400</span><span>300</span><span>200</span><span>100</span></div>
                   <div className="bar-chart-area">
                      <div className="bg-grid-lines"><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div><div className="h-line"></div></div>
                      <div className="bars-container">
                        <div className="bar-col"><div className="bar bg-cyan" style={{height:'30%'}}></div></div>
                        <div className="bar-col"><div className="bar bg-blue" style={{height:'50%'}}></div></div>
                        <div className="bar-col"><div className={`bar ${isUnderAttack ? 'bg-red border-flash' : 'bg-red'}`} style={{height: isUnderAttack ? '95%' : '80%'}}></div></div>
                      </div>
                   </div>
                 </div>
                 <div className="x-labels-container"><span className="x-label">Zone A</span><span className="x-label">Zone B</span><span className="x-label">Zone C (Threat)</span></div>
              </div>
            </div>
           </div>
        )}

      </main>
    </div>
  );
}

export default App;