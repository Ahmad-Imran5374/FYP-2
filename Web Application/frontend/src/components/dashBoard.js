import React, { useEffect, useState } from "react";
import axios from "axios";
import io from "socket.io-client";
import "./dashBoard.css";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:5000";
const socket = io(API_BASE, { transports: ["websocket"] });

function Dashboard() {
  const [user, setUser]         = useState(null);
  const [activeOption, setActiveOption] = useState("Scan IoT Devices");
  const [sidebarVisible, setSidebarVisible] = useState(true);

  const [isScanning, setIsScanning] = useState(false);
  const [packets, setPackets]       = useState([]);
  const [error, setError]           = useState("");

  useEffect(() => {
    // Fetch user profile
    axios.get("/dashboard", {
      baseURL: API_BASE,
      headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
    })
    .then(res => setUser(res.data))
    .catch(() => window.location.href = "/login");

    // Listen for incoming packets
    socket.on("new-packet", pkt => {
      setPackets(prev => [pkt, ...prev].slice(0, 200));
    });
    return () => socket.off("new-packet");
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  const handleScanToggle = async () => {
    setError("");
    try {
      const url = isScanning ? "/stop-scan" : "/start-scan";
      await axios.post(url, {}, {
        baseURL: API_BASE,
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
      });
      setIsScanning(v => !v);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    }
  };

  const renderScanView = () => (
    <div className="scan-view">
      <h3>Scan IoT Devices</h3>
      <button className={`scan-button ${isScanning ? "stop" : "start"}`}
              onClick={handleScanToggle}>
        {isScanning ? "Stop Scan" : "Scan Now"}
      </button>
      {error && <p className="error-text">Error: {error}</p>}

      <div className="packet-container">
        <table className="packet-table">
          <thead>
            <tr>
              <th>Src IP</th>
              <th>Src Port</th>
              <th>Dst IP</th>
              <th>Dst Port</th>
              <th>Device</th>
              <th>Label</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((p, i) => (
              <tr key={i}>
                <td>{p.src_ip}</td>
                <td>{p.src_port}</td>
                <td>{p.dst_ip}</td>
                <td>{p.dst_port}</td>
                <td>{p.device_type}</td>
                <td className={p.attack_label === 1 ? "malicious" : "normal"}>
                  {p.attack_label === 1 ? "Malicious" : "Normal"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  if (!user) {
    return <div className="loading">Loading user data…</div>;
  }

  return (
    <div className="dashboard-container">
      <aside className={`sidebar ${sidebarVisible ? "visible" : "hidden"}`}>
        <h3>Dashboard</h3>
        <ul>
          {[
            "Scan IoT Devices",
            "Block IoT Devices",
            "Unblock IoT Devices",
            "Alerts",
            "Activity Log",
            "Detailed IoT Device Info",
          ].map(opt => (
            <li key={opt}
                className={activeOption === opt ? "active" : ""}
                onClick={() => setActiveOption(opt)}>
              {opt}
            </li>
          ))}
        </ul>
      </aside>

      <main className="main-content">
        <header className="top-bar">
          <button onClick={() => setSidebarVisible(v => !v)}
                  className="sidebar-toggle">☰</button>
          <div className="user-block">
            <span>Welcome, {user.email.split("@")[0]}!</span>
            <button onClick={handleLogout} className="logout-button">
              Logout
            </button>
          </div>
        </header>

        <section className="content">
          {activeOption === "Scan IoT Devices"
            ? renderScanView()
            : <div className="center-content">Select an option</div>
          }
        </section>
      </main>
    </div>
  );
}

export default Dashboard;
