import React, { useEffect, useState } from "react";
import axios from "axios";
import "./dashBoard.css";

function Dashboard() {
  const [user, setUser] = useState(null);
  const [activeOption, setActiveOption] = useState("Scan IoT Devices");
  const [sidebarVisible, setSidebarVisible] = useState(true);

  useEffect(() => {
    // Fetch user data from the backend
    const fetchUserData = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await axios.get("http://localhost:5000/dashboard", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUser(response.data);
      } catch (error) {
        alert(error.response?.data?.error || "Failed to load user data.");
        window.location.href = "/login"; // Redirect to login if not authenticated
      }
    };

    fetchUserData();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  const renderContent = () => {
    switch (activeOption) {
      case "Scan IoT Devices":
        return (
          <div className="center-content">
            <h3>Scan IoT Devices</h3>
            <button className="scan-now-button">Scan Now</button>
          </div>
        );
      case "Block IoT Devices":
        return (
          <div className="center-content">
            <h3>Block IoT Devices</h3>
          </div>
        );
      case "Unblock IoT Devices":
        return (
          <div className="center-content">
            <h3>Unblock IoT Devices</h3>
          </div>
        );
      case "Alerts":
        return (
          <div className="center-content">
            <h3>Alerts</h3>
          </div>
        );
      case "Activity Log":
        return (
          <div className="center-content">
            <h3>Activity Log</h3>
          </div>
        );
      case "Detailed IoT Device Info":
        return (
          <div className="center-content">
            <h3>Detailed IoT Device Info</h3>
          </div>
        );
      default:
        return <div className="center-content">Select an option</div>;
    }
  };

  return (
    <div className="dashboard-container">
      <div className={`sidebar ${sidebarVisible ? "visible" : "hidden"}`}>
        <h3>Dashboard</h3>
        <ul>
          <li
            className={activeOption === "Scan IoT Devices" ? "active" : ""}
            onClick={() => setActiveOption("Scan IoT Devices")}
          >
            Scan IoT Devices
          </li>
          <li
            className={activeOption === "Block IoT Devices" ? "active" : ""}
            onClick={() => setActiveOption("Block IoT Devices")}
          >
            Block IoT Devices
          </li>
          <li
            className={activeOption === "Unblock IoT Devices" ? "active" : ""}
            onClick={() => setActiveOption("Unblock IoT Devices")}
          >
            Unblock IoT Devices
          </li>
          <li
            className={activeOption === "Alerts" ? "active" : ""}
            onClick={() => setActiveOption("Alerts")}
          >
            Alerts
          </li>
          <li
            className={activeOption === "Activity Log" ? "active" : ""}
            onClick={() => setActiveOption("Activity Log")}
          >
            Activity Log
          </li>
          <li
            className={activeOption === "Detailed IoT Device Info" ? "active" : ""}
            onClick={() => setActiveOption("Detailed IoT Device Info")}
          >
            Detailed IoT Device Info
          </li>
        </ul>
      </div>
      <div className="main-content">
        <header>
          <button
            className="sidebar-toggle"
            onClick={() => setSidebarVisible(!sidebarVisible)}
          >
            ☰
          </button>
          {user ? (
            <div>
              {/* Extract username before the "@" symbol */}
              <h2>Welcome, {user.email.split("@")[0]}!</h2>
              <button onClick={handleLogout} className="logout-button">
                Logout
              </button>
            </div>
          ) : (
            <p>Loading user data...</p>
          )}
        </header>
        {renderContent()}
      </div>
    </div>
  );
}

export default Dashboard;
