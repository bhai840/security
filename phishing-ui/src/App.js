// src/App.js
import React, { useState, useEffect } from "react";
import { scanInbox, getIncidents } from "./api";
import IncidentTable from "./IncidentTable";

function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState("");

  const loadIncidents = async () => {
    const res = await getIncidents();
    setIncidents(res.data);
  };

  const handleScan = async () => {
    setLoading(true);
    setScanError("");
    try {
      const res = await scanInbox();
      setIncidents(res.data.incidents);
    } catch (error) {
      const status = error.response?.status;
      const detail = error.response?.data?.detail;
      setScanError(
        detail
          ? `Scan failed: ${detail}`
          : status
          ? `Scan failed (HTTP ${status}). Check the backend logs for details.`
          : "Could not reach the backend. Check that the services are running."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial" }}>
      <h1>Phishing Detection + Automated Response</h1>

      <button
        onClick={handleScan}
        disabled={loading}
        style={{
          padding: "10px 20px",
          background: loading ? "#999" : "#28a745",
          color: "white",
          border: "none",
          borderRadius: "6px",
          cursor: "pointer"
        }}
      >
        {loading ? "Scanning..." : "Scan Gmail Inbox"}
      </button>

      <p>
        <a href="/api/auth/google">Connect Gmail</a>
      </p>

      {scanError && <p role="alert">{scanError}</p>}

      <IncidentTable incidents={incidents} />
    </div>
  );
}

export default App;
