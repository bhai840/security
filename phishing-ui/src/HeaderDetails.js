// src/HeaderDetails.js
import React from "react";

function HeaderDetails({ header }) {
  if (!header) return null;

  return (
    <div style={{
      background: "#f7f7f7",
      padding: "1rem",
      borderRadius: "8px",
      marginTop: "1rem",
      border: "1px solid #ddd"
    }}>
      <h3>Header Analysis</h3>

      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <tbody>
          <tr>
            <td><strong>SPF</strong></td>
            <td>{header.spf}</td>
          </tr>
          <tr>
            <td><strong>DKIM</strong></td>
            <td>{header.dkim}</td>
          </tr>
          <tr>
            <td><strong>DMARC</strong></td>
            <td>{header.dmarc}</td>
          </tr>
          <tr>
            <td><strong>Spoofing Detected</strong></td>
            <td>{header.spoofing_detected ? "Yes" : "No"}</td>
          </tr>
          <tr>
            <td><strong>Sender Mismatch</strong></td>
            <td>{header.sender_display_vs_envelope_mismatch ? "Yes" : "No"}</td>
          </tr>
          <tr>
            <td><strong>Received Chain Anomaly</strong></td>
            <td>{header.received_chain_anomaly ? "Yes" : "No"}</td>
          </tr>
        </tbody>
      </table>

      <h4 style={{ marginTop: "1rem" }}>Raw Header JSON</h4>
      <pre style={{
        background: "#eee",
        padding: "1rem",
        borderRadius: "6px",
        maxHeight: "300px",
        overflowY: "auto"
      }}>
        {JSON.stringify(header, null, 2)}
      </pre>
    </div>
  );
}

export default HeaderDetails;
