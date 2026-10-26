// src/IncidentTable.js
import React, { useState } from "react";
import HeaderDetails from "./HeaderDetails";

function IncidentTable({ incidents }) {
  const [expandedId, setExpandedId] = useState(null);

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div style={{ marginTop: "2rem" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#ddd" }}>
            <th style={{ padding: "8px" }}>Subject</th>
            <th style={{ padding: "8px" }}>From</th>
            <th style={{ padding: "8px" }}>Classification</th>
            <th style={{ padding: "8px" }}>Reason</th>
            <th style={{ padding: "8px" }}>Headers</th>
          </tr>
        </thead>

        <tbody>
          {incidents.map((i) => (
            <>
              <tr key={i.id} style={{ borderBottom: "1px solid #ccc" }}>
                <td style={{ padding: "8px" }}>{i.subject}</td>
                <td style={{ padding: "8px" }}>{i.from}</td>
                <td style={{ padding: "8px" }}>{i.classification}</td>
                <td style={{ padding: "8px" }}>{i.reason}</td>
                <td style={{ padding: "8px" }}>
                  <button
                    onClick={() => toggleExpand(i.id)}
                    style={{
                      padding: "6px 10px",
                      borderRadius: "6px",
                      border: "none",
                      background: "#007bff",
                      color: "white",
                      cursor: "pointer"
                    }}
                  >
                    {expandedId === i.id ? "Hide" : "View"}
                  </button>
                </td>
              </tr>

              {expandedId === i.id && (
                <tr>
                  <td colSpan="5">
                    <HeaderDetails header={i.header_findings} />
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default IncidentTable;
