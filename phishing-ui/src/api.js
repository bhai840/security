// src/api.js
import axios from "axios";
import { withApiSpan } from "./telemetry";

const API = axios.create({
  baseURL: process.env.REACT_APP_API_BASE_URL || "/api",
});

export const scanInbox = () =>
  withApiSpan("phishing-ui.scan_inbox", (headers) =>
    API.post("/scan", null, { headers })
  );

export const getIncidents = () =>
  withApiSpan("phishing-ui.get_incidents", (headers) =>
    API.get("/incidents", { headers })
  );
