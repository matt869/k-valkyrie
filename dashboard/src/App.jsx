import React, { useState, useEffect, useCallback } from "react";
import LiveProvenanceGraph from "./components/LiveProvenanceGraph";
import KernelKillSwitch from "./components/KernelKillSwitch";
import SubgraphAnomalyDiff from "./components/SubgraphAnomalyDiff";
import SeccompPatchViewer from "./components/SeccompPatchViewer";
import { createWebSocketStream } from "./services/websocket_stream";

/* ─── Theme tokens ──────────────────────────────────────────────── */
const theme = {
  bg: "#0a0e17",
  surface: "#111827",
  surfaceAlt: "#1a2233",
  border: "#1e293b",
  accent: "#3b82f6",
  accentGlow: "rgba(59, 130, 246, 0.35)",
  danger: "#ef4444",
  warn: "#f59e0b",
  success: "#22c55e",
  text: "#c9d1d9",
  textDim: "#6b7280",
  headerBg: "linear-gradient(90deg, #0f172a 0%, #1e293b 100%)",
};

/* ─── Styles ────────────────────────────────────────────────────── */
const styles = {
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
    width: "100vw",
    background: theme.bg,
    color: theme.text,
    fontFamily:
      '"SF Mono", "Fira Code", "JetBrains Mono", "Cascadia Code", monospace',
    overflow: "hidden",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "12px 24px",
    background: theme.headerBg,
    borderBottom: `1px solid ${theme.border}`,
    flexShrink: 0,
  },
  logoGroup: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },
  logoIcon: {
    width: "32px",
    height: "32px",
    borderRadius: "8px",
    background: `linear-gradient(135deg, ${theme.accent}, #6366f1)`,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "16px",
    fontWeight: "700",
    color: "#fff",
    boxShadow: `0 0 12px ${theme.accentGlow}`,
  },
  title: {
    fontSize: "16px",
    fontWeight: "700",
    color: "#e2e8f0",
    letterSpacing: "0.5px",
  },
  subtitle: {
    fontSize: "11px",
    color: theme.textDim,
    letterSpacing: "1px",
    textTransform: "uppercase",
  },
  statusBar: {
    display: "flex",
    alignItems: "center",
    gap: "16px",
  },
  statusDot: (color) => ({
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    background: color,
    boxShadow: `0 0 6px ${color}`,
  }),
  statusLabel: {
    fontSize: "11px",
    color: theme.textDim,
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gridTemplateRows: "1fr 1fr",
    gap: "1px",
    flex: 1,
    background: theme.border,
    overflow: "hidden",
  },
  panel: {
    background: theme.surface,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
  },
};

/* ─── App ───────────────────────────────────────────────────────── */
export default function App() {
  const [ws, setWs] = useState(null);
  const [connectionState, setConnectionState] = useState("CONNECTING");
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [anomalyData, setAnomalyData] = useState({ edges: [], stats: null });
  const [quarantineList, setQuarantineList] = useState([]);
  const [patchData, setPatchData] = useState(null);

  /* WebSocket lifecycle */
  useEffect(() => {
    const stream = createWebSocketStream();

    stream.subscribe("graph_update", (data) => {
      setGraphData(data);
    });

    stream.subscribe("anomaly_alert", (data) => {
      setAnomalyData(data);
    });

    stream.subscribe("quarantine_update", (data) => {
      setQuarantineList(Array.isArray(data.pids) ? data.pids : []);
    });

    stream.subscribe("patch_generated", (data) => {
      setPatchData(data);
    });

    stream.subscribe("connection_state", (data) => {
      setConnectionState(data.state);
    });

    setWs(stream);

    return () => {
      stream.close();
    };
  }, []);

  /* Quarantine action handler */
  const handleQuarantineUpdate = useCallback((updatedList) => {
    setQuarantineList(updatedList);
  }, []);

  /* Patch action handler */
  const handlePatchAction = useCallback(() => {
    setPatchData(null);
  }, []);

  /* Connection state color */
  const stateColor =
    connectionState === "OPEN"
      ? theme.success
      : connectionState === "RECONNECTING"
      ? theme.warn
      : connectionState === "CLOSED"
      ? theme.danger
      : theme.textDim;

  return (
    <div style={styles.root}>
      {/* ── Header ── */}
      <header style={styles.header}>
        <div style={styles.logoGroup}>
          <div style={styles.logoIcon}>K</div>
          <div>
            <div style={styles.title}>K-Valkyrie | Ring-0 Threat Detection</div>
            <div style={styles.subtitle}>
              eBPF Provenance Graph &bull; GATv2 Anomaly Engine &bull; LSM
              Enforcement
            </div>
          </div>
        </div>
        <div style={styles.statusBar}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <div style={styles.statusDot(stateColor)} />
            <span style={styles.statusLabel}>
              WS: {connectionState}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <div
              style={styles.statusDot(
                quarantineList.length > 0 ? theme.danger : theme.success
              )}
            />
            <span style={styles.statusLabel}>
              Quarantined: {quarantineList.length}
            </span>
          </div>
        </div>
      </header>

      {/* ── Dashboard Grid ── */}
      <div style={styles.grid}>
        {/* Top-left: Provenance Graph */}
        <div style={styles.panel}>
          <LiveProvenanceGraph graphData={graphData} />
        </div>

        {/* Top-right: Kill Switch */}
        <div style={styles.panel}>
          <KernelKillSwitch
            quarantineList={quarantineList}
            onQuarantineUpdate={handleQuarantineUpdate}
          />
        </div>

        {/* Bottom-left: Anomaly Diff */}
        <div style={styles.panel}>
          <SubgraphAnomalyDiff anomalyData={anomalyData} />
        </div>

        {/* Bottom-right: Seccomp Patch Viewer */}
        <div style={styles.panel}>
          <SeccompPatchViewer
            patchData={patchData}
            onAction={handlePatchAction}
          />
        </div>
      </div>
    </div>
  );
}
