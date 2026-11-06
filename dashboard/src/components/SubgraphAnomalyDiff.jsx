import React from 'react';

export default function SubgraphAnomalyDiff({ anomalyData }) {
  if (!anomalyData) {
    return (
      <div style={{
        background: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: 8,
        padding: 16,
        color: '#64748b',
        fontSize: 13,
        fontFamily: 'monospace'
      }}>
        Waiting for anomalous causal transitions from GNN inference engine...
      </div>
    );
  }

  const {
    max_edge_anomaly_score = 0,
    subgraph_nodes_count = 0,
    subgraph_edges_count = 0,
    top_anomalous_edges = [],
    trigger_node = '',
  } = anomalyData;

  return (
    <div style={{
      background: '#0f172a',
      border: '1px solid #1e293b',
      borderRadius: 8,
      padding: 16,
      color: '#f8fafc',
      fontFamily: 'system-ui, sans-serif'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 15, color: '#38bdf8' }}>
          GATv2 Causal Attention & Edge Anomaly Scores
        </h3>
        <span style={{
          background: max_edge_anomaly_score > 0.65 ? '#dc2626' : '#16a34a',
          padding: '2px 8px',
          borderRadius: 4,
          fontSize: 11,
          fontWeight: 700
        }}>
          PEAK ANOMALY: {max_edge_anomaly_score.toFixed(4)}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 16, fontSize: 12, color: '#94a3b8', marginBottom: 12 }}>
        <div>Trigger: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{trigger_node}</span></div>
        <div>Neighborhood: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{subgraph_nodes_count} nodes, {subgraph_edges_count} edges</span></div>
      </div>

      <div style={{ maxHeight: 220, overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'monospace' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8', textAlign: 'left' }}>
              <th style={{ padding: '6px 4px' }}>Causal Path</th>
              <th style={{ padding: '6px 4px' }}>Syscall</th>
              <th style={{ padding: '6px 4px' }}>GAT Attention</th>
              <th style={{ padding: '6px 4px' }}>Anomaly Score</th>
            </tr>
          </thead>
          <tbody>
            {top_anomalous_edges.map((e, idx) => {
              const isHigh = e.anomaly_score > 0.65;
              return (
                <tr
                  key={idx}
                  style={{
                    borderBottom: '1px solid #1e293b',
                    background: isHigh ? 'rgba(220, 38, 38, 0.1)' : 'transparent',
                  }}
                >
                  <td style={{ padding: '6px 4px', color: '#cbd5e1' }}>
                    {e.src} &rarr; {e.dst}
                  </td>
                  <td style={{ padding: '6px 4px', color: '#38bdf8' }}>
                    {e.syscall}
                  </td>
                  <td style={{ padding: '6px 4px', color: '#f59e0b' }}>
                    {(e.gat_attention_weight || 0).toFixed(4)}
                  </td>
                  <td style={{ padding: '6px 4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{
                        width: 48,
                        height: 6,
                        background: '#334155',
                        borderRadius: 3,
                        overflow: 'hidden'
                      }}>
                        <div style={{
                          width: `${Math.min(e.anomaly_score * 100, 100)}%`,
                          height: '100%',
                          background: isHigh ? '#ef4444' : '#10b981'
                        }} />
                      </div>
                      <span style={{ color: isHigh ? '#ef4444' : '#94a3b8' }}>
                        {(e.anomaly_score || 0).toFixed(4)}
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
