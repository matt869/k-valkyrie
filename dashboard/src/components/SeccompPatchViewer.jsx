import React, { useState } from 'react';

export default function SeccompPatchViewer({ patchData, onApplyPatch, onDismiss }) {
  const [activeTab, setActiveTab] = useState('seccomp');

  if (!patchData) {
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
        No pending LLM remediation patches generated.
      </div>
    );
  }

  const {
    incident_classification = {},
    kernel_enforcement_decision = {},
    seccomp_bpf_patch = {},
    ebpf_lsm_rule_c = '',
  } = patchData;

  return (
    <div style={{
      background: '#0f172a',
      border: '1px solid #1e293b',
      borderRadius: 8,
      padding: 16,
      color: '#f8fafc',
      fontFamily: 'system-ui, sans-serif'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 15, color: '#a855f7' }}>
            LLM Autonomous Patch: {incident_classification.attack_type || 'FILELESS_ATTACK'}
          </h3>
          <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
            MITRE: {(incident_classification.mitre_techniques || []).join(', ')} | Confidence: {((incident_classification.confidence || 0) * 100).toFixed(0)}%
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => onApplyPatch && onApplyPatch(patchData)}
            style={{
              background: '#9333ea',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Apply Hot-Patch
          </button>
          <button
            onClick={() => onDismiss && onDismiss()}
            style={{
              background: 'transparent',
              border: '1px solid #475569',
              color: '#cbd5e1',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 12,
              cursor: 'pointer'
            }}
          >
            Dismiss
          </button>
        </div>
      </div>

      <div style={{ fontSize: 12, color: '#cbd5e1', marginBottom: 12, background: '#1e293b', padding: 8, borderRadius: 4 }}>
        <strong>Root Cause:</strong> {incident_classification.root_cause_summary}
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <button
          onClick={() => setActiveTab('seccomp')}
          style={{
            background: activeTab === 'seccomp' ? '#334155' : 'transparent',
            color: activeTab === 'seccomp' ? '#38bdf8' : '#94a3b8',
            border: 'none',
            borderRadius: 4,
            padding: '4px 10px',
            fontSize: 12,
            cursor: 'pointer'
          }}
        >
          Seccomp-BPF JSON
        </button>
        <button
          onClick={() => setActiveTab('lsm')}
          style={{
            background: activeTab === 'lsm' ? '#334155' : 'transparent',
            color: activeTab === 'lsm' ? '#a855f7' : '#94a3b8',
            border: 'none',
            borderRadius: 4,
            padding: '4px 10px',
            fontSize: 12,
            cursor: 'pointer'
          }}
        >
          eBPF LSM C Rule
        </button>
      </div>

      <div style={{
        background: '#090d16',
        borderRadius: 4,
        padding: 10,
        fontFamily: 'monospace',
        fontSize: 11,
        maxHeight: 180,
        overflowY: 'auto',
        color: '#e2e8f0',
        whiteSpace: 'pre-wrap'
      }}>
        {activeTab === 'seccomp'
          ? JSON.stringify(seccomp_bpf_patch, null, 2)
          : ebpf_lsm_rule_c}
      </div>
    </div>
  );
}
