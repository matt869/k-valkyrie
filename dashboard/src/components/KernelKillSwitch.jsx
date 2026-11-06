import React, { useState } from 'react';

export default function KernelKillSwitch({
  quarantinedPids,
  quarantineList,
  onQuarantine,
  onRelease,
  onQuarantineUpdate,
}) {
  const activeList = quarantineList || quarantinedPids || [];
  const [targetPid, setTargetPid] = useState('');
  const [autoQuarantine, setAutoQuarantine] = useState(true);

  const handleFreeze = (e) => {
    e.preventDefault();
    const pid = parseInt(targetPid, 10);
    if (!isNaN(pid) && pid > 0) {
      if (onQuarantine) onQuarantine(pid, 2);
      if (onQuarantineUpdate) onQuarantineUpdate([...activeList, pid]);
      setTargetPid('');
    }
  };

  return (
    <div style={{
      background: '#0f172a',
      border: '1px solid #1e293b',
      borderRadius: '8px',
      padding: '16px',
      color: '#f8fafc',
      fontFamily: 'system-ui, sans-serif'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: '15px', color: '#f43f5e', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} />
          Kernel Kill-Switch & LSM Quarantine
        </h3>
        <label style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={autoQuarantine}
            onChange={(e) => setAutoQuarantine(e.target.checked)}
          />
          Auto-Freeze (GATv2 &gt; 0.65)
        </label>
      </div>

      <form onSubmit={handleFreeze} style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input
          type="number"
          placeholder="Target Process PID"
          value={targetPid}
          onChange={(e) => setTargetPid(e.target.value)}
          style={{
            flex: 1,
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: 4,
            padding: '6px 10px',
            color: '#fff',
            fontSize: '13px',
          }}
        />
        <button
          type="submit"
          style={{
            background: '#e11d48',
            color: '#fff',
            border: 'none',
            borderRadius: 4,
            padding: '6px 14px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Freeze Subtree (SIGSTOP)
        </button>
      </form>

      <div>
        <div style={{ fontSize: '12px', color: '#94a3b8', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Active Ring-0 Quarantined Processes ({activeList.length})
        </div>
        {activeList.length === 0 ? (
          <div style={{ fontSize: '13px', color: '#64748b', fontStyle: 'italic', padding: '8px 0' }}>
            No process trees currently quarantined.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: '160px', overflowY: 'auto' }}>
            {activeList.map((item) => {
              const pid = typeof item === 'object' ? item.pid : item;
              const action = typeof item === 'object' ? item.action : 'SIGSTOP';
              return (
                <div
                  key={pid}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    background: '#1e1b4b',
                    border: '1px solid #3730a3',
                    padding: '6px 10px',
                    borderRadius: 4,
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                >
                  <div>
                    <span style={{ color: '#ec4899', fontWeight: 'bold' }}>PID {pid}</span>
                    <span style={{ color: '#94a3b8', marginLeft: 8 }}>Action: {action}</span>
                  </div>
                  <button
                    onClick={() => onRelease && onRelease(pid)}
                    style={{
                      background: 'transparent',
                      border: '1px solid #475569',
                      color: '#cbd5e1',
                      borderRadius: 3,
                      padding: '2px 8px',
                      fontSize: '11px',
                      cursor: 'pointer',
                    }}
                  >
                    Release
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
