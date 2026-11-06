import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';

export default function LiveProvenanceGraph({ graphData, onSelectNode }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selectedNodeData, setSelectedNodeData] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;

    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#f8fafc',
            'font-size': '11px',
            'font-family': 'monospace',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#3b82f6',
            'width': 28,
            'height': 28,
            'border-width': 2,
            'border-color': '#1e293b',
          },
        },
        {
          selector: 'node[type="process"]',
          style: {
            'shape': 'ellipse',
            'background-color': '#38bdf8',
          },
        },
        {
          selector: 'node[type="file"]',
          style: {
            'shape': 'diamond',
            'background-color': '#34d399',
            'width': 24,
            'height': 24,
          },
        },
        {
          selector: 'node[type="memfd"]',
          style: {
            'shape': 'triangle',
            'background-color': '#f43f5e',
            'width': 32,
            'height': 32,
            'border-color': '#ffe4e6',
          },
        },
        {
          selector: 'edge',
          style: {
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': '#64748b',
            'line-color': '#64748b',
            'width': 'mapData(weight, 0, 1, 1.5, 6)',
            'label': 'data(label)',
            'font-size': '9px',
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: 'edge[syscall="memfd_create"]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'width': 4,
          },
        },
        {
          selector: 'edge[syscall="ptrace"]',
          style: {
            'line-color': '#f97316',
            'target-arrow-color': '#f97316',
            'width': 4,
          },
        },
        {
          selector: 'edge[anomalous="true"]',
          style: {
            'line-color': '#dc2626',
            'target-arrow-color': '#dc2626',
            'line-style': 'dashed',
            'width': 5,
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        padding: 40,
        randomize: false,
      },
    });

    cyRef.current.on('tap', 'node', (evt) => {
      const node = evt.target;
      const data = node.data();
      setSelectedNodeData(data);
      if (onSelectNode) onSelectNode(data);
    });

    return () => {
      if (cyRef.current) cyRef.current.destroy();
    };
  }, []);

  // Sync graphData updates into Cytoscape
  useEffect(() => {
    if (!cyRef.current || !graphData) return;

    const cy = cyRef.current;
    cy.batch(() => {
      cy.elements().remove();

      // Add nodes
      (graphData.nodes || []).forEach((n) => {
        cy.add({
          group: 'nodes',
          data: {
            id: n.id,
            label: n.label || n.id,
            type: n.type || 'process',
            pid: n.pid,
            comm: n.comm,
            isQuarantined: n.isQuarantined,
          },
        });
      });

      // Add edges
      (graphData.edges || []).forEach((e, idx) => {
        cy.add({
          group: 'edges',
          data: {
            id: `e_${idx}_${e.src}_${e.dst}`,
            source: e.src,
            target: e.dst,
            label: e.syscall || '',
            syscall: e.syscall,
            weight: e.weight || 0.5,
            anomalous: e.anomalous ? 'true' : 'false',
          },
        });
      });
    });

    const layout = cy.layout({ name: 'cose', animate: false, padding: 30 });
    layout.run();
    cy.fit(null, 30);
  }, [graphData]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', minHeight: '480px', background: '#090d16', borderRadius: '8px' }}>
      <div ref={containerRef} style={{ width: '100%', height: '100%', minHeight: '480px' }} />
      {selectedNodeData && (
        <div style={{
          position: 'absolute',
          bottom: 16,
          right: 16,
          background: 'rgba(15, 23, 42, 0.95)',
          border: '1px solid #334155',
          borderRadius: 6,
          padding: 12,
          color: '#e2e8f0',
          fontSize: 12,
          fontFamily: 'monospace',
          maxWidth: 280,
          zIndex: 10,
        }}>
          <div style={{ fontWeight: 'bold', color: '#38bdf8', marginBottom: 6 }}>ENTITY DETAILS</div>
          <div>ID: {selectedNodeData.id}</div>
          <div>Type: {selectedNodeData.type}</div>
          {selectedNodeData.comm && <div>Command: {selectedNodeData.comm}</div>}
          {selectedNodeData.pid && <div>PID: {selectedNodeData.pid}</div>}
          <div>Quarantined: {selectedNodeData.isQuarantined ? 'YES (Frozen)' : 'No'}</div>
        </div>
      )}
    </div>
  );
}
