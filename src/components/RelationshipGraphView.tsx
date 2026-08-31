import React, { useEffect, useState, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  MarkerType,
  Position,
  Handle,
  useNodesState,
  useEdgesState
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Mail, Globe, Server, Network, Layers, FileText, ShieldAlert } from 'lucide-react';

const API_URL = ((import.meta as any).env?.VITE_API_URL || '').replace(/\/$/, '');

// Custom Node component
const EntityNode = ({ data }: any) => {
  const { type, label, risk_level, infra_type } = data;
  
  let Icon = FileText;
  let bgClass = "bg-slate-800";
  let borderClass = "border-slate-700";
  let textClass = "text-slate-200";
  let iconClass = "text-slate-400";
  
  if (type === 'email') {
    Icon = Mail;
    if (risk_level === 'MALICIOUS' || risk_level === 'PHISHING') {
      bgClass = "bg-rose-950/40";
      borderClass = "border-rose-500/50";
      iconClass = "text-rose-400";
    } else {
      bgClass = "bg-amber-950/40";
      borderClass = "border-amber-500/50";
      iconClass = "text-amber-400";
    }
  } else if (type === 'domain') {
    Icon = Globe;
  } else if (type === 'ip') {
    Icon = Server;
    if (infra_type && ['VPN', 'TOR', 'botnet_indicator'].includes(infra_type)) {
      borderClass = "border-rose-500/50";
      iconClass = "text-rose-400";
    }
  } else if (type === 'asn') {
    Icon = Network;
  } else if (type === 'campaign') {
    Icon = Layers;
    bgClass = "bg-purple-950/40";
    borderClass = "border-purple-500/50";
    iconClass = "text-purple-400";
  } else if (type === 'case') {
    Icon = FileText;
    bgClass = "bg-emerald-950/40";
    borderClass = "border-emerald-500/50";
    iconClass = "text-emerald-400";
  }

  return (
    <div className={`px-4 py-2 rounded-lg border ${bgClass} ${borderClass} flex items-center gap-3 shadow-lg min-w-[150px]`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 bg-slate-500 border-none" />
      <div className={`p-1.5 rounded-md bg-slate-900/50 ${iconClass}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <div className="text-[9px] font-mono uppercase text-slate-500">{type}</div>
        <div className={`text-xs font-semibold ${textClass} truncate max-w-[120px]`} title={label}>{label}</div>
        {infra_type && <div className="text-[10px] text-slate-400">{infra_type}</div>}
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-slate-500 border-none" />
    </div>
  );
};

const nodeTypes = {
  entity: EntityNode
};

export function RelationshipGraphView({ caseId }: { caseId: string }) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedDetails, setSelectedDetails] = useState<any | null>(null);

  useEffect(() => {
    let active = true;
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const res = await fetch(`${API_URL}/api/v1/cases/${caseId}/relationship-graph`);
        if (!res.ok) throw new Error("Failed to load graph data");
        const data = await res.json();
        if (!active) return;
        
        // Auto-layout logic (simple tree layout)
        const levels: Record<string, number> = {
          'campaign': 0,
          'email': 1,
          'case': 1,
          'domain': 2,
          'ip': 3,
          'asn': 4
        };
        
        const typeCounts: Record<string, number> = {};
        
        const flowNodes: Node[] = data.nodes.map((n: any) => {
          const t = n.type;
          typeCounts[t] = (typeCounts[t] || 0) + 1;
          const x = (typeCounts[t] * 180) - 200;
          const y = (levels[t] || 0) * 120 + 50;
          return {
            id: n.id,
            type: 'entity',
            position: { x, y },
            data: { ...n }
          };
        });
        
        const flowEdges: Edge[] = data.edges.map((e: any, i: number) => {
          let color = '#64748b'; // slate-500
          let width = 1;
          
          if (e.tier === 'STRONG') { color = '#f43f5e'; width = 2; } // rose-500
          else if (e.tier === 'MEDIUM') { color = '#f59e0b'; width = 1.5; } // amber-500
          
          return {
            id: `e${i}`,
            source: e.source,
            target: e.target,
            label: e.relationship,
            type: 'smoothstep',
            animated: e.tier === 'STRONG' || e.tier === 'MEDIUM',
            style: { stroke: color, strokeWidth: width },
            labelStyle: { fill: '#94a3b8', fontSize: 10, fontWeight: 500 },
            labelBgStyle: { fill: '#0f172a', stroke: '#1e293b', strokeWidth: 1, rx: 4 },
            data: { ...e }
          };
        });

        setNodes(flowNodes);
        setEdges(flowEdges);
      } catch (err: any) {
        if (active) setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    };
    fetchGraph();
    return () => { active = false; };
  }, [caseId]);

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedDetails({ type: 'node', data: node.data });
  };

  const onEdgeClick = (_: React.MouseEvent, edge: Edge) => {
    setSelectedDetails({ type: 'edge', data: edge.data });
  };

  if (loading) return <div className="h-64 flex items-center justify-center text-slate-400">Loading correlation graph...</div>;
  if (error) return <div className="h-64 flex items-center justify-center text-rose-400">{error}</div>;

  return (
    <div className="relative h-[400px] bg-[#0F172A] rounded-xl border border-slate-700 overflow-hidden flex">
      <div className="flex-1 h-full">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onEdgeClick={onEdgeClick}
          nodeTypes={nodeTypes}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#1e293b" gap={16} />
          <Controls className="bg-slate-800 border-slate-700 fill-slate-300" />
        </ReactFlow>
      </div>
      
      {/* Side Panel for details */}
      {selectedDetails && (
        <div className="w-64 border-l border-slate-700 bg-[#1E293B] p-4 overflow-y-auto">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wide">
              {selectedDetails.type === 'node' ? 'Entity Details' : 'Relationship'}
            </h3>
            <button onClick={() => setSelectedDetails(null)} className="text-slate-400 hover:text-slate-200">
              ✕
            </button>
          </div>
          
          <div className="space-y-3">
            {Object.entries(selectedDetails.data).map(([k, v]) => {
              if (k === 'id' || k === 'source' || k === 'target') return null;
              return (
                <div key={k} className="space-y-1">
                  <div className="text-[10px] uppercase font-mono text-slate-500">{k.replace('_', ' ')}</div>
                  <div className="text-xs text-slate-300 break-words font-medium">{String(v)}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
