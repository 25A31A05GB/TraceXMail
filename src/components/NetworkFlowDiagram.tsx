import { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  MarkerType,
  Position,
  Handle
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network, Server, AlertTriangle, CheckCircle, Globe } from 'lucide-react';
import { EmailAnalysis, EmailHop } from '../types';

interface NetworkFlowDiagramProps {
  analysis?: EmailAnalysis;
  hops?: EmailHop[];
}

// Custom Node Component for Hop Relays
function HopNodeComponent({ data }: { data: any }) {
  const isSuspicious = data.isSuspicious || (data.delay && data.delay > 10) || data.untrusted;
  const isOrigin = data.isOrigin;
  const isDestination = data.isDestination;

  return (
    <div
      className={`px-4 py-3 rounded-xl border shadow-lg transition-all min-w-[200px] max-w-[260px] ${
        isSuspicious
          ? 'bg-rose-950/80 border-rose-500/80 text-rose-200 shadow-rose-950/50'
          : isOrigin
          ? 'bg-amber-950/80 border-amber-500/80 text-amber-200 shadow-amber-950/50'
          : isDestination
          ? 'bg-emerald-950/80 border-emerald-500/80 text-emerald-200 shadow-emerald-950/50'
          : 'bg-slate-900/90 border-slate-700 text-slate-200'
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-blue-400 !w-2.5 !h-2.5" />
      
      <div className="flex items-center gap-2 mb-1.5">
        <div className={`p-1.5 rounded-lg ${
          isSuspicious ? 'bg-rose-500/20 text-rose-400' : isOrigin ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'
        }`}>
          {isOrigin ? (
            <Globe className="w-4 h-4" />
          ) : isDestination ? (
            <CheckCircle className="w-4 h-4" />
          ) : isSuspicious ? (
            <AlertTriangle className="w-4 h-4" />
          ) : (
            <Server className="w-4 h-4" />
          )}
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
            {isOrigin ? 'Originating Client' : isDestination ? 'Final MX Gateway' : `Hop #${data.hopNumber}`}
          </div>
          <div className="text-xs font-bold font-mono truncate max-w-[170px]" title={data.ip || data.host}>
            {data.ip || data.host || 'Unknown Node'}
          </div>
        </div>
      </div>

      <div className="text-[11px] space-y-0.5 pt-1 border-t border-slate-800/80 font-mono">
        {data.location && (
          <div className="text-slate-400 flex items-center justify-between">
            <span>Location:</span>
            <span className="text-slate-200 font-semibold">{data.location}</span>
          </div>
        )}
        {data.asn && (
          <div className="text-slate-400 flex items-center justify-between">
            <span>ASN:</span>
            <span className="text-slate-300 truncate max-w-[120px]">{data.asn}</span>
          </div>
        )}
        {data.delay !== undefined && (
          <div className="text-slate-400 flex items-center justify-between">
            <span>Delay:</span>
            <span className={data.delay > 10 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
              +{data.delay}s
            </span>
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-2.5 !h-2.5" />
    </div>
  );
}

// Custom Node Component for NetworkX Graph Engine Nodes
function CustomNodeComponent({ data }: { data: any }) {
  const nodeType = data.node_type || 'entity';
  const severity = data.severity || 'LOW';
  const isCritical = severity === 'CRITICAL' || severity === 'HIGH';

  return (
    <div
      className={`px-3.5 py-2.5 rounded-xl border shadow-lg transition-all min-w-[180px] max-w-[240px] ${
        isCritical
          ? 'bg-rose-950/80 border-rose-500/80 text-rose-200 shadow-rose-950/50'
          : severity === 'MEDIUM'
          ? 'bg-amber-950/80 border-amber-500/80 text-amber-200 shadow-amber-950/50'
          : 'bg-slate-900/90 border-slate-700 text-slate-200'
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-blue-400 !w-2.5 !h-2.5" />
      <div className="flex items-center gap-2 mb-1">
        <div className={`p-1 rounded-md ${isCritical ? 'bg-rose-500/20 text-rose-400' : 'bg-blue-500/20 text-blue-400'}`}>
          <Network className="w-3.5 h-3.5" />
        </div>
        <div className="truncate">
          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-400">{nodeType}</div>
          <div className="text-xs font-bold font-mono truncate" title={data.label}>{data.label || 'Node'}</div>
        </div>
      </div>
      {data.details && (
        <div className="text-[10px] text-slate-400 font-mono border-t border-slate-800/80 pt-1 mt-1 truncate">
          {data.details}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-2.5 !h-2.5" />
    </div>
  );
}

const nodeTypes = {
  hopNode: HopNodeComponent,
  customNode: CustomNodeComponent,
};

export function NetworkFlowDiagram({ analysis, hops }: NetworkFlowDiagramProps) {
  const { nodes, edges, isBackendGraph } = useMemo(() => {
    // 1. Prefer Backend NetworkX Forensic Graph
    if (analysis?.graph?.nodes && Array.isArray(analysis.graph.nodes) && analysis.graph.nodes.length > 0) {
      return {
        nodes: analysis.graph.nodes as Node[],
        edges: (analysis.graph.edges || []) as Edge[],
        isBackendGraph: true
      };
    }

    // 2. Otherwise derive DAG from hops if provided
    const hopList = (hops && hops.length > 0) ? hops : (analysis?.hops && analysis.hops.length > 0) ? analysis.hops : [];
    if (hopList.length === 0) {
      return { nodes: [], edges: [], isBackendGraph: false };
    }

    const generatedNodes: Node[] = [];
    const generatedEdges: Edge[] = [];

    const startY = 40;
    const verticalGap = 130;

    hopList.forEach((h, index) => {
      const isFirst = index === 0 || !!h.isOrigin;
      const isLast = index === hopList.length - 1;
      const nodeId = `hop-node-${index}`;
      const locationText = h.city ? `${h.city}, ${h.countryCode || h.country || ''}` : h.country ? h.country : undefined;

      generatedNodes.push({
        id: nodeId,
        type: 'hopNode',
        position: { x: 260, y: startY + index * verticalGap },
        data: {
          hopNumber: h.hopNumber || index + 1,
          ip: h.fromIp,
          host: h.fromHost || h.byHost,
          location: locationText,
          asn: h.asn || undefined,
          delay: h.delaySec ?? 0,
          isSuspicious: (h.abuseScore && h.abuseScore > 50) || (h.delaySec && h.delaySec > 8),
          isOrigin: isFirst,
          isDestination: isLast,
        },
      });

      if (index > 0) {
        const prevNodeId = `hop-node-${index - 1}`;
        const prevHop = hopList[index - 1];
        const isAnomalous = (prevHop.abuseScore && prevHop.abuseScore > 50) || ((h.delaySec ?? 0) > 8);

        generatedEdges.push({
          id: `edge-${prevNodeId}-${nodeId}`,
          source: prevNodeId,
          target: nodeId,
          animated: true,
          style: {
            stroke: isAnomalous ? '#f43f5e' : '#3b82f6',
            strokeWidth: 2,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isAnomalous ? '#f43f5e' : '#3b82f6',
          },
          label: h.delaySec !== undefined ? `+${h.delaySec}s latency` : 'Direct Relay',
          labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
          labelBgStyle: { fill: '#0f172a', fillOpacity: 0.8 },
        });
      }
    });

    return { nodes: generatedNodes, edges: generatedEdges, isBackendGraph: false };
  }, [analysis, hops]);

  if (nodes.length === 0) {
    return (
      <div className="w-full h-full min-h-[350px] bg-slate-950/60 rounded-xl border border-slate-800 p-8 flex flex-col items-center justify-center text-center">
        <Server className="w-10 h-10 text-slate-600 mb-3" />
        <h4 className="text-sm font-semibold text-slate-300 font-mono uppercase">
          No Transmission Graph Recorded
        </h4>
        <p className="text-xs text-slate-500 max-w-md mt-1 font-mono">
          No network hops or forensic topology nodes were detected in this email payload. UNKNOWN is preserved per §24 forensic guidelines.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full h-full min-h-[420px] bg-slate-950/60 rounded-xl border border-slate-800 relative overflow-hidden flex flex-col">
      {/* Header Overlay */}
      <div className="absolute top-3 left-4 z-10 bg-slate-900/90 border border-slate-700/80 px-3 py-1.5 rounded-lg flex items-center gap-2 shadow-md">
        <Network className="w-4 h-4 text-blue-400" />
        <span className="text-xs font-sans font-semibold text-slate-200">
          {isBackendGraph ? 'Forensic Topology Engine' : `Interactive Topology DAG (${nodes.length} Hop Nodes)`}
        </span>
      </div>

      <div className="flex-1 w-full h-full">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          attributionPosition="bottom-right"
          className="bg-transparent"
        >
          <Background color="#334155" gap={20} size={1} />
          <Controls className="!bg-slate-900 !border-slate-700 !text-slate-300" />
        </ReactFlow>
      </div>
    </div>
  );
}
