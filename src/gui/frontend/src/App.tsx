import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ReactFlow,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
} from '@xyflow/react';
import dagre from 'dagre';
import { CustomNodeCard, CustomNodeData } from './CustomNode';

interface RawNode {
  id: string;
  role: string;
  ip: string;
  port: number;
}

interface RawCircuit {
  cid: number;
  client: string;
  relay: string;
  exit: string;
  dest: string;
}

interface TopologySnapshot {
  nodes: RawNode[];
  circuits: RawCircuit[];
  timestamp: number;
}

const nodeTypes = {
  custom: CustomNodeCard,
};

const getRoleColumn = (role: string): number => {
  if (role === 'client') return 0;
  if (role === 'relay' || role === 'client-relay') return 1;
  if (role === 'exit') return 2;
  return 1;
};

const getLayoutedElements = (nodes: Node<CustomNodeData>[], edges: Edge[]) => {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: 'LR',
    align: 'UL',
    nodesep: 36,
    ranksep: 160,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 200, height: 68 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const COLUMN_WIDTH = 360;
  const columnCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0 };

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const col = getRoleColumn(node.data.role);
    const hasEdges = edges.some((e) => e.source === node.id || e.target === node.id);

    const y = hasEdges
      ? nodeWithPosition.y - 34
      : columnCounts[col] * 104;

    columnCounts[col] += 1;

    return {
      ...node,
      position: {
        x: col * COLUMN_WIDTH,
        y,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
};

export default function App() {
  const [snapshot, setSnapshot] = useState<TopologySnapshot>({ nodes: [], circuits: [], timestamp: 0 });
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [connected, setConnected] = useState<boolean>(false);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<CustomNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const sse = new EventSource('/events');

    sse.onopen = () => {
      setConnected(true);
    };

    sse.onmessage = (event) => {
      try {
        const data: TopologySnapshot = JSON.parse(event.data);
        setSnapshot(data);
      } catch (err) {
        console.error('Failed to parse topology event:', err);
      }
    };

    sse.onerror = () => {
      setConnected(false);
    };

    return () => {
      sse.close();
    };
  }, []);

  const activeCircuits = useMemo(() => {
    if (!selectedNodeId) return [];
    return snapshot.circuits.filter((c) => {
      const targetRelay = snapshot.nodes.find((n) => `${n.ip}:${n.port}` === c.relay);
      const targetExit = snapshot.nodes.find((n) => `${n.ip}:${n.port}` === c.exit);
      return (
        c.client === selectedNodeId ||
        (targetRelay && targetRelay.id === selectedNodeId) ||
        (targetExit && targetExit.id === selectedNodeId)
      );
    });
  }, [snapshot.circuits, snapshot.nodes, selectedNodeId]);

  useEffect(() => {
    const rawNodes = snapshot.nodes;
    const rawCircuits = snapshot.circuits;

    const epToNodeId = new Map<string, string>();
    rawNodes.forEach((n) => {
      epToNodeId.set(`${n.ip}:${n.port}`, n.id);
    });

    const flowNodes: Node<CustomNodeData>[] = rawNodes.map((n) => {
      let isDimmed = false;
      const isSelected = n.id === selectedNodeId;

      if (selectedNodeId) {
        const isRelated =
          n.id === selectedNodeId ||
          activeCircuits.some((c) => {
            const rId = epToNodeId.get(c.relay);
            const eId = epToNodeId.get(c.exit);
            return c.client === n.id || rId === n.id || eId === n.id;
          });
        isDimmed = !isRelated;
      }

      const cktCount = rawCircuits.filter((c) => {
        const rId = epToNodeId.get(c.relay);
        const eId = epToNodeId.get(c.exit);
        return c.client === n.id || rId === n.id || eId === n.id;
      }).length;

      return {
        id: n.id,
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          id: n.id,
          role: n.role,
          ip: n.ip,
          port: n.port,
          isSelected,
          isDimmed,
          activeCircuitCount: cktCount,
        },
      };
    });

    const flowEdges: Edge[] = [];
    rawCircuits.forEach((c) => {
      const relayNodeId = epToNodeId.get(c.relay);
      const exitNodeId = epToNodeId.get(c.exit);

      const isCircuitActive =
        !selectedNodeId ||
        c.client === selectedNodeId ||
        relayNodeId === selectedNodeId ||
        exitNodeId === selectedNodeId;

      // Hop 1: Client -> Relay (solid muted blue)
      if (relayNodeId) {
        flowEdges.push({
          id: `edge-${c.cid}-cr`,
          source: c.client,
          target: relayNodeId,
          style: {
            stroke: isCircuitActive ? '#60a5fa' : '#2e2e2e',
            strokeWidth: isCircuitActive ? 1.5 : 1,
            opacity: isCircuitActive ? 0.85 : 0.25,
          },
        });
      }

      // Hop 2: Relay -> Exit (solid muted emerald)
      if (relayNodeId && exitNodeId) {
        flowEdges.push({
          id: `edge-${c.cid}-re`,
          source: relayNodeId,
          target: exitNodeId,
          style: {
            stroke: isCircuitActive ? '#34d399' : '#2e2e2e',
            strokeWidth: isCircuitActive ? 1.5 : 1,
            opacity: isCircuitActive ? 0.85 : 0.25,
          },
        });
      }
    });

    const layouted = getLayoutedElements(flowNodes, flowEdges);
    setNodes(layouted.nodes);
    setEdges(layouted.edges);
  }, [snapshot, selectedNodeId, activeCircuits, setNodes, setEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNodeId((prev) => (prev === node.id ? null : node.id));
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNodeId(null);
  }, []);

  const clientCount = snapshot.nodes.filter((n) => n.role === 'client').length;
  const relayCount = snapshot.nodes.filter((n) => n.role === 'relay' || n.role === 'client-relay').length;
  const exitCount = snapshot.nodes.filter((n) => n.role === 'exit').length;

  return (
    <div className="relative w-full h-full bg-[#121212] text-[#e5e5e5]">
      {/* Simple Top-Left Status Box */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-4 bg-[#1a1a1a] border border-[#333333] px-3.5 py-2 text-sm">
        <span>Clients: {clientCount}</span>
        <span>Relays: {relayCount}</span>
        <span>Exits: {exitCount}</span>
        <span className="text-[#444444]">|</span>
        <span className={connected ? 'text-[#d4d4d4]' : 'text-[#ef4444]'}>
          {connected ? 'Connected' : 'Disconnected'}
        </span>
      </div>

      {/* Canvas */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        fitView
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
        maxZoom={2}
      />

      {/* Circuit Detail Panel on Node Click */}
      {selectedNodeId && (
        <aside className="absolute bottom-4 right-4 z-20 w-80 max-h-[80vh] overflow-y-auto bg-[#1a1a1a] border border-[#333333] p-4">
          <div className="flex items-center justify-between pb-2.5 border-b border-[#2e2e2e]">
            <span className="font-semibold text-sm text-[#f5f5f5]">{selectedNodeId}</span>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-xs text-[#a3a3a3] hover:text-white px-1.5 py-0.5"
            >
              Close
            </button>
          </div>

          <div className="mt-3 space-y-2.5">
            <div className="text-xs text-[#a3a3a3]">
              Active Circuits ({activeCircuits.length})
            </div>

            {activeCircuits.length === 0 ? (
              <div className="text-xs text-[#737373] py-1">
                No active circuits routed through this node.
              </div>
            ) : (
              activeCircuits.map((ckt) => (
                <div
                  key={ckt.cid}
                  className="bg-[#121212] border border-[#2e2e2e] p-2.5 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between text-[#d4d4d4] font-medium">
                    <span>Circuit #{ckt.cid}</span>
                    <span className="text-[11px] text-[#a3a3a3]">Established</span>
                  </div>
                  <div className="text-[#a3a3a3] font-mono text-[11px]">
                    {ckt.client} &rarr; {ckt.relay} &rarr; {ckt.exit}
                  </div>
                  {ckt.dest && (
                    <div className="text-[11px] text-[#737373] font-mono truncate">
                      Dest: {ckt.dest}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </aside>
      )}
    </div>
  );
}