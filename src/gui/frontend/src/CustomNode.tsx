import React from 'react';
import { Handle, Position } from '@xyflow/react';

export interface CustomNodeData extends Record<string, unknown> {
  id: string;
  role: 'client' | 'relay' | 'exit' | string;
  ip: string;
  port: number;
  isSelected?: boolean;
  isDimmed?: boolean;
  activeCircuitCount?: number;
}

export const CustomNodeCard: React.FC<{ data: CustomNodeData }> = ({ data }) => {
  const isClient = data.role === 'client';
  const isRelay = data.role === 'relay' || data.role === 'client-relay';
  const isExit = data.role === 'exit';

  let roleLabel = 'CLIENT';
  let headerStyle = 'bg-[#1e293b] text-[#93c5fd]';

  if (isRelay) {
    roleLabel = 'RELAY';
    headerStyle = 'bg-[#292218] text-[#fcd34d]';
  } else if (isExit) {
    roleLabel = 'EXIT';
    headerStyle = 'bg-[#172822] text-[#6ee7b7]';
  }

  const opacityClass = data.isDimmed ? 'opacity-25' : 'opacity-100';
  const borderClass = data.isSelected ? 'border-[#888888]' : 'border-[#333333]';

  return (
    <div
      className={`min-w-[180px] bg-[#1a1a1a] border ${borderClass} ${opacityClass} transition-opacity duration-150 select-none`}
    >
      {!isClient && (
        <Handle
          type="target"
          position={Position.Left}
          className="!w-2 !h-2 !rounded-none !bg-[#888888] !border-0"
        />
      )}
      {!isExit && (
        <Handle
          type="source"
          position={Position.Right}
          className="!w-2 !h-2 !rounded-none !bg-[#888888] !border-0"
        />
      )}

      {/* Top Header Strip */}
      <div className={`flex items-center justify-between px-2.5 py-1 border-b border-[#2e2e2e] text-[10px] font-mono tracking-wider ${headerStyle}`}>
        <span>{roleLabel}</span>
        {data.activeCircuitCount !== undefined && data.activeCircuitCount > 0 && (
          <span className="text-[#a3a3a3]">{data.activeCircuitCount} ckt</span>
        )}
      </div>

      {/* Body */}
      <div className="px-2.5 py-2">
        <div className="text-xs font-medium text-[#f5f5f5]">{data.id}</div>
        <div className="font-mono text-[11px] text-[#888888] mt-0.5">
          {data.ip}:{data.port}
        </div>
      </div>
    </div>
  );
};