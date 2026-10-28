import React, { useMemo } from 'react';
import { Layers } from 'lucide-react';
import {
  parseAndSortPorts,
  detectPortRanges,
  getPortServiceName,
} from '../utils/portUtils';

interface PortBadgesCellProps {
  portString: string;
  hedefIp: string;
  onOpenModal: (ip: string, portString: string) => void;
  onFilterByPort?: (port: number) => void;
}

export const PortBadgesCell: React.FC<PortBadgesCellProps> = ({
  portString,
  hedefIp,
  onOpenModal,
  onFilterByPort,
}) => {
  const sortedPorts = useMemo(() => {
    return parseAndSortPorts(portString);
  }, [portString]);

  const { ranges } = useMemo(() => {
    return detectPortRanges(sortedPorts);
  }, [sortedPorts]);

  if (sortedPorts.length === 0) {
    return <span className="text-slate-400 font-mono text-xs">-</span>;
  }

  // Case 1: Very few ports (1-3 ports)
  if (sortedPorts.length <= 3) {
    return (
      <div className="flex flex-wrap items-center gap-1.5 py-0.5">
        {sortedPorts.map(p => {
          const sName = getPortServiceName(p);
          const isKnown = sName !== 'Diğer / Özel' && sName !== 'Dinamik / Ephemeral';
          return (
            <button
              key={p}
              onClick={() => onFilterByPort?.(p)}
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-mono font-bold transition-colors cursor-pointer ${
                isKnown
                  ? 'bg-blue-50 text-blue-800 border border-blue-200 hover:bg-blue-100'
                  : 'bg-slate-100 text-slate-700 border border-slate-200 hover:bg-slate-200'
              }`}
              title={isKnown ? `${p} - ${sName} (Filtrelemek için tıkla)` : `${p} (Filtrelemek için tıkla)`}
            >
              <span>{p}</span>
              {isKnown && (
                <span className="text-[10px] font-sans font-medium text-blue-600 opacity-90">
                  {sName}
                </span>
              )}
            </button>
          );
        })}
      </div>
    );
  }

  // Case 2: Many ports (4 or more, e.g. 50-500 ports as in user's screenshot)
  const displayCount = 2;
  const initialPorts = sortedPorts.slice(0, displayCount);
  const remainingCount = sortedPorts.length - displayCount;
  const primaryRange = ranges.length > 0 ? ranges[0] : null;

  return (
    <div className="flex flex-wrap items-center gap-1.5 py-0.5 max-w-md">
      {/* First 2 ports */}
      {initialPorts.map(p => {
        const sName = getPortServiceName(p);
        const isKnown = sName !== 'Diğer / Özel' && sName !== 'Dinamik / Ephemeral';
        return (
          <span
            key={p}
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-mono font-bold ${
              isKnown
                ? 'bg-blue-50 text-blue-800 border border-blue-200'
                : 'bg-slate-100 text-slate-700 border border-slate-200'
            }`}
          >
            {p}
            {isKnown && <span className="text-[9px] font-sans font-medium text-blue-600">({sName})</span>}
          </span>
        );
      })}

      {/* If consecutive range detected, highlight it */}
      {primaryRange && (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded text-[11px] font-mono font-bold"
          title={`${primaryRange.start} ile ${primaryRange.end} arası ardışık ${primaryRange.count} port taraması / pasif FTP`}
        >
          {primaryRange.start}&ndash;{primaryRange.end} ({primaryRange.count} port)
        </span>
      )}

      {/* Button to open complete sorted list modal */}
      <button
        onClick={() => onOpenModal(hedefIp, portString)}
        className="inline-flex items-center gap-1 px-2.5 py-0.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-[11px] font-semibold transition-all cursor-pointer shadow-2xs hover:shadow-xs"
        title={`${sortedPorts.length} portun tamamını sayısal sıralı incele`}
      >
        <Layers className="w-3 h-3" />
        <span>+{remainingCount} Port ({sortedPorts.length})</span>
      </button>
    </div>
  );
};
