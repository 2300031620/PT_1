import React, { useState } from 'react';
import { Incident, IncidentStatus } from '../types';

interface IncidentsViewProps {
  incidents: Incident[];
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => Promise<void>;
  onContainToggle: () => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  onUpdateStatus,
  onContainToggle
}) => {
  const [filter, setFilter] = useState<string>('ALL');

  const filtered = incidents.filter(
    (inc) => filter === 'ALL' || inc.status === filter
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-gray-900 uppercase">Incidents List</h2>
          <p className="text-xs text-gray-500">Security incidents triggered by critical ransomware events</p>
        </div>

        {/* Simple status filter */}
        <div className="flex gap-1 text-xs">
          {['ALL', 'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setFilter(st)}
              className={`px-2.5 py-1 rounded border text-xs font-semibold ${
                filter === st
                  ? 'bg-blue-600 text-white border-blue-700'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-100'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white border border-gray-300 rounded overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="bg-gray-100 text-gray-700 border-b border-gray-200">
            <tr>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Incident ID</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Risk Score</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Severity</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Device</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Files Affected</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Status</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Reason</th>
              <th className="p-2.5 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {filtered.map((inc) => (
              <tr key={inc.id} className="hover:bg-gray-50">
                <td className="p-2.5 border-r border-gray-200 font-mono font-bold text-blue-700">
                  {inc.incidentId}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-bold">{inc.riskScore} / 100</td>
                <td className="p-2.5 border-r border-gray-200">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      inc.severity === 'CRITICAL'
                        ? 'bg-red-100 text-red-700'
                        : inc.severity === 'HIGH'
                        ? 'bg-orange-100 text-orange-700'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}
                  >
                    {inc.severity}
                  </span>
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-700">
                  {inc.deviceId}
                </td>
                <td className="p-2.5 border-r border-gray-200 text-gray-800 font-semibold">
                  {inc.filesAffected}
                </td>
                <td className="p-2.5 border-r border-gray-200">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      inc.status === 'CONTAINED'
                        ? 'bg-purple-100 text-purple-800'
                        : inc.status === 'RESOLVED'
                        ? 'bg-green-100 text-green-800'
                        : inc.status === 'INVESTIGATING'
                        ? 'bg-yellow-100 text-yellow-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {inc.status}
                  </span>
                </td>
                <td className="p-2.5 border-r border-gray-200 text-gray-700 max-w-xs truncate" title={inc.reason}>
                  {inc.reason}
                </td>
                <td className="p-2.5">
                  <div className="flex items-center gap-1.5">
                    {inc.status !== 'INVESTIGATING' && inc.status !== 'RESOLVED' && (
                      <button
                        onClick={() => onUpdateStatus(inc.id, 'INVESTIGATING')}
                        className="px-2 py-1 bg-gray-100 hover:bg-gray-200 text-gray-800 rounded border border-gray-300 text-[11px]"
                      >
                        Investigate
                      </button>
                    )}
                    {inc.status !== 'CONTAINED' && inc.status !== 'RESOLVED' && (
                      <button
                        onClick={async () => {
                          await onUpdateStatus(inc.id, 'CONTAINED');
                          onContainToggle();
                        }}
                        className="px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-[11px] font-bold"
                      >
                        Contain
                      </button>
                    )}
                    {inc.status !== 'RESOLVED' && (
                      <button
                        onClick={() => onUpdateStatus(inc.id, 'RESOLVED')}
                        className="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-[11px] font-bold"
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="p-4 text-center text-gray-400">
                  No incidents found. Run "Test 4: Mass Ransomware" on the Dashboard to trigger an incident.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
