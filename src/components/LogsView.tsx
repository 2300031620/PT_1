import React, { useState } from 'react';
import { AuditLog } from '../types';

interface LogsViewProps {
  logs: AuditLog[];
}

export const LogsView: React.FC<LogsViewProps> = ({ logs }) => {
  const [filterAction, setFilterAction] = useState('ALL');

  const filtered = logs.filter(
    (l) => filterAction === 'ALL' || l.action.toLowerCase().includes(filterAction.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-gray-900 uppercase">Audit Log</h2>
          <p className="text-xs text-gray-500">History of actions recorded in Firebase</p>
        </div>

        <select
          value={filterAction}
          onChange={(e) => setFilterAction(e.target.value)}
          className="p-1.5 border border-gray-300 rounded text-xs bg-white"
        >
          <option value="ALL">All Actions</option>
          <option value="login">login</option>
          <option value="protected">file added / removed</option>
          <option value="archive">archive created</option>
          <option value="incident">incident created</option>
          <option value="containment">containment triggered</option>
          <option value="released">device released</option>
          <option value="settings">settings changed</option>
        </select>
      </div>

      <div className="bg-white border border-gray-300 rounded overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="bg-gray-100 text-gray-700 border-b border-gray-200">
            <tr>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Timestamp</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">User</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Action</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Device</th>
              <th className="p-2.5 font-semibold">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {filtered.map((log) => (
              <tr key={log.id} className="hover:bg-gray-50">
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-500 whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-medium text-gray-800">
                  {log.user}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-bold text-gray-800">
                  {log.action}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-700">
                  {log.device}
                </td>
                <td className="p-2.5 text-gray-700">
                  {log.result}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="p-4 text-center text-gray-400">
                  No logs found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
