import React, { useState } from 'react';
import { ArchiveRecord, ProtectedFile } from '../types';

interface ArchivesViewProps {
  archives: ArchiveRecord[];
  protectedFiles: ProtectedFile[];
  onCreateArchive: (selectedIds: string[], format?: 'ZIP' | '7Z') => Promise<void>;
}

export const ArchivesView: React.FC<ArchivesViewProps> = ({
  archives,
  protectedFiles,
  onCreateArchive
}) => {
  const [selectedFormat, setSelectedFormat] = useState<'ZIP' | '7Z'>('ZIP');
  const [inspectArch, setInspectArch] = useState<ArchiveRecord | null>(null);

  const handleCreate = async () => {
    await onCreateArchive(protectedFiles.map((f) => f.id), selectedFormat);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-gray-900 uppercase">Archive Manager</h2>
          <p className="text-xs text-gray-500">Backups of prioritized files with recorded file hashes</p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedFormat}
            onChange={(e) => setSelectedFormat(e.target.value as 'ZIP' | '7Z')}
            className="p-1.5 border border-gray-300 rounded text-xs bg-white"
          >
            <option value="ZIP">ZIP Format</option>
            <option value="7Z">7Z Format</option>
          </select>
          <button
            onClick={handleCreate}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded"
          >
            + Create New Archive
          </button>
        </div>
      </div>

      <div className="bg-white border border-gray-300 rounded overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="bg-gray-100 text-gray-700 border-b border-gray-200">
            <tr>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Archive ID</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Creation Time</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Files Included</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Archive Size</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Format</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Status</th>
              <th className="p-2.5 font-semibold text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {archives.map((arch) => (
              <tr key={arch.id} className="hover:bg-gray-50">
                <td className="p-2.5 border-r border-gray-200 font-mono font-bold text-blue-700">
                  {arch.archiveId}
                </td>
                <td className="p-2.5 border-r border-gray-200 text-gray-600 font-mono">
                  {new Date(arch.createdAt).toLocaleString()}
                </td>
                <td className="p-2.5 border-r border-gray-200">
                  <span className="font-semibold text-gray-800">
                    {arch.filesIncluded.length} files:
                  </span>{' '}
                  <span className="text-gray-500 font-mono">
                    {arch.filesIncluded.join(', ')}
                  </span>
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-700">
                  {arch.archiveSize}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono font-semibold">
                  {arch.format}
                </td>
                <td className="p-2.5 border-r border-gray-200">
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-green-100 text-green-800">
                    {arch.status}
                  </span>
                </td>
                <td className="p-2.5 text-right">
                  <button
                    onClick={() => setInspectArch(arch)}
                    className="px-2 py-1 bg-gray-100 hover:bg-gray-200 border border-gray-300 rounded text-[11px] font-semibold"
                  >
                    View Hashes
                  </button>
                </td>
              </tr>
            ))}
            {archives.length === 0 && (
              <tr>
                <td colSpan={7} className="p-4 text-center text-gray-400">
                  No archives created yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Simple Hashes Popup */}
      {inspectArch && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white border border-gray-400 rounded p-4 max-w-lg w-full space-y-3 text-xs">
            <div className="flex justify-between items-center border-b pb-2">
              <span className="font-bold text-sm">
                Hashes for {inspectArch.archiveId} ({inspectArch.format})
              </span>
              <button
                onClick={() => setInspectArch(null)}
                className="text-gray-500 hover:text-black font-bold text-base"
              >
                ✕
              </button>
            </div>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {inspectArch.filesIncluded.map((name, i) => (
                <div key={i} className="p-2 bg-gray-50 border rounded">
                  <div className="font-bold">{name}</div>
                  <div className="font-mono text-[11px] text-gray-600 break-all">
                    SHA256: {inspectArch.fileHashes[i] || 'N/A'}
                  </div>
                </div>
              ))}
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => setInspectArch(null)}
                className="px-3 py-1 bg-gray-700 text-white rounded font-bold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
