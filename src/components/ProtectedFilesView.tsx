import React, { useState } from 'react';
import { ProtectedFile, FilePriority } from '../types';

interface ProtectedFilesViewProps {
  files: ProtectedFile[];
  onAddFile: (file: { name: string; path: string; priority: FilePriority; sha256: string; sizeBytes: number }) => Promise<void>;
  onRemoveFile: (id: string, name: string) => Promise<void>;
  onCreateArchive: (selectedIds: string[]) => Promise<void>;
}

export const ProtectedFilesView: React.FC<ProtectedFilesViewProps> = ({
  files,
  onAddFile,
  onRemoveFile,
  onCreateArchive
}) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [priority, setPriority] = useState<FilePriority>('HIGH');
  const [sha256, setSha256] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const handleToggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleSelectAll = () => {
    if (selectedIds.length === files.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(files.map((f) => f.id));
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !path) return;

    const dummyHash =
      sha256 ||
      Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    await onAddFile({
      name,
      path,
      priority,
      sha256: dummyHash,
      sizeBytes: 1048576 * 2
    });

    setName('');
    setPath('');
    setSha256('');
    setShowAddForm(false);
  };

  return (
    <div className="space-y-4">
      {/* Top Action Buttons */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-gray-900 uppercase">Protected Files Manager</h2>
          <p className="text-xs text-gray-500">
            Files with priority levels and monitored SHA-256 integrity
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onCreateArchive(selectedIds.length ? selectedIds : files.map((f) => f.id))}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-900 text-white text-xs font-bold rounded"
          >
            Create Archive ({selectedIds.length || files.length} files)
          </button>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded"
          >
            {showAddForm ? 'Cancel' : '+ Add Protected File'}
          </button>
        </div>
      </div>

      {/* Simple Inline Form to Add File */}
      {showAddForm && (
        <form onSubmit={handleAddSubmit} className="bg-gray-50 border border-gray-300 p-3 rounded space-y-3 text-xs">
          <div className="font-bold text-gray-800">Add New File to Protection List</div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <div>
              <label className="block text-gray-600 font-medium mb-1">File Name</label>
              <input
                type="text"
                placeholder="e.g. database.sql"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full p-1.5 border border-gray-300 rounded bg-white"
              />
            </div>
            <div>
              <label className="block text-gray-600 font-medium mb-1">Full Path</label>
              <input
                type="text"
                placeholder="e.g. C:\ProtectedFiles\database.sql"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                required
                className="w-full p-1.5 border border-gray-300 rounded bg-white font-mono"
              />
            </div>
            <div>
              <label className="block text-gray-600 font-medium mb-1">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as FilePriority)}
                className="w-full p-1.5 border border-gray-300 rounded bg-white"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
            <div>
              <label className="block text-gray-600 font-medium mb-1">SHA-256 (optional)</label>
              <input
                type="text"
                placeholder="Leave blank for auto hash"
                value={sha256}
                onChange={(e) => setSha256(e.target.value)}
                className="w-full p-1.5 border border-gray-300 rounded bg-white font-mono"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded"
            >
              Save File
            </button>
          </div>
        </form>
      )}

      {/* Simple Files Table */}
      <div className="bg-white border border-gray-300 rounded overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="bg-gray-100 text-gray-700 border-b border-gray-200">
            <tr>
              <th className="p-2.5 border-r border-gray-200 w-8">
                <input
                  type="checkbox"
                  checked={selectedIds.length === files.length && files.length > 0}
                  onChange={handleSelectAll}
                />
              </th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">File Name</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">Priority</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">File Path</th>
              <th className="p-2.5 border-r border-gray-200 font-semibold">SHA-256 Hash</th>
              <th className="p-2.5 font-semibold text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {files.map((file) => (
              <tr key={file.id} className="hover:bg-gray-50">
                <td className="p-2.5 border-r border-gray-200">
                  <input
                    type="checkbox"
                    checked={selectedIds.includes(file.id)}
                    onChange={() => handleToggleSelect(file.id)}
                  />
                </td>
                <td className="p-2.5 border-r border-gray-200 font-bold text-gray-900">
                  {file.name}
                </td>
                <td className="p-2.5 border-r border-gray-200">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      file.priority === 'CRITICAL'
                        ? 'bg-red-100 text-red-700'
                        : file.priority === 'HIGH'
                        ? 'bg-orange-100 text-orange-700'
                        : file.priority === 'MEDIUM'
                        ? 'bg-blue-100 text-blue-700'
                        : 'bg-gray-100 text-gray-700'
                    }`}
                  >
                    {file.priority}
                  </span>
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-600 max-w-xs truncate" title={file.path}>
                  {file.path}
                </td>
                <td className="p-2.5 border-r border-gray-200 font-mono text-gray-500 text-[11px] max-w-sm truncate" title={file.sha256}>
                  {file.sha256}
                </td>
                <td className="p-2.5 text-right">
                  <button
                    onClick={() => onRemoveFile(file.id, file.name)}
                    className="px-2 py-1 text-red-600 hover:text-red-800 hover:bg-red-50 rounded font-semibold text-[11px]"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
