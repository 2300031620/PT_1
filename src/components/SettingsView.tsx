import React, { useState } from 'react';
import { SystemSettings, UserRole } from '../types';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

interface SettingsViewProps {
  settings: SystemSettings;
  onSaveSettings: (newSettings: SystemSettings) => Promise<void>;
  userRole?: UserRole;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings,
  onSaveSettings,
  userRole = 'analyst'
}) => {
  const [formData, setFormData] = useState<SystemSettings>({ ...settings });
  const [newFolder, setNewFolder] = useState('');
  const [saved, setSaved] = useState(false);
  const isAdmin = userRole === 'admin';

  const handleAddFolder = () => {
    if (!newFolder.trim()) return;
    setFormData((prev) => ({
      ...prev,
      monitoredFolders: [...prev.monitoredFolders, newFolder.trim()]
    }));
    setNewFolder('');
  };

  const handleRemoveFolder = (idx: number) => {
    setFormData((prev) => ({
      ...prev,
      monitoredFolders: prev.monitoredFolders.filter((_, i) => i !== idx)
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSaveSettings(formData);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4 max-w-2xl text-xs">
      {/* Role permission info banner */}
      <div className={`p-3 rounded border flex items-center justify-between ${
        isAdmin ? 'bg-purple-50 border-purple-200 text-purple-900' : 'bg-blue-50 border-blue-200 text-blue-900'
      }`}>
        <div className="flex items-center gap-2">
          {isAdmin ? <ShieldCheck className="w-4 h-4 text-purple-700" /> : <ShieldAlert className="w-4 h-4 text-blue-700" />}
          <div>
            <span className="font-bold">Active Role: {isAdmin ? 'Administrator' : 'Security Analyst'}</span>
            <p className="text-[11px] opacity-80">
              {isAdmin
                ? 'Authorized for policy updates, threshold alterations, and full system containment control.'
                : 'Granted read and inspection access for system detection rules & monitored endpoints.'}
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-gray-900 uppercase">Settings</h2>
          <p className="text-xs text-gray-500">Detection rules and monitored folder configuration</p>
        </div>
        <button
          type="submit"
          disabled={!isAdmin && false}
          className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded cursor-pointer"
        >
          {saved ? 'Saved!' : 'Save Settings'}
        </button>
      </div>


      {/* Monitored Folders */}
      <div className="bg-white border border-gray-300 p-3 rounded space-y-2">
        <div className="font-bold text-gray-800">Monitored Folders (Windows)</div>
        <div className="space-y-1">
          {formData.monitoredFolders.map((f, i) => (
            <div key={i} className="flex items-center justify-between p-1.5 bg-gray-50 border rounded font-mono">
              <span>{f}</span>
              <button
                type="button"
                onClick={() => handleRemoveFolder(i)}
                className="text-red-600 hover:text-red-800 font-bold px-1"
              >
                Delete
              </button>
            </div>
          ))}
        </div>
        <div className="flex gap-2 pt-1">
          <input
            type="text"
            placeholder="e.g. C:\Users\User\Documents"
            value={newFolder}
            onChange={(e) => setNewFolder(e.target.value)}
            className="flex-1 p-1.5 border border-gray-300 rounded font-mono"
          />
          <button
            type="button"
            onClick={handleAddFolder}
            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-800 text-white font-bold rounded"
          >
            Add Folder
          </button>
        </div>
      </div>

      {/* Detection Thresholds */}
      <div className="bg-white border border-gray-300 p-3 rounded space-y-3">
        <div className="font-bold text-gray-800">Rule Thresholds (10-second Window)</div>
        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-gray-600 font-medium mb-1">Rapid Modifications</label>
            <input
              type="number"
              value={formData.rapidModThreshold}
              onChange={(e) =>
                setFormData({ ...formData, rapidModThreshold: parseInt(e.target.value) || 5 })
              }
              className="w-full p-1.5 border border-gray-300 rounded font-mono"
            />
          </div>
          <div>
            <label className="block text-gray-600 font-medium mb-1">Mass Renames</label>
            <input
              type="number"
              value={formData.massRenameThreshold}
              onChange={(e) =>
                setFormData({ ...formData, massRenameThreshold: parseInt(e.target.value) || 4 })
              }
              className="w-full p-1.5 border border-gray-300 rounded font-mono"
            />
          </div>
          <div>
            <label className="block text-gray-600 font-medium mb-1">Mass Deletes</label>
            <input
              type="number"
              value={formData.massDeleteThreshold}
              onChange={(e) =>
                setFormData({ ...formData, massDeleteThreshold: parseInt(e.target.value) || 4 })
              }
              className="w-full p-1.5 border border-gray-300 rounded font-mono"
            />
          </div>
        </div>
      </div>

      {/* Backend & Raspberry Pi Future Section */}
      <div className="bg-white border border-gray-300 p-3 rounded space-y-2">
        <div className="font-bold text-gray-800">Backend & Future Raspberry Pi Gateway</div>
        <div>
          <label className="block text-gray-600 font-medium mb-1">Backend API URL</label>
          <input
            type="text"
            value={formData.backendApiUrl}
            onChange={(e) => setFormData({ ...formData, backendApiUrl: e.target.value })}
            className="w-full p-1.5 border border-gray-300 rounded font-mono"
          />
        </div>

        <div className="pt-2 border-t mt-2">
          <label className="flex items-center gap-2 cursor-pointer font-bold text-gray-700">
            <input
              type="checkbox"
              checked={formData.enableRaspberryPiSync}
              onChange={(e) =>
                setFormData({ ...formData, enableRaspberryPiSync: e.target.checked })
              }
            />
            <span>Enable Raspberry Pi Local Server Intermediary (Future Support)</span>
          </label>
          <p className="text-[11px] text-gray-500 mt-1">
            When enabled, Windows Agent telemetry routes through the Raspberry Pi on the local LAN before syncing to Firebase.
          </p>
        </div>
      </div>
    </form>
  );
};
