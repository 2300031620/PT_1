import React from 'react';
import {
  LayoutDashboard,
  AlertTriangle,
  FileCheck,
  Archive,
  Monitor,
  ScrollText,
  Settings,
  Shield
} from 'lucide-react';
import { DeviceStatus } from '../types';

export type TabKey =
  | 'dashboard'
  | 'incidents'
  | 'protected-files'
  | 'archives'
  | 'devices'
  | 'logs'
  | 'settings';

interface SidebarProps {
  activeTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  openIncidentsCount: number;
  deviceStatus: DeviceStatus;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  openIncidentsCount,
  deviceStatus
}) => {
  const items: { key: TabKey; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { key: 'incidents', label: 'Incidents', icon: AlertTriangle },
    { key: 'protected-files', label: 'Protected Files', icon: FileCheck },
    { key: 'archives', label: 'Archives', icon: Archive },
    { key: 'devices', label: 'Devices', icon: Monitor },
    { key: 'logs', label: 'Logs', icon: ScrollText },
    { key: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-56 bg-white border-r border-gray-300 flex flex-col h-screen shrink-0 text-gray-800">
      {/* Title */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-600" />
          <h1 className="font-bold text-sm text-gray-900 leading-tight">
            Ransomware System
          </h1>
        </div>
        <p className="text-xs text-gray-500 mt-1">Student Academic Project</p>
      </div>

      {/* Menu List */}
      <nav className="p-3 space-y-1 flex-1">
        {items.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.key;
          return (
            <button
              key={item.key}
              onClick={() => onSelectTab(item.key)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-sm text-left transition-colors ${
                isActive
                  ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-blue-600' : 'text-gray-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.key === 'incidents' && openIncidentsCount > 0 && (
                <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-bold border border-red-200">
                  {openIncidentsCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Endpoint status at bottom */}
      <div className="p-3 border-t border-gray-200 bg-gray-50 text-xs space-y-2">
        <div>
          <div className="text-gray-500">Target PC:</div>
          <div className="font-bold text-gray-800">WINDOWS-PC-01</div>
          <div className="mt-0.5">
            Status:{' '}
            <span
              className={`font-bold ${
                deviceStatus === 'CONTAINED'
                  ? 'text-red-600'
                  : 'text-green-700'
              }`}
            >
              {deviceStatus}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
};

