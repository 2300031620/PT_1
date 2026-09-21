import React from 'react';
import { Shield, Lock, Unlock, LogOut, User as UserIcon } from 'lucide-react';
import { DeviceStatus } from '../types';
import { useAuth } from '../context/AuthContext';

interface HeaderProps {
  title: string;
  deviceStatus: DeviceStatus;
  onContainToggle: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  deviceStatus,
  onContainToggle,
}) => {
  const { userProfile, role, logout } = useAuth();
  const isContained = deviceStatus === 'CONTAINED';

  return (
    <header className="bg-white border-b border-gray-300 px-6 py-3 flex items-center justify-between">
      <div>
        <h2 className="text-base font-bold text-gray-900">{title}</h2>
        <p className="text-xs text-gray-500">Academic Prototype · Windows Watchdog & Firebase</p>
      </div>

      <div className="flex items-center gap-4">
        {/* Simple manual contain / release buttons as required by the prompt */}
        {isContained ? (
          <button
            onClick={onContainToggle}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-xs font-bold rounded shadow-xs cursor-pointer"
          >
            <Unlock className="w-3.5 h-3.5" />
            [RELEASE DEVICE]
          </button>
        ) : (
          <button
            onClick={onContainToggle}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-bold rounded shadow-xs cursor-pointer"
          >
            <Lock className="w-3.5 h-3.5" />
            [CONTAIN DEVICE]
          </button>
        )}

        {/* User profile & role badge */}
        <div className="flex items-center gap-2 pl-3 border-l border-gray-300">
          <div className="flex flex-col text-right">
            <span className="text-xs font-bold text-gray-800 leading-tight">
              {userProfile?.email || 'User'}
            </span>
            <span
              className={`text-[10px] font-bold uppercase tracking-wider inline-block ${
                role === 'admin' ? 'text-purple-700' : 'text-blue-600'
              }`}
            >
              Role: {role}
            </span>
          </div>

          <button
            onClick={logout}
            title="Logout"
            className="flex items-center gap-1 px-2.5 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 hover:text-gray-900 text-xs font-semibold rounded border border-gray-300 transition-colors cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5 text-gray-600" />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
};

