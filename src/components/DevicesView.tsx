import React from 'react';
import { Device } from '../types';

interface DevicesViewProps {
  devices: Device[];
  onContainToggle: (deviceId: string) => void;
}

export const DevicesView: React.FC<DevicesViewProps> = ({
  devices,
  onContainToggle
}) => {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-bold text-gray-900 uppercase">Monitored Devices</h2>
        <p className="text-xs text-gray-500">Endpoints running the Python watchdog agent</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {devices.map((device) => {
          const isContained = device.status === 'CONTAINED';

          return (
            <div
              key={device.id}
              className={`bg-white border rounded p-4 space-y-3 ${
                isContained ? 'border-red-500 bg-red-50/30' : 'border-gray-300'
              }`}
            >
              <div className="flex items-start justify-between border-b pb-2">
                <div>
                  <h3 className="font-bold text-base text-gray-900">{device.hostname}</h3>
                  <div className="text-xs text-gray-500">{device.os} · IP: {device.ipAddress}</div>
                </div>

                <div className="text-right">
                  <span
                    className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${
                      isContained ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
                    }`}
                  >
                    {device.status}
                  </span>
                  <div className="text-xs font-bold text-gray-700 mt-1">
                    Risk: {device.riskScore}/100
                  </div>
                </div>
              </div>

              <div className="text-xs space-y-1">
                <div className="font-semibold text-gray-700">Monitored Folders:</div>
                {device.monitoredFolders.map((folder, idx) => (
                  <div
                    key={idx}
                    className="p-1 bg-gray-50 border rounded font-mono text-[11px] text-gray-700 truncate"
                  >
                    {folder}
                  </div>
                ))}
              </div>

              <div className="text-xs text-gray-500 pt-1">
                Last Heartbeat: {new Date(device.lastHeartbeat).toLocaleTimeString()}
              </div>

              <div className="pt-2 border-t flex justify-end">
                {isContained ? (
                  <button
                    onClick={() => onContainToggle(device.hostname)}
                    className="px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-xs font-bold rounded"
                  >
                    [RELEASE DEVICE]
                  </button>
                ) : (
                  <button
                    onClick={() => onContainToggle(device.hostname)}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-bold rounded"
                  >
                    [CONTAIN DEVICE]
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
