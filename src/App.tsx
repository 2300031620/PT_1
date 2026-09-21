import React, { useState, useEffect } from 'react';
import { Loader2 } from 'lucide-react';
import { Sidebar, TabKey } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { IncidentsView } from './components/IncidentsView';
import { ProtectedFilesView } from './components/ProtectedFilesView';
import { ArchivesView } from './components/ArchivesView';
import { DevicesView } from './components/DevicesView';
import { LogsView } from './components/LogsView';
import { SettingsView } from './components/SettingsView';
import { LoginPage } from './components/LoginPage';
import { AuthProvider, useAuth } from './context/AuthContext';
import {
  SecurityService,
  DEFAULT_DEVICES,
  DEFAULT_PROTECTED_FILES,
  DEFAULT_EVENTS,
  DEFAULT_ARCHIVES,
  DEFAULT_AUDIT_LOGS
} from './firebase/services';
import {
  Device,
  SecurityEvent,
  Incident,
  ProtectedFile,
  ArchiveRecord,
  AuditLog,
  SystemSettings,
  IncidentStatus,
  FilePriority
} from './types';

const INITIAL_SETTINGS: SystemSettings = {
  monitoredFolders: [
    'C:\\Users\\User\\Documents',
    'C:\\Users\\User\\Desktop',
    'C:\\ProtectedFiles'
  ],
  rapidModThreshold: 5,
  massRenameThreshold: 4,
  massDeleteThreshold: 4,
  ransomwareExtensions: [
    '.locked',
    '.crypto',
    '.enc',
    '.crypted',
    '.ransom',
    '.wnry'
  ],
  backendApiUrl: 'http://localhost:8000/api',
  enableRaspberryPiSync: false,
  raspberryPiAddress: '192.168.1.150:8000'
};

function DashboardApp() {
  const { user, userProfile, role, loading } = useAuth();
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [devices, setDevices] = useState<Device[]>(DEFAULT_DEVICES);
  const [events, setEvents] = useState<SecurityEvent[]>(DEFAULT_EVENTS);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [protectedFiles, setProtectedFiles] = useState<ProtectedFile[]>(DEFAULT_PROTECTED_FILES);
  const [archives, setArchives] = useState<ArchiveRecord[]>(DEFAULT_ARCHIVES);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>(DEFAULT_AUDIT_LOGS);
  const [settings, setSettings] = useState<SystemSettings>(INITIAL_SETTINGS);

  const currentUserEmail = userProfile?.email || user?.email || 'authenticated-user';

  // Seed / sync all 7 Firestore collections on authenticated connection
  useEffect(() => {
    if (user || userProfile) {
      SecurityService.seedFirestoreCollections();
    }
  }, [user, userProfile]);

  // Subscribe to live data updates across all collections (Firestore + Local fallback)
  useEffect(() => {
    const unsubscribe = SecurityService.subscribeToData((data) => {
      if (data.devices.length) setDevices(data.devices);
      if (data.events.length) setEvents(data.events);
      setIncidents(data.incidents);
      if (data.protectedFiles.length) setProtectedFiles(data.protectedFiles);
      if (data.archives.length) setArchives(data.archives);
      if (data.auditLogs.length) setAuditLogs(data.auditLogs);
    });

    return () => {
      if (typeof unsubscribe === 'function') unsubscribe();
    };
  }, []);

  // Protected route enforcement
  if (loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-gray-100 font-sans">
        <div className="flex flex-col items-center gap-3 p-6 bg-white border border-gray-300 rounded shadow-xs">
          <Loader2 className="w-7 h-7 text-blue-600 animate-spin" />
          <span className="text-xs font-bold text-gray-700">Connecting to Firebase Defense System...</span>
        </div>
      </div>
    );
  }

  if (!user && !userProfile) {
    return <LoginPage />;
  }

  const activeDevice = devices[0] || DEFAULT_DEVICES[0];

  // Containment handlers
  const handleContainDevice = async (targetDeviceId?: string, reason?: string) => {
    const dev = targetDeviceId
      ? devices.find((d) => d.hostname === targetDeviceId || d.id === targetDeviceId) || activeDevice
      : activeDevice;
    const nowIso = new Date().toISOString();
    const containmentReason = reason || 'Manual prevention containment initiated by administrator';

    await SecurityService.setContainment(
      dev.hostname,
      true,
      containmentReason,
      currentUserEmail,
      role
    );

    setDevices((prev) =>
      prev.map((d) =>
        d.hostname === dev.hostname
          ? {
              ...d,
              status: 'CONTAINED',
              containedAt: nowIso,
              containmentReason,
              containedBy: `${currentUserEmail} (${role})`
            }
          : d
      )
    );
  };

  const handleReleaseDevice = async (targetDeviceId?: string) => {
    const dev = targetDeviceId
      ? devices.find((d) => d.hostname === targetDeviceId || d.id === targetDeviceId) || activeDevice
      : activeDevice;

    await SecurityService.setContainment(
      dev.hostname,
      false,
      undefined,
      currentUserEmail,
      role
    );

    setDevices((prev) =>
      prev.map((d) =>
        d.hostname === dev.hostname
          ? {
              ...d,
              status: 'PROTECTED',
              riskScore: Math.min(d.riskScore, 18),
              containedAt: undefined,
              containmentReason: undefined,
              containedBy: undefined
            }
          : d
      )
    );
  };

  const handleContainToggle = async (targetDeviceId?: string) => {
    const dev = targetDeviceId
      ? devices.find((d) => d.hostname === targetDeviceId || d.id === targetDeviceId) || activeDevice
      : activeDevice;
    if (dev.status === 'CONTAINED') {
      await handleReleaseDevice(dev.hostname);
    } else {
      await handleContainDevice(dev.hostname, 'Toggled containment via navigation bar');
    }
  };

  // Update incident status
  const handleUpdateIncidentStatus = async (incidentId: string, status: IncidentStatus) => {
    await SecurityService.updateIncidentStatus(incidentId, status, currentUserEmail);
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === incidentId ? { ...inc, status } : inc))
    );
  };

  // Add Protected File
  const handleAddProtectedFile = async (newFile: {
    name: string;
    path: string;
    priority: FilePriority;
    sha256: string;
    sizeBytes: number;
  }) => {
    const added = await SecurityService.addProtectedFile(newFile, currentUserEmail);
    setProtectedFiles((prev) => [...prev, added]);
  };

  // Remove Protected File
  const handleRemoveProtectedFile = async (id: string, name: string) => {
    await SecurityService.removeProtectedFile(id, name, currentUserEmail);
    setProtectedFiles((prev) => prev.filter((f) => f.id !== id));
  };

  // Create Archive
  const handleCreateArchive = async (selectedIds: string[], format: 'ZIP' | '7Z' = 'ZIP') => {
    const created = await SecurityService.createArchive(selectedIds, format, currentUserEmail);
    setArchives((prev) => [created, ...prev]);
    setActiveTab('archives');
  };

  // Save Settings
  const handleSaveSettings = async (newSettings: SystemSettings) => {
    setSettings(newSettings);
    await SecurityService.addAuditLog(
      'settings changed',
      currentUserEmail,
      activeDevice.hostname,
      'Updated thresholds and monitored paths'
    );
  };

  // Reset Demo to clean baseline
  const handleResetDemo = () => {
    SecurityService.resetDemoState();
    setDevices(DEFAULT_DEVICES);
    setEvents(DEFAULT_EVENTS);
    setIncidents([]);
    setProtectedFiles(DEFAULT_PROTECTED_FILES);
    setArchives(DEFAULT_ARCHIVES);
    setAuditLogs(DEFAULT_AUDIT_LOGS);
  };

  // Safe Academic Ransomware Simulation Trigger
  const handleTriggerSimulation = async (
    type:
      | 'NORMAL'
      | 'RAPID_MODS'
      | 'MASS_MODS'
      | 'RAPID_RENAMES'
      | 'MASS_DELETION'
      | 'PROTECTED_TAMPER'
      | 'SUSPICIOUS_EXTENSION'
      | 'EXCESSIVE_BURST'
  ) => {
    const now = new Date().toISOString();
    const newEventsToAdd: SecurityEvent[] = [];

    if (type === 'NORMAL') {
      const evt = await SecurityService.logSecurityEvent({
        deviceId: activeDevice.hostname,
        eventType: 'MODIFY',
        filePath: 'C:\\Users\\User\\Documents\\notes.txt',
        timestamp: now,
        isProtected: false,
        isSuspicious: false,
        details: 'User modified notes.txt via Notepad',
        processName: 'notepad.exe'
      });
      newEventsToAdd.push(evt);

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 15 } : d
        )
      );
    } else if (type === 'RAPID_MODS') {
      for (let i = 1; i <= 5; i++) {
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: 'MODIFY',
          filePath: `C:\\Users\\User\\Documents\\project_data_${i}.csv`,
          timestamp: new Date(Date.now() - (5 - i) * 300).toISOString(),
          isProtected: false,
          isSuspicious: true,
          details: 'Rapid modification burst detected across documents',
          processName: 'python.exe'
        });
        newEventsToAdd.push(evt);
      }

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 45 } : d
        )
      );
    } else if (type === 'MASS_MODS') {
      for (let i = 1; i <= 11; i++) {
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: 'MODIFY',
          filePath: `C:\\Users\\User\\Documents\\financial_ledger_${i}.xlsx`,
          timestamp: new Date(Date.now() - (11 - i) * 200).toISOString(),
          isProtected: false,
          isSuspicious: true,
          details: 'Mass file modifications detected across multiple folders',
          processName: 'bulk_script.exe'
        });
        newEventsToAdd.push(evt);
      }

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 75 } : d
        )
      );
    } else if (type === 'RAPID_RENAMES') {
      for (let i = 1; i <= 4; i++) {
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: 'RENAME',
          filePath: `C:\\Users\\User\\Documents\\archive_temp_${i}.bak`,
          oldPath: `C:\\Users\\User\\Documents\\archive_temp_${i}.dat`,
          timestamp: new Date(Date.now() - (4 - i) * 250).toISOString(),
          isProtected: false,
          isSuspicious: true,
          details: 'Rapid file renames in short window',
          processName: 'rename_utility.exe'
        });
        newEventsToAdd.push(evt);
      }

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 55 } : d
        )
      );
    } else if (type === 'MASS_DELETION') {
      for (let i = 1; i <= 4; i++) {
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: 'DELETE',
          filePath: `C:\\Users\\User\\Documents\\client_backup_${i}.tar`,
          timestamp: new Date(Date.now() - (4 - i) * 200).toISOString(),
          isProtected: false,
          isSuspicious: true,
          details: 'Mass deletion pattern detected',
          processName: 'cmd.exe'
        });
        newEventsToAdd.push(evt);
      }

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 65 } : d
        )
      );
    } else if (type === 'PROTECTED_TAMPER') {
      const evt = await SecurityService.logSecurityEvent({
        deviceId: activeDevice.hostname,
        eventType: 'MODIFY',
        filePath: 'C:\\ProtectedFiles\\database.sql',
        timestamp: now,
        isProtected: true,
        isSuspicious: true,
        details: 'Unauthorized modification attempt on prioritized file database.sql',
        processName: 'cmd.exe'
      });
      newEventsToAdd.push(evt);

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 70 } : d
        )
      );
    } else if (type === 'EXCESSIVE_BURST') {
      for (let i = 1; i <= 14; i++) {
        const isMod = i % 2 === 0;
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: isMod ? 'MODIFY' : 'CREATE',
          filePath: `C:\\Users\\User\\Documents\\burst_item_${i}.tmp`,
          timestamp: new Date(Date.now() - (14 - i) * 150).toISOString(),
          isProtected: false,
          isSuspicious: true,
          details: 'Excessive file activity burst detected within short period',
          processName: 'powershell.exe'
        });
        newEventsToAdd.push(evt);
      }

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname ? { ...d, riskScore: 65 } : d
        )
      );
    } else if (type === 'SUSPICIOUS_EXTENSION') {
      const targets = [
        'budget_2026.xlsx',
        'payroll_master.csv',
        'customer_records.db',
        'confidential_contract.docx',
        'project.zip',
        'database.sql'
      ];

      for (let i = 0; i < targets.length; i++) {
        const original = targets[i];
        const locked = `${original}.locked`;
        const evt = await SecurityService.logSecurityEvent({
          deviceId: activeDevice.hostname,
          eventType: 'RENAME',
          filePath: `C:\\Users\\User\\Documents\\${locked}`,
          oldPath: `C:\\Users\\User\\Documents\\${original}`,
          timestamp: new Date(Date.now() - (targets.length - i) * 200).toISOString(),
          isProtected: original === 'database.sql' || original === 'project.zip',
          isSuspicious: true,
          details: `Mass encryption signature: renamed to ${locked}`,
          processName: 'suspicious_payload.exe'
        });
        newEventsToAdd.push(evt);
      }

      // Calculate risk with detection engine
      const evalResult = SecurityService.evaluateRansomwareBehavior(
        [...newEventsToAdd, ...events],
        protectedFiles
      );

      // Create critical security incident
      const count = incidents.length + 1;
      const newIncident = await SecurityService.createIncident({
        incidentId: `INC-${String(count).padStart(3, '0')}`,
        riskScore: evalResult.risk_score,
        severity: 'CRITICAL',
        deviceId: activeDevice.hostname,
        filesAffected: targets.length,
        status: 'CONTAINED',
        reason: 'Mass files modified and renamed with .locked extension in short window',
        recommendedAction: 'CONTAIN',
        timestamp: new Date().toISOString()
      });

      setIncidents((prev) => [newIncident, ...prev]);

      // Execute containment on endpoint
      await SecurityService.setContainment(activeDevice.hostname, true, currentUserEmail);

      setDevices((prev) =>
        prev.map((d) =>
          d.hostname === activeDevice.hostname
            ? { ...d, status: 'CONTAINED', riskScore: evalResult.risk_score }
            : d
        )
      );
    }

    setEvents((prev) => [...newEventsToAdd, ...prev]);
  };

  const getTabTitle = (tab: TabKey) => {
    switch (tab) {
      case 'dashboard':
        return 'Dashboard Overview';
      case 'incidents':
        return 'Incident Management';
      case 'protected-files':
        return 'Protected Files Manager';
      case 'archives':
        return 'Archive Manager';
      case 'devices':
        return 'Monitored Devices';
      case 'logs':
        return 'Audit Logs';
      case 'settings':
        return 'System Settings';
    }
  };

  const openIncidentsCount = incidents.filter(
    (i) => i.status === 'OPEN' || i.status === 'INVESTIGATING'
  ).length;

  return (
    <div className="flex h-screen w-screen bg-gray-100 font-sans text-gray-800 overflow-hidden">
      {/* Simple Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        openIncidentsCount={openIncidentsCount}
        deviceStatus={activeDevice.status}
      />

      {/* Main Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Header
          title={getTabTitle(activeTab)}
          deviceStatus={activeDevice.status}
          onContainToggle={() => handleContainToggle()}
        />

        <main className="flex-1 overflow-y-auto p-5">
          <div className="max-w-5xl mx-auto">
            {activeTab === 'dashboard' && (
              <DashboardView
                device={activeDevice}
                events={events}
                incidents={incidents}
                protectedFiles={protectedFiles}
                onContainToggle={() => handleContainToggle()}
                onContainDevice={handleContainDevice}
                onReleaseDevice={handleReleaseDevice}
                onTriggerSimulation={handleTriggerSimulation}
                onResetDemo={handleResetDemo}
                onNavigateTab={(t) => setActiveTab(t)}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentsView
                incidents={incidents}
                onUpdateStatus={handleUpdateIncidentStatus}
                onContainToggle={() => handleContainToggle()}
              />
            )}

            {activeTab === 'protected-files' && (
              <ProtectedFilesView
                files={protectedFiles}
                onAddFile={handleAddProtectedFile}
                onRemoveFile={handleRemoveProtectedFile}
                onCreateArchive={handleCreateArchive}
              />
            )}

            {activeTab === 'archives' && (
              <ArchivesView
                archives={archives}
                protectedFiles={protectedFiles}
                onCreateArchive={handleCreateArchive}
              />
            )}

            {activeTab === 'devices' && (
              <DevicesView
                devices={devices}
                onContainToggle={handleContainToggle}
              />
            )}

            {activeTab === 'logs' && <LogsView logs={auditLogs} />}

            {activeTab === 'settings' && (
              <SettingsView
                settings={settings}
                onSaveSettings={handleSaveSettings}
                userRole={role}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <DashboardApp />
    </AuthProvider>
  );
}

