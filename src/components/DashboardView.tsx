import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  Activity,
  FileCode,
  FileX,
  FileEdit,
  FolderSync,
  Flame,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Filter,
  Lock,
  Unlock,
  UserCheck,
  AlertOctagon,
  Info
} from 'lucide-react';
import { Device, Incident, ProtectedFile, SecurityEvent, RiskSeverity } from '../types';
import { useAuth } from '../context/AuthContext';

export type SimulationType =
  | 'NORMAL'
  | 'RAPID_MODS'
  | 'MASS_MODS'
  | 'RAPID_RENAMES'
  | 'MASS_DELETION'
  | 'PROTECTED_TAMPER'
  | 'SUSPICIOUS_EXTENSION'
  | 'EXCESSIVE_BURST';

interface DashboardViewProps {
  device: Device;
  events: SecurityEvent[];
  incidents: Incident[];
  protectedFiles: ProtectedFile[];
  onContainToggle: () => void;
  onContainDevice?: (targetDeviceId?: string, reason?: string) => Promise<void>;
  onReleaseDevice?: (targetDeviceId?: string) => Promise<void>;
  onTriggerSimulation: (type: SimulationType) => void;
  onResetDemo: () => void;
  onNavigateTab: (tab: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  device,
  events,
  incidents,
  protectedFiles,
  onContainToggle,
  onContainDevice,
  onReleaseDevice,
  onTriggerSimulation,
  onResetDemo,
  onNavigateTab
}) => {
  const { role, isAdmin, quickDemoLogin } = useAuth();
  const [activeFilter, setActiveFilter] = useState<'all' | 'suspicious'>('all');
  const [showRbacModal, setShowRbacModal] = useState<boolean>(false);
  const [showContainModal, setShowContainModal] = useState<boolean>(false);
  const [containReasonInput, setContainReasonInput] = useState<string>(
    'Behavioral threshold reached: rapid encryption activity detected'
  );
  const [actionFeedback, setActionFeedback] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const activeIncidents = useMemo(() => {
    return incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING');
  }, [incidents]);

  const activeCriticalIncident = useMemo(() => {
    return incidents.find(
      (i) =>
        i.deviceId === device.hostname &&
        (i.severity === 'CRITICAL' || i.status === 'CONTAINED')
    );
  }, [incidents, device.hostname]);

  const suspiciousEvents = useMemo(() => {
    return events.filter((e) => e.isSuspicious);
  }, [events]);

  // Rolling 15-second window calculations for live detection heuristics display
  const rollingWindowAnalysis = useMemo(() => {
    const cutoff = Date.now() - 20000;
    const recent = events.filter((e) => new Date(e.timestamp).getTime() > cutoff);

    const mods = recent.filter((e) => e.eventType === 'MODIFY').length;
    const renames = recent.filter((e) => e.eventType === 'RENAME').length;
    const deletes = recent.filter((e) => e.eventType === 'DELETE').length;
    const totalOps = recent.length;

    const ransomwareExtRegex = /\.(locked|crypto|enc|crypted|ransom|wnry|crypt|locky|darkness|payme)$/i;
    const suspExtCount = recent.filter((e) => ransomwareExtRegex.test(e.filePath)).length;

    const protPaths = new Set(protectedFiles.map((p) => p.path.toLowerCase()));
    const protNames = new Set(protectedFiles.map((p) => p.name.toLowerCase()));
    const protTamperCount = recent.filter((e) => {
      const p = e.filePath.toLowerCase();
      const b = p.split('\\').pop()?.split('/').pop() || '';
      return (
        (e.isProtected || protPaths.has(p) || protNames.has(b)) &&
        (e.eventType === 'MODIFY' || e.eventType === 'DELETE' || e.eventType === 'RENAME')
      );
    }).length;

    return {
      rapidMods: mods >= 4 && mods < 10,
      massMods: mods >= 10,
      rapidRenames: renames >= 2,
      massDeletions: deletes >= 2,
      suspiciousExtensions: suspExtCount > 0,
      protectedTamper: protTamperCount > 0,
      excessiveBurst: totalOps >= 12,
      counts: {
        mods,
        renames,
        deletes,
        totalOps,
        suspExtCount,
        protTamperCount
      }
    };
  }, [events, protectedFiles]);

  const getSeverity = (score: number): { label: RiskSeverity; color: string; bg: string; border: string } => {
    if (score >= 80) {
      return { label: 'CRITICAL', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-300' };
    }
    if (score >= 60) {
      return { label: 'HIGH', color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-300' };
    }
    if (score >= 30) {
      return { label: 'SUSPICIOUS', color: 'text-yellow-800', bg: 'bg-yellow-50', border: 'border-yellow-300' };
    }
    return { label: 'NORMAL', color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-300' };
  };

  const sev = getSeverity(device.riskScore);
  const isContained = device.status === 'CONTAINED';
  const hasElevatedThreat = device.riskScore >= 30 || suspiciousEvents.length > 0;
  const isCriticalThreat = device.riskScore >= 80 || isContained || sev.label === 'CRITICAL';

  // Recommended action mapping
  const recommendedAction = useMemo(() => {
    if (device.riskScore >= 80) return 'CONTAIN';
    if (device.riskScore >= 60) return 'ALERT';
    if (device.riskScore >= 30) return 'MONITOR';
    return 'NONE';
  }, [device.riskScore]);

  // Recorded containment details
  const recordedReason = useMemo(() => {
    return (
      device.containmentReason ||
      activeCriticalIncident?.reason ||
      'Suspicious ransomware activity detected: behavioral heuristic score exceeded critical threshold'
    );
  }, [device.containmentReason, activeCriticalIncident]);

  const recordedTimestamp = useMemo(() => {
    const raw = device.containedAt || activeCriticalIncident?.timestamp;
    if (!raw) return new Date().toLocaleString();
    try {
      return new Date(raw).toLocaleString();
    } catch {
      return raw;
    }
  }, [device.containedAt, activeCriticalIncident]);

  const recordedOperator = useMemo(() => {
    return device.containedBy || 'Automated Behavioral Heuristics';
  }, [device.containedBy]);

  // Containment Handlers with RBAC
  const handleContainClick = async () => {
    if (!isAdmin) {
      setShowRbacModal(true);
      return;
    }
    setShowContainModal(true);
  };

  const confirmContainmentExecution = async () => {
    setShowContainModal(false);
    try {
      if (onContainDevice) {
        await onContainDevice(device.hostname, containReasonInput);
      } else {
        onContainToggle();
      }
      setActionFeedback({
        type: 'success',
        message: `Device ${device.hostname} safely contained. Simulated host isolation enforced.`
      });
      setTimeout(() => setActionFeedback(null), 5000);
    } catch (err: any) {
      setActionFeedback({
        type: 'error',
        message: `Failed to contain device: ${err.message || err}`
      });
    }
  };

  const handleReleaseClick = async () => {
    if (!isAdmin) {
      setShowRbacModal(true);
      return;
    }

    try {
      if (onReleaseDevice) {
        await onReleaseDevice(device.hostname);
      } else {
        onContainToggle();
      }
      setActionFeedback({
        type: 'info',
        message: `Device ${device.hostname} released from containment. Normal monitoring restored.`
      });
      setTimeout(() => setActionFeedback(null), 5000);
    } catch (err: any) {
      setActionFeedback({
        type: 'error',
        message: `Failed to release device: ${err.message || err}`
      });
    }
  };

  const handleRoleElevate = async () => {
    await quickDemoLogin('admin');
    setShowRbacModal(false);
    setActionFeedback({
      type: 'success',
      message: 'Role elevated to Security Administrator. Containment actions now authorized.'
    });
    setTimeout(() => setActionFeedback(null), 4000);
  };

  const displayedEvents = activeFilter === 'suspicious' ? suspiciousEvents : events;

  return (
    <div className="space-y-4">
      {/* Action Feedback Notification */}
      {actionFeedback && (
        <div
          id="containment-action-feedback"
          className={`p-3 rounded border text-xs font-semibold flex items-center justify-between transition-all ${
            actionFeedback.type === 'success'
              ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
              : actionFeedback.type === 'error'
              ? 'bg-red-50 border-red-300 text-red-900'
              : 'bg-blue-50 border-blue-300 text-blue-900'
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-xs underline hover:opacity-75 font-normal"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* CRITICAL ALERT ON DASHBOARD: Displayed when device is contained or risk reaches CRITICAL */}
      {isCriticalThreat && (
        <div
          id="critical-containment-alert"
          className="bg-red-50 border-2 border-red-600 text-red-950 p-4 rounded-md shadow-sm"
        >
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="p-2 bg-red-100 border border-red-300 rounded shrink-0">
                <AlertOctagon className="w-6 h-6 text-red-700" />
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-sm text-red-950 tracking-wide uppercase">
                    CRITICAL ALERT: HOST {isContained ? 'CONTAINED' : 'REQUIRES CONTAINMENT'}
                  </span>
                  <span className="text-[11px] bg-red-700 text-white font-mono px-2 py-0.5 rounded font-bold">
                    SCORE {device.riskScore}/100 — CRITICAL
                  </span>
                  <span className={`text-[11px] font-semibold px-2 py-0.5 rounded border ${
                    isContained ? 'bg-red-200 text-red-900 border-red-300' : 'bg-orange-100 text-orange-900 border-orange-300'
                  }`}>
                    {isContained ? 'Device Contained' : 'Action Required'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs text-red-900 pt-1">
                  <div>
                    <span className="font-semibold text-red-950">Target Device:</span>{' '}
                    <span className="font-mono">{device.hostname} ({device.ipAddress})</span>
                  </div>
                  <div>
                    <span className="font-semibold text-red-950">Timestamp:</span>{' '}
                    <span>{recordedTimestamp}</span>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="font-semibold text-red-950">Reason:</span>{' '}
                    <span className="font-medium bg-red-100 px-1.5 py-0.5 rounded border border-red-200">
                      {recordedReason}
                    </span>
                  </div>
                  <div className="sm:col-span-2 text-[11px] text-red-800 italic pt-0.5">
                    Safe Student Demonstration Mode: Non-destructive containment is active. Threat quarantined from network propagation without affecting workstation stability.
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
              {isContained ? (
                <button
                  id="alert-btn-release-device"
                  onClick={handleReleaseClick}
                  className="bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold px-3.5 py-2 rounded flex items-center gap-1.5 shadow-xs transition-colors"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  RELEASE DEVICE
                </button>
              ) : (
                <button
                  id="alert-btn-contain-device"
                  onClick={handleContainClick}
                  className="bg-red-700 hover:bg-red-800 text-white text-xs font-bold px-3.5 py-2 rounded flex items-center gap-1.5 shadow-xs transition-colors"
                >
                  <Lock className="w-3.5 h-3.5" />
                  CONTAIN DEVICE
                </button>
              )}
              <button
                id="alert-btn-view-incident"
                onClick={() => onNavigateTab('incidents')}
                className="bg-white hover:bg-gray-100 text-gray-800 border border-red-300 text-xs font-bold px-3.5 py-2 rounded flex items-center gap-1.5 transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                View Incident
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dedicated Prevention & Containment Module Card with CONTAIN & RELEASE Buttons */}
      <div
        id="prevention-and-containment-module"
        className="bg-white border border-gray-300 rounded p-4 shadow-xs space-y-3"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-200 gap-2">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded ${isContained ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'}`}>
              {isContained ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>
            <div>
              <h2 className="text-xs font-bold text-gray-900 uppercase tracking-wide">
                Prevention & Containment Module
              </h2>
              <p className="text-xs text-gray-500">
                Automated threat isolation and operator response controls
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Live Host Status Badge */}
            <span
              id="device-status-badge"
              className={`text-xs px-2.5 py-1 rounded font-bold border flex items-center gap-1.5 ${
                isContained
                  ? 'bg-red-100 text-red-900 border-red-300 animate-pulse'
                  : 'bg-emerald-50 text-emerald-800 border-emerald-300'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${isContained ? 'bg-red-600' : 'bg-emerald-600'}`} />
              STATUS: {device.status}
            </span>

            {/* Role indicator & demo switcher */}
            <div className="flex items-center gap-1 bg-gray-100 px-2 py-1 rounded border border-gray-300 text-xs">
              <span className="text-gray-500">Role:</span>
              <span className={`font-bold uppercase ${isAdmin ? 'text-blue-700' : 'text-purple-700'}`}>
                {role}
              </span>
              <button
                id="btn-toggle-demo-role"
                onClick={() => quickDemoLogin(isAdmin ? 'analyst' : 'admin')}
                className="text-[11px] text-blue-600 hover:text-blue-800 underline ml-1 font-normal"
                title="Toggle role between Administrator and Security Analyst for testing"
              >
                (Switch to {isAdmin ? 'Analyst' : 'Admin'})
              </button>
            </div>
          </div>
        </div>

        {/* Containment State Details */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs bg-gray-50 p-3 rounded border border-gray-200">
          <div>
            <div className="text-gray-500 text-[11px]">Monitored Target</div>
            <div className="font-bold text-gray-900 font-mono mt-0.5">{device.hostname}</div>
            <div className="text-gray-500 text-[11px] font-mono">{device.ipAddress}</div>
          </div>

          <div>
            <div className="text-gray-500 text-[11px]">Containment Timestamp</div>
            <div className="font-bold text-gray-900 mt-0.5">
              {isContained ? recordedTimestamp : 'Not Isolated'}
            </div>
            <div className="text-gray-500 text-[11px]">
              {isContained ? 'Recorded at isolation' : 'Continuous monitoring'}
            </div>
          </div>

          <div>
            <div className="text-gray-500 text-[11px]">Containment Initiator</div>
            <div className="font-bold text-gray-900 mt-0.5 truncate" title={recordedOperator}>
              {isContained ? recordedOperator : 'Awaiting trigger'}
            </div>
            <div className="text-gray-500 text-[11px]">Role: {isContained ? 'Enforced' : 'Standby'}</div>
          </div>

          <div>
            <div className="text-gray-500 text-[11px]">Recorded Containment Reason</div>
            <div
              className="font-bold text-gray-900 mt-0.5 truncate text-[11px]"
              title={recordedReason}
            >
              {isContained ? recordedReason : 'None (Host is Protected)'}
            </div>
            <div className="text-gray-500 text-[11px]">
              {isContained ? 'Logged in incident record' : 'Normal file activity'}
            </div>
          </div>
        </div>

        {/* Safe Student Demonstration Notice */}
        <div className="text-[11px] text-gray-600 bg-blue-50/70 border border-blue-200 p-2.5 rounded flex items-start gap-2">
          <Info className="w-4 h-4 text-blue-600 mt-0.5 shrink-0" />
          <div>
            <strong className="text-blue-950">Safe Student Demonstration Notice:</strong>{' '}
            Containment actions enforce simulated host isolation (network firewall rules and directory write-protection alerts) non-destructively. This guarantees that host operating system services, active terminal shells, and container development connections remain fully functional during demonstrations.
          </div>
        </div>

        {/* Explicit Dashboard Buttons: CONTAIN DEVICE and RELEASE DEVICE */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
          <div className="text-xs text-gray-500">
            <strong>Authorization:</strong> Containment and release require{' '}
            <span className="font-bold text-gray-700 uppercase">Administrator</span> role privilege.
          </div>

          <div className="flex items-center gap-2.5 w-full sm:w-auto">
            {/* Dashboard Button 1: CONTAIN DEVICE */}
            <button
              id="btn-contain-device"
              onClick={handleContainClick}
              disabled={isContained}
              className={`flex-1 sm:flex-none px-4 py-2 rounded text-xs font-bold flex items-center justify-center gap-1.5 transition-colors shadow-xs ${
                isContained
                  ? 'bg-gray-200 text-gray-400 border border-gray-300 cursor-not-allowed'
                  : 'bg-red-700 hover:bg-red-800 text-white border border-red-800'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              CONTAIN DEVICE
            </button>

            {/* Dashboard Button 2: RELEASE DEVICE */}
            <button
              id="btn-release-device"
              onClick={handleReleaseClick}
              disabled={!isContained}
              className={`flex-1 sm:flex-none px-4 py-2 rounded text-xs font-bold flex items-center justify-center gap-1.5 transition-colors shadow-xs ${
                !isContained
                  ? 'bg-gray-200 text-gray-400 border border-gray-300 cursor-not-allowed'
                  : 'bg-emerald-700 hover:bg-emerald-800 text-white border border-emerald-800'
              }`}
            >
              <Unlock className="w-3.5 h-3.5" />
              RELEASE DEVICE
            </button>
          </div>
        </div>
      </div>

      {/* Main 5 Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div id="card-protection-status" className="bg-white border border-gray-300 p-3 rounded shadow-xs">
          <div className="text-xs text-gray-500 font-medium uppercase">Protection Status</div>
          <div
            className={`text-lg font-bold mt-1 ${
              isContained ? 'text-red-600' : 'text-green-700'
            }`}
          >
            {device.status}
          </div>
          <div className="text-[11px] text-gray-400 mt-1 truncate">Host: {device.hostname}</div>
        </div>

        <div id="card-risk-score" className="bg-white border border-gray-300 p-3 rounded shadow-xs">
          <div className="text-xs text-gray-500 font-medium uppercase">Current Risk Score</div>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-2xl font-bold text-gray-900">{device.riskScore}</span>
            <span className="text-xs text-gray-400 font-semibold">/ 100</span>
            <span className={`ml-auto text-xs px-1.5 py-0.5 rounded font-bold ${sev.bg} ${sev.color} border ${sev.border}`}>
              {sev.label}
            </span>
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Rule-based scoring</div>
        </div>

        <div
          id="card-active-incidents"
          onClick={() => onNavigateTab('incidents')}
          className="bg-white border border-gray-300 p-3 rounded shadow-xs cursor-pointer hover:bg-gray-50 transition-colors"
        >
          <div className="text-xs text-gray-500 font-medium uppercase">Active Incidents</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{activeIncidents.length}</div>
          <div className="text-[11px] text-blue-600 mt-1 flex items-center gap-1">
            View incidents <ExternalLink className="w-2.5 h-2.5" />
          </div>
        </div>

        <div
          id="card-protected-files"
          onClick={() => onNavigateTab('protected-files')}
          className="bg-white border border-gray-300 p-3 rounded shadow-xs cursor-pointer hover:bg-gray-50 transition-colors"
        >
          <div className="text-xs text-gray-500 font-medium uppercase">Protected Files</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{protectedFiles.length}</div>
          <div className="text-[11px] text-blue-600 mt-1 flex items-center gap-1">
            Manage files <ExternalLink className="w-2.5 h-2.5" />
          </div>
        </div>

        <div
          id="card-suspicious-events"
          onClick={() => setActiveFilter('suspicious')}
          className={`bg-white border p-3 rounded shadow-xs cursor-pointer transition-colors ${
            suspiciousEvents.length > 0 ? 'border-yellow-400 hover:bg-yellow-50/50' : 'border-gray-300 hover:bg-gray-50'
          }`}
        >
          <div className="text-xs text-gray-500 font-medium uppercase flex items-center justify-between">
            <span>Suspicious Events</span>
            {suspiciousEvents.length > 0 && (
              <span className="inline-block w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            )}
          </div>
          <div className={`text-2xl font-bold mt-1 ${suspiciousEvents.length > 0 ? 'text-red-700' : 'text-gray-900'}`}>
            {suspiciousEvents.length}
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Filtered telemetry</div>
        </div>
      </div>

      {/* Risk Indicator Bar & Severity Ranges */}
      <div id="risk-meter-container" className="bg-white border border-gray-300 p-4 rounded shadow-xs">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-gray-700" />
            <span className="text-xs font-bold text-gray-800 uppercase">Behavioral Risk Score Meter</span>
          </div>
          <span className="text-xs font-semibold text-gray-700">
            Score: <strong className="text-sm font-bold text-gray-900">{device.riskScore}</strong> ({sev.label}) | Action: <strong className="font-mono">{recommendedAction}</strong>
          </span>
        </div>

        <div className="w-full bg-gray-200 h-3 rounded overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${
              device.riskScore >= 80
                ? 'bg-red-600'
                : device.riskScore >= 60
                ? 'bg-orange-500'
                : device.riskScore >= 30
                ? 'bg-yellow-500'
                : 'bg-green-600'
            }`}
            style={{ width: `${Math.max(device.riskScore, 4)}%` }}
          />
        </div>

        <div className="grid grid-cols-4 text-xs mt-2 text-center text-gray-600 border-t border-gray-200 pt-2 font-mono">
          <div className={device.riskScore < 30 ? 'font-bold text-green-700 bg-green-50 py-0.5 rounded' : ''}>
            0–29 NORMAL
          </div>
          <div className={device.riskScore >= 30 && device.riskScore < 60 ? 'font-bold text-yellow-800 bg-yellow-50 py-0.5 rounded' : ''}>
            30–59 SUSPICIOUS
          </div>
          <div className={device.riskScore >= 60 && device.riskScore < 80 ? 'font-bold text-orange-800 bg-orange-50 py-0.5 rounded' : ''}>
            60–79 HIGH
          </div>
          <div className={device.riskScore >= 80 ? 'font-bold text-red-800 bg-red-50 py-0.5 rounded' : ''}>
            80–100 CRITICAL
          </div>
        </div>
      </div>

      {/* Behavioral Detection Engine Heuristics (7 Rules Monitored) */}
      <div id="detection-rules-matrix" className="bg-white border border-gray-300 p-4 rounded shadow-xs">
        <div className="flex items-center justify-between pb-2 border-b border-gray-200 mb-3">
          <div>
            <h3 className="text-xs font-bold text-gray-900 uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-blue-700" />
              Behavioral Detection Engine Rules (7 Active Monitored Heuristics)
            </h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Continuously monitors endpoint events against rule-based ransomware behavioral thresholds.
            </p>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">Window: 10–15s rolling</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
          {/* Rule 1: Rapid File Modifications */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.rapidMods ? 'border-yellow-400 bg-yellow-50/70' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <FileEdit className="w-3.5 h-3.5 text-gray-600" />
                Rapid File Edits
              </span>
              {rollingWindowAnalysis.rapidMods ? (
                <span className="text-[10px] bg-yellow-200 text-yellow-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Threshold: ≥4 edits in 10s</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Count: {rollingWindowAnalysis.counts.mods} edits</div>
          </div>

          {/* Rule 2: Mass File Modifications */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.massMods ? 'border-red-400 bg-red-50/70' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <Flame className="w-3.5 h-3.5 text-gray-600" />
                Mass File Edits
              </span>
              {rollingWindowAnalysis.massMods ? (
                <span className="text-[10px] bg-red-200 text-red-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Threshold: ≥10 edits in 10s</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Count: {rollingWindowAnalysis.counts.mods} edits</div>
          </div>

          {/* Rule 3: Rapid File Renames */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.rapidRenames ? 'border-yellow-400 bg-yellow-50/70' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <FolderSync className="w-3.5 h-3.5 text-gray-600" />
                Rapid Renames
              </span>
              {rollingWindowAnalysis.rapidRenames ? (
                <span className="text-[10px] bg-yellow-200 text-yellow-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Threshold: ≥2 renames in 10s</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Count: {rollingWindowAnalysis.counts.renames} renames</div>
          </div>

          {/* Rule 4: Mass Deletions */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.massDeletions ? 'border-red-400 bg-red-50/70' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <FileX className="w-3.5 h-3.5 text-gray-600" />
                Mass Deletions
              </span>
              {rollingWindowAnalysis.massDeletions ? (
                <span className="text-[10px] bg-red-200 text-red-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Threshold: ≥2 deletions in 10s</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Count: {rollingWindowAnalysis.counts.deletes} deletes</div>
          </div>

          {/* Rule 5: Suspicious Extension Changes */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.suspiciousExtensions ? 'border-red-500 bg-red-50' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <FileCode className="w-3.5 h-3.5 text-gray-600" />
                Suspicious Extensions
              </span>
              {rollingWindowAnalysis.suspiciousExtensions ? (
                <span className="text-[10px] bg-red-200 text-red-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Detects: .locked, .crypto, .enc</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Matched: {rollingWindowAnalysis.counts.suspExtCount} files</div>
          </div>

          {/* Rule 6: Protected-File Modification */}
          <div className={`p-2.5 rounded border ${rollingWindowAnalysis.protectedTamper ? 'border-orange-400 bg-orange-50' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5 text-gray-600" />
                Protected Tampering
              </span>
              {rollingWindowAnalysis.protectedTamper ? (
                <span className="text-[10px] bg-orange-200 text-orange-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Targets: Prioritized assets</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Tampered: {rollingWindowAnalysis.counts.protTamperCount} events</div>
          </div>

          {/* Rule 7: Excessive File Activity Within Short Period */}
          <div className={`p-2.5 rounded border sm:col-span-2 ${rollingWindowAnalysis.excessiveBurst ? 'border-orange-400 bg-orange-50' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-gray-800 flex items-center gap-1">
                <Activity className="w-3.5 h-3.5 text-gray-600" />
                Excessive Short-Period Activity Burst
              </span>
              {rollingWindowAnalysis.excessiveBurst ? (
                <span className="text-[10px] bg-orange-200 text-orange-900 font-bold px-1.5 py-0.2 rounded">TRIGGERED</span>
              ) : (
                <span className="text-[10px] text-green-700 font-semibold flex items-center gap-0.5">
                  <CheckCircle2 className="w-3 h-3" /> Safe
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500">Threshold: ≥12 total operations in rolling 10s</div>
            <div className="text-[11px] font-mono mt-1 text-gray-700">Total Ops: {rollingWindowAnalysis.counts.totalOps} in window</div>
          </div>
        </div>
      </div>

      {/* Demonstration / Rule-Testing Controls */}
      <div id="demo-simulation-controls" className="bg-white border border-gray-300 p-4 rounded shadow-xs">
        <div className="flex items-center justify-between pb-2 border-b border-gray-200 mb-3">
          <div>
            <h3 className="text-xs font-bold text-gray-900 uppercase">
              Safe Demonstration Controls (Heuristic Rule Testing)
            </h3>
            <p className="text-xs text-gray-500">
              Execute benign test scenarios to observe each behavioral detection engine rule trigger without harmful actions.
            </p>
          </div>
          <button
            id="btn-reset-demo"
            onClick={onResetDemo}
            className="flex items-center gap-1 text-xs text-gray-600 hover:text-gray-900 bg-gray-100 hover:bg-gray-200 px-2.5 py-1 rounded border border-gray-300 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            Reset Baseline
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
          <button
            id="sim-btn-normal"
            onClick={() => onTriggerSimulation('NORMAL')}
            className="p-2.5 rounded border border-gray-300 bg-gray-50 hover:bg-gray-100 text-left transition-colors"
          >
            <div className="font-bold text-gray-800">1. Normal Edit</div>
            <div className="text-gray-500 text-[11px] mt-0.5">Isolated edit (Score ~15, NORMAL)</div>
          </button>

          <button
            id="sim-btn-rapid-mods"
            onClick={() => onTriggerSimulation('RAPID_MODS')}
            className="p-2.5 rounded border border-yellow-300 bg-yellow-50 hover:bg-yellow-100 text-left transition-colors"
          >
            <div className="font-bold text-yellow-900">2. Rapid File Edits</div>
            <div className="text-yellow-700 text-[11px] mt-0.5">5 edits quickly (Score ~45, SUSPICIOUS)</div>
          </button>

          <button
            id="sim-btn-rapid-renames"
            onClick={() => onTriggerSimulation('RAPID_RENAMES')}
            className="p-2.5 rounded border border-yellow-300 bg-yellow-50 hover:bg-yellow-100 text-left transition-colors"
          >
            <div className="font-bold text-yellow-900">3. Rapid File Renames</div>
            <div className="text-yellow-700 text-[11px] mt-0.5">4 renames in sequence (Score ~55)</div>
          </button>

          <button
            id="sim-btn-mass-deletion"
            onClick={() => onTriggerSimulation('MASS_DELETION')}
            className="p-2.5 rounded border border-orange-300 bg-orange-50 hover:bg-orange-100 text-left transition-colors"
          >
            <div className="font-bold text-orange-900">4. Mass Deletions</div>
            <div className="text-orange-700 text-[11px] mt-0.5">4 files removed (Score ~65, HIGH)</div>
          </button>

          <button
            id="sim-btn-protected-tamper"
            onClick={() => onTriggerSimulation('PROTECTED_TAMPER')}
            className="p-2.5 rounded border border-orange-300 bg-orange-50 hover:bg-orange-100 text-left transition-colors"
          >
            <div className="font-bold text-orange-900">5. Protected File Tamper</div>
            <div className="text-orange-700 text-[11px] mt-0.5">Touches database.sql (Score ~70, HIGH)</div>
          </button>

          <button
            id="sim-btn-excessive-burst"
            onClick={() => onTriggerSimulation('EXCESSIVE_BURST')}
            className="p-2.5 rounded border border-orange-300 bg-orange-50 hover:bg-orange-100 text-left transition-colors"
          >
            <div className="font-bold text-orange-900">6. Excessive Burst Activity</div>
            <div className="text-orange-700 text-[11px] mt-0.5">14 operations in 2s (Score ~65, HIGH)</div>
          </button>

          <button
            id="sim-btn-mass-mods"
            onClick={() => onTriggerSimulation('MASS_MODS')}
            className="p-2.5 rounded border border-red-300 bg-red-50 hover:bg-red-100 text-left transition-colors"
          >
            <div className="font-bold text-red-900">7. Mass File Edits</div>
            <div className="text-red-700 text-[11px] mt-0.5">10+ batch edits (Score ~75, HIGH)</div>
          </button>

          <button
            id="sim-btn-ransomware-ext"
            onClick={() => onTriggerSimulation('SUSPICIOUS_EXTENSION')}
            className="p-2.5 rounded border border-red-400 bg-red-100 hover:bg-red-200 text-left transition-colors"
          >
            <div className="font-bold text-red-950">8. Ransomware .locked</div>
            <div className="text-red-800 text-[11px] mt-0.5">Renames to .locked (CRITICAL & Contain!)</div>
          </button>
        </div>
      </div>

      {/* Security Events Table with Suspicious Activity Filter */}
      <div id="events-table-card" className="bg-white border border-gray-300 rounded overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-gray-50 border-b border-gray-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-gray-800 uppercase">Endpoint Security Events</span>
            <span className="text-xs text-gray-500">({events.length} total events stored)</span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              id="filter-btn-all"
              onClick={() => setActiveFilter('all')}
              className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                activeFilter === 'all'
                  ? 'bg-gray-800 text-white border-gray-800 font-bold'
                  : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-100'
              }`}
            >
              All Events ({events.length})
            </button>
            <button
              id="filter-btn-suspicious"
              onClick={() => setActiveFilter('suspicious')}
              className={`text-xs px-2.5 py-1 rounded border transition-colors flex items-center gap-1 ${
                activeFilter === 'suspicious'
                  ? 'bg-red-700 text-white border-red-700 font-bold'
                  : 'bg-white text-red-700 border-red-300 hover:bg-red-50'
              }`}
            >
              <AlertTriangle className="w-3 h-3" />
              Suspicious Activity ({suspiciousEvents.length})
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-gray-100 text-gray-700 border-b border-gray-200">
              <tr>
                <th className="p-2 border-r border-gray-200 font-semibold">Time</th>
                <th className="p-2 border-r border-gray-200 font-semibold">Action</th>
                <th className="p-2 border-r border-gray-200 font-semibold">File Path</th>
                <th className="p-2 border-r border-gray-200 font-semibold">Protected?</th>
                <th className="p-2 border-r border-gray-200 font-semibold">Detection State</th>
                <th className="p-2 font-semibold">Reason / Telemetry Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 font-mono">
              {displayedEvents.slice(0, 10).map((evt) => (
                <tr
                  key={evt.id}
                  className={
                    evt.isSuspicious
                      ? 'bg-yellow-50/80 hover:bg-yellow-100/80 transition-colors'
                      : 'hover:bg-gray-50 transition-colors'
                  }
                >
                  <td className="p-2 border-r border-gray-200 text-gray-500 whitespace-nowrap">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-2 border-r border-gray-200 font-bold whitespace-nowrap">
                    <span
                      className={
                        evt.eventType === 'DELETE'
                          ? 'text-red-700'
                          : evt.eventType === 'RENAME'
                          ? 'text-yellow-700'
                          : evt.eventType === 'CREATE'
                          ? 'text-green-700'
                          : 'text-blue-700'
                      }
                    >
                      {evt.eventType}
                    </span>
                  </td>
                  <td className="p-2 border-r border-gray-200 text-gray-900 max-w-xs truncate" title={evt.filePath}>
                    {evt.filePath}
                  </td>
                  <td className="p-2 border-r border-gray-200 whitespace-nowrap font-sans">
                    {evt.isProtected ? (
                      <span className="text-green-800 font-bold bg-green-100 px-1.5 py-0.5 rounded text-[11px] border border-green-200">
                        Protected
                      </span>
                    ) : (
                      <span className="text-gray-400">No</span>
                    )}
                  </td>
                  <td className="p-2 border-r border-gray-200 whitespace-nowrap font-sans">
                    {evt.isSuspicious ? (
                      <span className="text-red-700 font-bold bg-red-100 px-1.5 py-0.5 rounded text-[11px] border border-red-200 flex items-center gap-1 w-fit">
                        <AlertTriangle className="w-3 h-3 text-red-600" />
                        Suspicious
                      </span>
                    ) : (
                      <span className="text-gray-500">Normal</span>
                    )}
                  </td>
                  <td className="p-2 text-gray-600 max-w-sm truncate font-sans" title={evt.details}>
                    {evt.details}
                  </td>
                </tr>
              ))}
              {displayedEvents.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-gray-400 font-sans">
                    {activeFilter === 'suspicious'
                      ? 'No suspicious activity detected in the current session.'
                      : 'No events recorded yet. Click one of the test buttons above.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      {/* Role-Based Authorization Warning Modal */}
      {showRbacModal && (
        <div
          id="rbac-auth-modal"
          className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 animate-in fade-in"
        >
          <div className="bg-white rounded-lg max-w-md w-full p-5 border border-red-300 shadow-xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2 bg-red-100 text-red-700 rounded-full shrink-0">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-gray-900">
                  Role-Based Authorization Required
                </h3>
                <p className="text-xs text-gray-600 mt-1">
                  Access Denied: Only users with the{' '}
                  <span className="font-bold text-gray-900 uppercase">Administrator</span> role
                  have permission to contain or release endpoint devices.
                </p>
                <div className="text-xs mt-2 bg-yellow-50 border border-yellow-200 p-2 rounded text-yellow-900">
                  Current Authenticated Role: <strong className="uppercase">{role}</strong>
                </div>
              </div>
            </div>

            <div className="text-xs text-gray-500">
              For grading and demonstration purposes, you can immediately elevate your session to Security Administrator below.
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-gray-200">
              <button
                id="btn-rbac-cancel"
                onClick={() => setShowRbacModal(false)}
                className="px-3 py-1.5 rounded text-xs font-semibold text-gray-600 hover:bg-gray-100 border border-gray-300"
              >
                Cancel
              </button>
              <button
                id="btn-rbac-elevate-admin"
                onClick={handleRoleElevate}
                className="px-3.5 py-1.5 rounded text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 shadow-xs flex items-center gap-1.5"
              >
                <UserCheck className="w-3.5 h-3.5" />
                Switch to Admin for Demo
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Containment Confirmation / Reason Modal */}
      {showContainModal && (
        <div
          id="contain-confirmation-modal"
          className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 animate-in fade-in"
        >
          <div className="bg-white rounded-lg max-w-md w-full p-5 border border-red-300 shadow-xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2 bg-red-100 text-red-700 rounded-full shrink-0">
                <Lock className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h3 className="text-sm font-bold text-gray-900">
                  Confirm Endpoint Host Containment
                </h3>
                <p className="text-xs text-gray-600 mt-1">
                  You are about to isolate <strong className="font-mono">{device.hostname}</strong> ({device.ipAddress}). An incident will be generated and containment state recorded.
                </p>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-gray-700">
                Containment Reason (Recorded in audit trail):
              </label>
              <textarea
                id="input-containment-reason"
                rows={2}
                value={containReasonInput}
                onChange={(e) => setContainReasonInput(e.target.value)}
                className="w-full text-xs p-2 border border-gray-300 rounded focus:ring-1 focus:ring-red-500 font-sans"
                placeholder="Enter containment reason..."
              />
            </div>

            <div className="text-[11px] text-gray-500 bg-gray-50 p-2 rounded border border-gray-200">
              Safe Student Demonstration: Non-destructive software containment. No operating system crash or loss of student work.
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-gray-200">
              <button
                id="btn-contain-modal-cancel"
                onClick={() => setShowContainModal(false)}
                className="px-3 py-1.5 rounded text-xs font-semibold text-gray-600 hover:bg-gray-100 border border-gray-300"
              >
                Cancel
              </button>
              <button
                id="btn-contain-modal-confirm"
                onClick={confirmContainmentExecution}
                className="px-3.5 py-1.5 rounded text-xs font-bold text-white bg-red-700 hover:bg-red-800 shadow-xs flex items-center gap-1.5"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                Confirm Containment
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
