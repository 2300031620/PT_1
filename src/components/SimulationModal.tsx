import React, { useState } from 'react';
import {
  PlayCircle,
  AlertTriangle,
  FileCheck,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  RotateCcw,
  CheckCircle2,
  Copy,
  Check
} from 'lucide-react';
import { SecurityEvent, ProtectedFile, Incident } from '../types';

interface SimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  protectedFiles: ProtectedFile[];
  onTriggerSimulation: (type: 'NORMAL' | 'RAPID_MODS' | 'PROTECTED_TAMPER' | 'RANSOMWARE_ENCRYPTION') => Promise<void>;
  onResetDemo: () => void;
}

export const SimulationModal: React.FC<SimulationModalProps> = ({
  isOpen,
  onClose,
  protectedFiles,
  onTriggerSimulation,
  onResetDemo
}) => {
  const [runningType, setRunningType] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  if (!isOpen) return null;

  const handleRun = async (type: 'NORMAL' | 'RAPID_MODS' | 'PROTECTED_TAMPER' | 'RANSOMWARE_ENCRYPTION') => {
    setRunningType(type);
    try {
      await onTriggerSimulation(type);
      setSuccessMsg(
        type === 'RANSOMWARE_ENCRYPTION'
          ? 'Critical Ransomware Scenario executed! Score > 80, Incident created, Device Contained.'
          : type === 'PROTECTED_TAMPER'
          ? 'Protected file modification detected! Elevated risk triggered.'
          : type === 'RAPID_MODS'
          ? 'Burst of 5 file edits dispatched. Risk raised to Suspicious.'
          : 'Single benign file edit dispatched. Risk remains Normal.'
      );
      setTimeout(() => setSuccessMsg(null), 4000);
    } finally {
      setRunningType(null);
    }
  };

  const copyPythonAgentCommand = () => {
    navigator.clipboard.writeText('cd endpoint_agent && python agent.py');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-white rounded-xl border border-slate-200 shadow-2xl max-w-2xl w-full p-6 space-y-5 my-8">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-100 text-indigo-700 flex items-center justify-center">
              <PlayCircle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-900 text-base">
                Safe Academic Ransomware Simulation Lab
              </h3>
              <p className="text-xs text-slate-500">
                Safely test and evaluate detection heuristics without touching local system files
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-sm p-1">
            ✕
          </button>
        </div>

        {/* Academic Safety Banner */}
        <div className="p-3 bg-blue-50 rounded-lg border border-blue-200 text-xs text-blue-900 flex items-start gap-2.5">
          <ShieldCheck className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
          <div>
            <strong className="font-semibold">Academic Safety Notice:</strong> These scenarios simulate realistic file-system events conforming to the scoring engine specifications. You can also run the real Python Watchdog agent on a Windows PC against dummy files in <code className="bg-blue-100 px-1 py-0.5 rounded font-mono">./test_sandbox</code>.
          </div>
        </div>

        {/* Scenario Buttons */}
        <div className="space-y-3">
          {/* Scenario 1: Benign */}
          <div className="p-3.5 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors flex items-center justify-between gap-4">
            <div>
              <div className="font-semibold text-xs text-slate-900 flex items-center gap-2">
                <span>1. Normal Single File Modification</span>
                <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-bold">
                  Expected: 0–29 NORMAL
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Simulates standard user saving a single document (e.g. notes.txt update).
              </p>
            </div>
            <button
              onClick={() => handleRun('NORMAL')}
              disabled={runningType !== null}
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded font-semibold text-xs shrink-0 disabled:opacity-50"
            >
              {runningType === 'NORMAL' ? 'Running...' : 'Run Test 1'}
            </button>
          </div>

          {/* Scenario 2: Rapid Edits */}
          <div className="p-3.5 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors flex items-center justify-between gap-4">
            <div>
              <div className="font-semibold text-xs text-slate-900 flex items-center gap-2">
                <span>2. Rapid Burst of Modifications (5 files / 3s)</span>
                <span className="px-2 py-0.5 rounded bg-yellow-50 text-yellow-800 border border-yellow-200 text-[10px] font-bold">
                  Expected: 30–59 SUSPICIOUS
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Simulates unexpected rapid edits across multiple documents.
              </p>
            </div>
            <button
              onClick={() => handleRun('RAPID_MODS')}
              disabled={runningType !== null}
              className="px-3 py-1.5 bg-yellow-100 hover:bg-yellow-200 text-yellow-900 rounded font-semibold text-xs shrink-0 disabled:opacity-50"
            >
              {runningType === 'RAPID_MODS' ? 'Running...' : 'Run Test 2'}
            </button>
          </div>

          {/* Scenario 3: Protected File Tamper */}
          <div className="p-3.5 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors flex items-center justify-between gap-4">
            <div>
              <div className="font-semibold text-xs text-slate-900 flex items-center gap-2">
                <span>3. Tampering with Prioritized Protected File</span>
                <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-bold">
                  Expected: 60–79 HIGH
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Simulates unauthorized modification or deletion of prioritized <code className="font-mono">database.sql</code>.
              </p>
            </div>
            <button
              onClick={() => handleRun('PROTECTED_TAMPER')}
              disabled={runningType !== null}
              className="px-3 py-1.5 bg-amber-100 hover:bg-amber-200 text-amber-900 rounded font-semibold text-xs shrink-0 disabled:opacity-50"
            >
              {runningType === 'PROTECTED_TAMPER' ? 'Running...' : 'Run Test 3'}
            </button>
          </div>

          {/* Scenario 4: Critical Ransomware Simulation */}
          <div className="p-3.5 rounded-lg border border-red-200 bg-red-50/40 hover:border-red-300 transition-colors flex items-center justify-between gap-4">
            <div>
              <div className="font-semibold text-xs text-red-950 flex items-center gap-2">
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
                  4. Mass Ransomware Renames & Encryption (.locked)
                </span>
                <span className="px-2 py-0.5 rounded bg-red-100 text-red-800 border border-red-300 text-[10px] font-bold">
                  Expected: 80–100 CRITICAL
                </span>
              </div>
              <p className="text-[11px] text-red-800/80 mt-0.5">
                Simulates mass rapid encryption signature (<code className="font-mono">.locked</code> extension) triggering automated containment and security incident creation!
              </p>
            </div>
            <button
              onClick={() => handleRun('RANSOMWARE_ENCRYPTION')}
              disabled={runningType !== null}
              className="px-3.5 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-semibold text-xs shrink-0 shadow-2xs disabled:opacity-50"
            >
              {runningType === 'RANSOMWARE_ENCRYPTION' ? 'Executing...' : 'Run Test 4'}
            </button>
          </div>
        </div>

        {/* Success Alert */}
        {successMsg && (
          <div className="p-3 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Python Agent Launch Command Snippet */}
        <div className="p-3 rounded-lg bg-slate-900 text-slate-200 text-xs space-y-1.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
              Windows Agent Command Line:
            </span>
            <button
              onClick={copyPythonAgentCommand}
              className="hover:text-white inline-flex items-center gap-1 text-[10px]"
            >
              {copiedCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedCmd ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div className="font-mono text-emerald-400 text-[11px] bg-slate-950 p-2 rounded">
            cd endpoint_agent && python agent.py
          </div>
        </div>

        <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
          <button
            type="button"
            onClick={() => {
              onResetDemo();
              setSuccessMsg('Telemetry and devices reset to default protected state.');
              setTimeout(() => setSuccessMsg(null), 3000);
            }}
            className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Demo Baseline</span>
          </button>

          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded text-xs font-semibold"
          >
            Close Lab
          </button>
        </div>
      </div>
    </div>
  );
};
