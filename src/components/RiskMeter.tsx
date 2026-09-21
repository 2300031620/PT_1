import React from 'react';
import { RiskSeverity } from '../types';

interface RiskMeterProps {
  score: number;
  severity: RiskSeverity;
  showBreakdown?: boolean;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score, severity, showBreakdown = false }) => {
  const getSeverityColor = (sev: RiskSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return {
          bar: 'bg-red-600',
          text: 'text-red-700',
          bg: 'bg-red-50',
          border: 'border-red-200',
          badge: 'bg-red-100 text-red-800 border-red-300'
        };
      case 'HIGH':
        return {
          bar: 'bg-amber-600',
          text: 'text-amber-700',
          bg: 'bg-amber-50',
          border: 'border-amber-200',
          badge: 'bg-amber-100 text-amber-800 border-amber-300'
        };
      case 'SUSPICIOUS':
        return {
          bar: 'bg-yellow-500',
          text: 'text-yellow-700',
          bg: 'bg-yellow-50',
          border: 'border-yellow-200',
          badge: 'bg-yellow-100 text-yellow-800 border-yellow-300'
        };
      default:
        return {
          bar: 'bg-emerald-600',
          text: 'text-emerald-700',
          bg: 'bg-emerald-50',
          border: 'border-emerald-200',
          badge: 'bg-emerald-100 text-emerald-800 border-emerald-300'
        };
    }
  };

  const style = getSeverityColor(severity);

  return (
    <div id="risk-meter-component" className="w-full">
      <div className="flex items-baseline justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-3xl font-bold tracking-tight text-slate-900">{score}</span>
          <span className="text-sm font-medium text-slate-500">/ 100</span>
        </div>
        <span id="risk-severity-badge" className={`px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${style.badge}`}>
          {severity}
        </span>
      </div>

      {/* Primary Score Bar */}
      <div className="w-full bg-slate-200 h-2.5 rounded-full overflow-hidden mb-3">
        <div
          id="risk-meter-bar"
          className={`h-full transition-all duration-500 ease-out ${style.bar}`}
          style={{ width: `${Math.min(Math.max(score, 4), 100)}%` }}
        />
      </div>

      {/* Simple standard range labels */}
      <div className="grid grid-cols-4 text-[11px] text-slate-500 border-t border-slate-200 pt-2 text-center">
        <div className={score < 30 ? 'font-bold text-emerald-700' : ''}>0–29 Normal</div>
        <div className={score >= 30 && score < 60 ? 'font-bold text-yellow-700' : ''}>30–59 Suspicious</div>
        <div className={score >= 60 && score < 80 ? 'font-bold text-amber-700' : ''}>60–79 High</div>
        <div className={score >= 80 ? 'font-bold text-red-700' : ''}>80–100 Critical</div>
      </div>

      {showBreakdown && (
        <div className={`mt-3 p-2.5 rounded border text-xs ${style.bg} ${style.border} ${style.text}`}>
          <div className="font-semibold mb-0.5">Threshold Action Status</div>
          <p className="text-slate-700">
            {severity === 'CRITICAL'
              ? 'Ransomware behavioral threshold exceeded. Automatic containment recommended.'
              : severity === 'HIGH'
              ? 'Abnormal modification frequency detected. Heightened inspection active.'
              : severity === 'SUSPICIOUS'
              ? 'Minor deviation in file operation frequency. Monitoring telemetry.'
              : 'File system behavior within nominal benign operating parameters.'}
          </p>
        </div>
      )}
    </div>
  );
};
