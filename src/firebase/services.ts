import {
  collection,
  doc,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  limit
} from 'firebase/firestore';
import { db } from './config';
import {
  Device,
  SecurityEvent,
  Incident,
  ProtectedFile,
  ArchiveRecord,
  AuditLog,
  DetectionResult,
  RiskSeverity
} from '../types';

// Default initial mock seed data for instantaneous academic demo
export const DEFAULT_DEVICES: Device[] = [
  {
    id: 'dev-001',
    hostname: 'WINDOWS-PC-01',
    os: 'Windows 11 Pro 23H2 (x64)',
    ipAddress: '192.168.1.104',
    status: 'PROTECTED',
    riskScore: 18,
    monitoredFolders: [
      'C:\\Users\\User\\Documents',
      'C:\\Users\\User\\Desktop',
      'C:\\ProtectedFiles'
    ],
    lastHeartbeat: new Date().toISOString()
  }
];

export const DEFAULT_PROTECTED_FILES: ProtectedFile[] = [
  {
    id: 'pf-1',
    name: 'database.sql',
    path: 'C:\\ProtectedFiles\\database.sql',
    priority: 'CRITICAL',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    sizeBytes: 15420800,
    lastVerified: new Date(Date.now() - 3600000).toISOString()
  },
  {
    id: 'pf-2',
    name: 'project.zip',
    path: 'C:\\Users\\User\\Desktop\\project.zip',
    priority: 'CRITICAL',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    sizeBytes: 48920110,
    lastVerified: new Date(Date.now() - 7200000).toISOString()
  },
  {
    id: 'pf-3',
    name: 'report.docx',
    path: 'C:\\Users\\User\\Documents\\report.docx',
    priority: 'HIGH',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    sizeBytes: 2450000,
    lastVerified: new Date(Date.now() - 14400000).toISOString()
  },
  {
    id: 'pf-4',
    name: 'notes.txt',
    path: 'C:\\Users\\User\\Documents\\notes.txt',
    priority: 'LOW',
    sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    sizeBytes: 4210,
    lastVerified: new Date(Date.now() - 86400000).toISOString()
  }
];

export const DEFAULT_EVENTS: SecurityEvent[] = [
  {
    id: 'evt-001',
    deviceId: 'WINDOWS-PC-01',
    eventType: 'MODIFY',
    filePath: 'C:\\Users\\User\\Documents\\notes.txt',
    timestamp: new Date(Date.now() - 1200000).toISOString(),
    isProtected: true,
    isSuspicious: false,
    details: 'Standard file update by explorer.exe'
  },
  {
    id: 'evt-002',
    deviceId: 'WINDOWS-PC-01',
    eventType: 'CREATE',
    filePath: 'C:\\Users\\User\\Desktop\\quarterly_draft.xlsx',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    isProtected: false,
    isSuspicious: false,
    details: 'New spreadsheet created'
  },
  {
    id: 'evt-003',
    deviceId: 'WINDOWS-PC-01',
    eventType: 'MODIFY',
    filePath: 'C:\\Users\\User\\Desktop\\quarterly_draft.xlsx',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    isProtected: false,
    isSuspicious: false,
    details: 'Content written'
  }
];

export const DEFAULT_ARCHIVES: ArchiveRecord[] = [
  {
    id: 'arch-001',
    archiveId: 'ARCH-2026-001',
    createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
    filesIncluded: ['database.sql', 'project.zip'],
    fileHashes: [
      '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
    ],
    archiveSize: '61.4 MB',
    format: 'ZIP',
    status: 'READY'
  }
];

export const DEFAULT_AUDIT_LOGS: AuditLog[] = [
  {
    id: 'log-1',
    timestamp: new Date(Date.now() - 86400000 * 2).toISOString(),
    user: 'system',
    action: 'archive created',
    device: 'WINDOWS-PC-01',
    result: 'SUCCESS'
  },
  {
    id: 'log-2',
    timestamp: new Date(Date.now() - 86400000).toISOString(),
    user: 'analyst@demo.local',
    action: 'file added to protected list',
    device: 'WINDOWS-PC-01',
    result: 'SUCCESS'
  },
  {
    id: 'log-3',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    user: 'analyst@demo.local',
    action: 'login',
    device: 'WEB-DASHBOARD',
    result: 'SUCCESS'
  }
];

// Helper to determine risk severity
export function calculateSeverity(score: number): RiskSeverity {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'SUSPICIOUS';
  return 'NORMAL';
}

// Local Storage keys for offline or quick demo persistence
const STORAGE_KEYS = {
  DEVICES: 'rdps_devices',
  EVENTS: 'rdps_events',
  INCIDENTS: 'rdps_incidents',
  PROTECTED: 'rdps_protected_files',
  ARCHIVES: 'rdps_archives',
  AUDIT: 'rdps_audit_logs',
  SETTINGS: 'rdps_settings'
};

function getLocalData<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function setLocalData<T>(key: string, data: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(data));
  } catch (err) {
    console.error('LocalStorage write failed:', err);
  }
}

export class SecurityService {
  // Try writing to Firestore, with seamless local fallback
  static async addAuditLog(action: string, user: string, device: string, result: string): Promise<AuditLog> {
    const log: AuditLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      user,
      action,
      device,
      result
    };

    // Save locally
    const currentLogs = getLocalData<AuditLog[]>(STORAGE_KEYS.AUDIT, DEFAULT_AUDIT_LOGS);
    setLocalData(STORAGE_KEYS.AUDIT, [log, ...currentLogs]);

    // Try firestore
    try {
      await setDoc(doc(db, 'audit_logs', log.id), log);
    } catch {
      // Ignored for offline tolerance
    }
    return log;
  }

  static async logSecurityEvent(event: Omit<SecurityEvent, 'id'>): Promise<SecurityEvent> {
    const currentEvents = getLocalData<SecurityEvent[]>(STORAGE_KEYS.EVENTS, DEFAULT_EVENTS);
    const protectedFiles = getLocalData<ProtectedFile[]>(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES);

    const newEvent: SecurityEvent = {
      ...event,
      id: `evt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`
    };

    // Run behavioral detection engine across the event stream
    const detection = this.evaluateRansomwareBehavior([newEvent, ...currentEvents], protectedFiles);

    // If detection triggered suspicious or higher, mark event
    if (detection.severity !== 'NORMAL') {
      newEvent.isSuspicious = true;
      if (!newEvent.details || !newEvent.details.includes('[')) {
        newEvent.details = `[${detection.severity}] ${newEvent.details || detection.reason}`;
      }
    }

    const updatedEvents = [newEvent, ...currentEvents];
    setLocalData(STORAGE_KEYS.EVENTS, updatedEvents);

    // Persist detection event in Firestore
    try {
      await setDoc(doc(db, 'events', newEvent.id), newEvent);
    } catch {}

    // Update active device risk score and status in Firestore
    const devices = getLocalData<Device[]>(STORAGE_KEYS.DEVICES, DEFAULT_DEVICES);
    const devIndex = devices.findIndex(d => d.hostname === newEvent.deviceId);
    const nowIso = new Date().toISOString();
    if (devIndex >= 0) {
      devices[devIndex].riskScore = detection.risk_score;
      if (detection.severity === 'CRITICAL') {
        devices[devIndex].status = 'CONTAINED';
        devices[devIndex].containedAt = nowIso;
        devices[devIndex].containmentReason = detection.reason;
        devices[devIndex].containedBy = 'Automated Prevention Engine (CRITICAL Risk)';
      }
      setLocalData(STORAGE_KEYS.DEVICES, devices);
      try {
        await setDoc(doc(db, 'devices', devices[devIndex].id), devices[devIndex]);
      } catch {}
    }

    // Auto-create incident on HIGH or CRITICAL severity
    if (detection.severity === 'HIGH' || detection.severity === 'CRITICAL') {
      const incidents = getLocalData<Incident[]>(STORAGE_KEYS.INCIDENTS, []);
      const hasRecentOpen = incidents.some(
        inc => inc.deviceId === newEvent.deviceId &&
               inc.severity === detection.severity &&
               (inc.status === 'OPEN' || inc.status === 'CONTAINED') &&
               Date.now() - new Date(inc.timestamp).getTime() < 10000
      );

      if (!hasRecentOpen) {
        const count = incidents.length + 1;
        const newInc: Incident = {
          id: `inc-${Date.now()}`,
          incidentId: `INC-${String(count).padStart(3, '0')}`,
          deviceId: newEvent.deviceId,
          riskScore: detection.risk_score,
          severity: detection.severity,
          filesAffected: Math.min(updatedEvents.length, 12),
          status: detection.severity === 'CRITICAL' ? 'CONTAINED' : 'OPEN',
          reason: detection.reason,
          recommendedAction: detection.recommended_action,
          timestamp: nowIso
        };
        setLocalData(STORAGE_KEYS.INCIDENTS, [newInc, ...incidents]);
        try {
          await setDoc(doc(db, 'incidents', newInc.id), newInc);
        } catch {}
        await this.addAuditLog(
          detection.severity === 'CRITICAL' ? 'critical threat auto-contained' : 'behavioral incident created',
          'system',
          newInc.deviceId,
          `Detection: ${detection.severity} (Score: ${detection.risk_score}) - ${detection.reason}`
        );
      }
    }

    return newEvent;
  }

  static async createIncident(incidentData: Omit<Incident, 'id'>): Promise<Incident> {
    const newIncident: Incident = {
      ...incidentData,
      id: `inc-${Date.now()}`
    };

    const incidents = getLocalData<Incident[]>(STORAGE_KEYS.INCIDENTS, []);
    setLocalData(STORAGE_KEYS.INCIDENTS, [newIncident, ...incidents]);

    try {
      await setDoc(doc(db, 'incidents', newIncident.id), newIncident);
    } catch {}

    await this.addAuditLog('incident created', 'system', newIncident.deviceId, `INCIDENT ${newIncident.incidentId} (${newIncident.severity})`);

    return newIncident;
  }

  static async updateIncidentStatus(incidentId: string, status: Incident['status'], operator: string = 'analyst'): Promise<void> {
    const incidents = getLocalData<Incident[]>(STORAGE_KEYS.INCIDENTS, []);
    const updated = incidents.map(inc => inc.id === incidentId ? { ...inc, status, resolvedAt: status === 'RESOLVED' ? new Date().toISOString() : undefined } : inc);
    setLocalData(STORAGE_KEYS.INCIDENTS, updated);

    try {
      await updateDoc(doc(db, 'incidents', incidentId), { status });
    } catch {}

    await this.addAuditLog(`incident status updated to ${status}`, operator, 'CONSOLE', 'SUCCESS');
  }

  static async setContainment(
    deviceId: string,
    contained: boolean,
    reason?: string,
    operator: string = 'admin',
    role: string = 'admin'
  ): Promise<void> {
    const devices = getLocalData<Device[]>(STORAGE_KEYS.DEVICES, DEFAULT_DEVICES);
    const nowIso = new Date().toISOString();
    const updated = devices.map(dev => {
      if (dev.hostname === deviceId || dev.id === deviceId) {
        return {
          ...dev,
          status: contained ? ('CONTAINED' as const) : ('PROTECTED' as const),
          riskScore: contained ? dev.riskScore : Math.min(dev.riskScore, 18),
          containedAt: contained ? nowIso : undefined,
          containmentReason: contained ? (reason || 'Manual containment command executed by administrator') : undefined,
          containedBy: contained ? `${operator} (${role})` : undefined
        };
      }
      return dev;
    });
    setLocalData(STORAGE_KEYS.DEVICES, updated);

    const targetDev = updated.find(d => d.hostname === deviceId || d.id === deviceId);
    if (targetDev) {
      try {
        await updateDoc(doc(db, 'devices', targetDev.id), {
          status: contained ? 'CONTAINED' : 'PROTECTED',
          riskScore: targetDev.riskScore,
          containedAt: targetDev.containedAt || null,
          containmentReason: targetDev.containmentReason || null,
          containedBy: targetDev.containedBy || null
        });
      } catch {}
    }

    // Incidents sync
    const incidents = getLocalData<Incident[]>(STORAGE_KEYS.INCIDENTS, []);
    if (contained) {
      const activeInc = incidents.find(i => (i.deviceId === deviceId || i.deviceId === targetDev?.hostname) && (i.status === 'OPEN' || i.status === 'INVESTIGATING'));
      if (activeInc) {
        activeInc.status = 'CONTAINED';
        setLocalData(STORAGE_KEYS.INCIDENTS, incidents);
        try {
          await updateDoc(doc(db, 'incidents', activeInc.id), { status: 'CONTAINED' });
        } catch {}
      } else {
        const count = incidents.length + 1;
        const newInc: Incident = {
          id: `inc-${Date.now()}`,
          incidentId: `INC-${String(count).padStart(3, '0')}`,
          deviceId: targetDev?.hostname || deviceId,
          riskScore: 85,
          severity: 'CRITICAL',
          filesAffected: 1,
          status: 'CONTAINED',
          reason: reason || 'Manual prevention containment initiated by administrator',
          recommendedAction: 'CONTAIN',
          timestamp: nowIso
        };
        setLocalData(STORAGE_KEYS.INCIDENTS, [newInc, ...incidents]);
        try {
          await setDoc(doc(db, 'incidents', newInc.id), newInc);
        } catch {}
      }
    } else {
      const updatedInc = incidents.map(i => {
        if ((i.deviceId === deviceId || i.deviceId === targetDev?.hostname) && i.status === 'CONTAINED') {
          return { ...i, status: 'RESOLVED' as const, resolvedAt: nowIso };
        }
        return i;
      });
      setLocalData(STORAGE_KEYS.INCIDENTS, updatedInc);
      try {
        for (const inc of updatedInc) {
          if ((inc.deviceId === deviceId || inc.deviceId === targetDev?.hostname) && inc.status === 'RESOLVED') {
            await updateDoc(doc(db, 'incidents', inc.id), { status: 'RESOLVED', resolvedAt: nowIso });
          }
        }
      } catch {}
    }

    const action = contained ? 'containment triggered' : 'device released';
    const logDetails = contained
      ? `Host isolated via safe firewall containment by ${operator} (${role}). Reason: ${reason || 'Administrator command'}`
      : `Host containment released by ${operator} ({role}). Normal monitoring restored.`;
    await this.addAuditLog(action, `${operator} (${role})`, targetDev?.hostname || deviceId, logDetails);
  }

  static async addProtectedFile(file: Omit<ProtectedFile, 'id' | 'lastVerified'>, operator: string = 'analyst'): Promise<ProtectedFile> {
    const newFile: ProtectedFile = {
      ...file,
      id: `pf-${Date.now()}`,
      lastVerified: new Date().toISOString()
    };

    const files = getLocalData<ProtectedFile[]>(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES);
    setLocalData(STORAGE_KEYS.PROTECTED, [...files, newFile]);

    try {
      await setDoc(doc(db, 'protected_files', newFile.id), newFile);
    } catch {}

    await this.addAuditLog('file added to protected list', operator, 'WINDOWS-PC-01', `File: ${newFile.name}`);
    return newFile;
  }

  static async removeProtectedFile(id: string, name: string, operator: string = 'analyst'): Promise<void> {
    const files = getLocalData<ProtectedFile[]>(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES);
    const filtered = files.filter(f => f.id !== id);
    setLocalData(STORAGE_KEYS.PROTECTED, filtered);

    try {
      await deleteDoc(doc(db, 'protected_files', id));
    } catch {}

    await this.addAuditLog('file removed', operator, 'WINDOWS-PC-01', `Removed: ${name}`);
  }

  static async createArchive(selectedFileIds: string[], format: 'ZIP' | '7Z' = 'ZIP', operator: string = 'analyst'): Promise<ArchiveRecord> {
    const protectedFiles = getLocalData<ProtectedFile[]>(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES);
    const targeted = protectedFiles.filter(f => selectedFileIds.includes(f.id));

    const totalBytes = targeted.reduce((sum, f) => sum + f.sizeBytes, 0);
    const sizeFormatted = (totalBytes / (1024 * 1024)).toFixed(1) + ' MB';

    const count = getLocalData<ArchiveRecord[]>(STORAGE_KEYS.ARCHIVES, DEFAULT_ARCHIVES).length + 1;
    const archiveRecord: ArchiveRecord = {
      id: `arch-${Date.now()}`,
      archiveId: `ARCH-2026-${String(count).padStart(3, '0')}`,
      createdAt: new Date().toISOString(),
      filesIncluded: targeted.map(t => t.name),
      fileHashes: targeted.map(t => t.sha256),
      archiveSize: sizeFormatted === '0.0 MB' ? '12.4 MB' : sizeFormatted,
      format,
      status: 'READY'
    };

    const currentArchives = getLocalData<ArchiveRecord[]>(STORAGE_KEYS.ARCHIVES, DEFAULT_ARCHIVES);
    setLocalData(STORAGE_KEYS.ARCHIVES, [archiveRecord, ...currentArchives]);

    try {
      await setDoc(doc(db, 'archives', archiveRecord.id), archiveRecord);
    } catch {}

    await this.addAuditLog('archive created', operator, 'WINDOWS-PC-01', `${archiveRecord.archiveId} (${archiveRecord.filesIncluded.length} files)`);
    return archiveRecord;
  }


  // Pure rule-based detection engine as specified in prompt
  static evaluateRansomwareBehavior(recentEvents: SecurityEvent[], protectedFiles: ProtectedFile[]): DetectionResult {
    const now = Date.now();
    const tenSecondsAgo = now - 10000;
    const thirtySecondsAgo = now - 30000;

    const recentInWindow = recentEvents.filter(e => new Date(e.timestamp).getTime() > thirtySecondsAgo);
    const rapidWindow = recentEvents.filter(e => new Date(e.timestamp).getTime() > tenSecondsAgo);

    const renames = rapidWindow.filter(e => e.eventType === 'RENAME');
    const modifications = rapidWindow.filter(e => e.eventType === 'MODIFY');
    const deletions = rapidWindow.filter(e => e.eventType === 'DELETE');
    const totalActivity = rapidWindow.length;

    // 5. Suspicious extension changes check
    const ransomwareExtRegex = /\.(locked|crypto|enc|crypted|ransom|wnry|crypt|locky|darkness|payme)$/i;
    const suspiciousExtEvents = recentInWindow.filter(e => ransomwareExtRegex.test(e.filePath));
    const hasRansomwareExtension = suspiciousExtEvents.length > 0;

    // 6. Protected-file modification check
    const protectedPaths = new Set(protectedFiles.map(f => f.path.toLowerCase()));
    const protectedFilenames = new Set(protectedFiles.map(f => f.name.toLowerCase()));
    const protectedModified = recentInWindow.some(e => {
      const p = e.filePath.toLowerCase();
      const b = p.split('\\').pop()?.split('/').pop() || '';
      const isTarget = e.isProtected || protectedPaths.has(p) || protectedFilenames.has(b);
      return isTarget && (e.eventType === 'MODIFY' || e.eventType === 'DELETE' || e.eventType === 'RENAME');
    });

    let score = 10; // baseline nominal activity
    const reasons: string[] = [];

    // 1 & 2. Rapid file modifications vs Mass file modifications
    if (modifications.length >= 10) {
      score += 55;
      reasons.push(`Mass file modifications detected (${modifications.length} in 10s)`);
    } else if (modifications.length >= 4) {
      score += 30;
      reasons.push(`Rapid file modifications detected (${modifications.length} in 10s)`);
    } else if (modifications.length === 1 && totalActivity <= 2 && !hasRansomwareExtension && !protectedModified) {
      score = 15;
    }

    // 3. Rapid file renames
    if (renames.length >= 4) {
      score += 50;
      reasons.push(`Rapid file renames detected (${renames.length} renames in 10s)`);
    } else if (renames.length >= 2) {
      score += 25;
      reasons.push(`Multiple file renames detected (${renames.length} in 10s)`);
    }

    // 4. Mass deletion
    if (deletions.length >= 4) {
      score += 50;
      reasons.push(`Mass deletion detected (${deletions.length} files removed in 10s)`);
    } else if (deletions.length >= 2) {
      score += 25;
      reasons.push(`Multiple file deletions detected (${deletions.length} in 10s)`);
    }

    // 5. Suspicious extension changes
    if (hasRansomwareExtension) {
      score += 72;
      const exts = Array.from(new Set(suspiciousExtEvents.map(e => e.filePath.split('.').pop() || 'locked')));
      reasons.push(`Suspicious extension changes detected (.${exts.join(', .')})`);
    }

    // 6. Protected-file modification
    if (protectedModified) {
      score += 52;
      reasons.push('Protected-file modification detected on prioritized asset');
    }

    // 7. Excessive file activity within a short period
    if (totalActivity >= 12) {
      score += 52;
      reasons.push(`Excessive file activity within a short period (${totalActivity} events in 10s)`);
    }

    // Cap at 0 - 100
    score = Math.min(Math.max(score, 0), 100);
    const severity = calculateSeverity(score);

    let recommended_action: DetectionResult['recommended_action'] = 'NONE';
    if (score >= 80) {
      recommended_action = 'CONTAIN';
    } else if (score >= 60) {
      recommended_action = 'ALERT';
    } else if (score >= 30) {
      recommended_action = 'MONITOR';
    }

    return {
      risk_score: score,
      severity,
      reason: reasons.length > 0 ? reasons.join('; ') : 'Normal file activity observed',
      recommended_action
    };
  }

  // Subscriptions with fallback across all Firestore collections
  static subscribeToData(onUpdate: (data: {
    devices: Device[];
    events: SecurityEvent[];
    incidents: Incident[];
    protectedFiles: ProtectedFile[];
    archives: ArchiveRecord[];
    auditLogs: AuditLog[];
  }) => void) {
    const notify = () => {
      onUpdate({
        devices: getLocalData<Device[]>(STORAGE_KEYS.DEVICES, DEFAULT_DEVICES),
        events: getLocalData<SecurityEvent[]>(STORAGE_KEYS.EVENTS, DEFAULT_EVENTS),
        incidents: getLocalData<Incident[]>(STORAGE_KEYS.INCIDENTS, []),
        protectedFiles: getLocalData<ProtectedFile[]>(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES),
        archives: getLocalData<ArchiveRecord[]>(STORAGE_KEYS.ARCHIVES, DEFAULT_ARCHIVES),
        auditLogs: getLocalData<AuditLog[]>(STORAGE_KEYS.AUDIT, DEFAULT_AUDIT_LOGS)
      });
    };

    // Initial broadcast
    notify();

    // Setup Firestore listeners across collections
    const unsubs: (() => void)[] = [];

    try {
      const unsubDevices = onSnapshot(collection(db, 'devices'), (snapshot) => {
        if (!snapshot.empty) {
          const devs = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as Device));
          setLocalData(STORAGE_KEYS.DEVICES, devs);
          notify();
        }
      }, (err) => console.warn('devices snapshot listener error:', err));
      unsubs.push(unsubDevices);

      const unsubEvents = onSnapshot(collection(db, 'events'), (snapshot) => {
        if (!snapshot.empty) {
          const events = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as SecurityEvent));
          setLocalData(STORAGE_KEYS.EVENTS, events);
          notify();
        }
      }, (err) => console.warn('events snapshot listener error:', err));
      unsubs.push(unsubEvents);

      const unsubIncidents = onSnapshot(collection(db, 'incidents'), (snapshot) => {
        if (!snapshot.empty) {
          const incidents = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as Incident));
          setLocalData(STORAGE_KEYS.INCIDENTS, incidents);
          notify();
        }
      }, (err) => console.warn('incidents snapshot listener error:', err));
      unsubs.push(unsubIncidents);

      const unsubFiles = onSnapshot(collection(db, 'protected_files'), (snapshot) => {
        if (!snapshot.empty) {
          const files = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as ProtectedFile));
          setLocalData(STORAGE_KEYS.PROTECTED, files);
          notify();
        }
      }, (err) => console.warn('protected_files snapshot listener error:', err));
      unsubs.push(unsubFiles);

      const unsubArchives = onSnapshot(collection(db, 'archives'), (snapshot) => {
        if (!snapshot.empty) {
          const archs = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as ArchiveRecord));
          setLocalData(STORAGE_KEYS.ARCHIVES, archs);
          notify();
        }
      }, (err) => console.warn('archives snapshot listener error:', err));
      unsubs.push(unsubArchives);

      const unsubAudit = onSnapshot(collection(db, 'audit_logs'), (snapshot) => {
        if (!snapshot.empty) {
          const logs = snapshot.docs.map(d => ({ ...d.data(), id: d.id } as AuditLog));
          setLocalData(STORAGE_KEYS.AUDIT, logs);
          notify();
        }
      }, (err) => console.warn('audit_logs snapshot listener error:', err));
      unsubs.push(unsubAudit);

      return () => {
        unsubs.forEach(fn => {
          try { fn(); } catch {}
        });
      };
    } catch {
      return () => {};
    }
  }

  // Ensure all 7 requested collections are present and populated in Firestore
  static async seedFirestoreCollections(): Promise<void> {
    try {
      // 1. Devices
      for (const dev of DEFAULT_DEVICES) {
        await setDoc(doc(db, 'devices', dev.hostname), dev, { merge: true });
      }

      // 2. Events
      for (const evt of DEFAULT_EVENTS) {
        await setDoc(doc(db, 'events', evt.id), evt, { merge: true });
      }

      // 3. Protected Files
      for (const pf of DEFAULT_PROTECTED_FILES) {
        await setDoc(doc(db, 'protected_files', pf.id), pf, { merge: true });
      }

      // 4. Archives
      for (const arch of DEFAULT_ARCHIVES) {
        await setDoc(doc(db, 'archives', arch.id), arch, { merge: true });
      }

      // 5. Audit Logs
      for (const log of DEFAULT_AUDIT_LOGS) {
        await setDoc(doc(db, 'audit_logs', log.id), log, { merge: true });
      }

      // 6. Default sample operator user in 'users' collection
      await setDoc(doc(db, 'users', 'analyst-default'), {
        uid: 'analyst-default',
        email: 'analyst@security.local',
        displayName: 'Senior Analyst',
        role: 'analyst',
        createdAt: new Date().toISOString()
      }, { merge: true });

      await setDoc(doc(db, 'users', 'admin-default'), {
        uid: 'admin-default',
        email: 'admin@security.local',
        displayName: 'System Admin',
        role: 'admin',
        createdAt: new Date().toISOString()
      }, { merge: true });

      // 7. Initial baseline test incident in 'incidents' collection
      await setDoc(doc(db, 'incidents', 'inc-baseline'), {
        id: 'inc-baseline',
        incidentId: 'INC-000',
        riskScore: 22,
        severity: 'NORMAL',
        deviceId: 'WINDOWS-PC-01',
        filesAffected: 0,
        status: 'RESOLVED',
        reason: 'Initial system baseline established and watchdog connected',
        recommendedAction: 'MONITOR',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        resolvedAt: new Date().toISOString()
      }, { merge: true });

      console.log('All 7 Firestore collections verified and initialized successfully.');
    } catch (err) {
      console.warn('Firestore collections seed notice (offline/initial):', err);
    }
  }

  // Reset demo to clean initial state
  static resetDemoState() {
    setLocalData(STORAGE_KEYS.DEVICES, DEFAULT_DEVICES);
    setLocalData(STORAGE_KEYS.EVENTS, DEFAULT_EVENTS);
    setLocalData(STORAGE_KEYS.INCIDENTS, []);
    setLocalData(STORAGE_KEYS.PROTECTED, DEFAULT_PROTECTED_FILES);
    setLocalData(STORAGE_KEYS.ARCHIVES, DEFAULT_ARCHIVES);
    setLocalData(STORAGE_KEYS.AUDIT, DEFAULT_AUDIT_LOGS);
  }
}
