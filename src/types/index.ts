export type RiskSeverity = 'NORMAL' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
export type DeviceStatus = 'PROTECTED' | 'MONITORING' | 'CONTAINED' | 'OFFLINE';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
export type FilePriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FileEventType = 'CREATE' | 'MODIFY' | 'DELETE' | 'RENAME' | 'MOVE/RENAME';

export interface Device {
  id: string;
  hostname: string;
  os: string;
  ipAddress: string;
  status: DeviceStatus;
  riskScore: number;
  monitoredFolders: string[];
  lastHeartbeat: string;
  containedAt?: string;
  containmentReason?: string;
  containedBy?: string;
}

export interface SecurityEvent {
  id: string;
  deviceId: string;
  eventType: FileEventType;
  filePath: string;
  oldPath?: string;
  timestamp: string;
  isProtected: boolean;
  isSuspicious: boolean;
  details: string;
  processName?: string;
}

export interface Incident {
  id: string;
  incidentId: string; // e.g. "INC-001"
  riskScore: number;
  severity: RiskSeverity;
  deviceId: string;
  filesAffected: number;
  status: IncidentStatus;
  reason: string;
  recommendedAction: string;
  timestamp: string;
  resolvedAt?: string;
}

export interface ProtectedFile {
  id: string;
  name: string;
  path: string;
  priority: FilePriority;
  sha256: string;
  sizeBytes: number;
  lastVerified: string;
}

export interface ArchiveRecord {
  id: string;
  archiveId: string;
  createdAt: string;
  filesIncluded: string[];
  fileHashes: string[];
  archiveSize: string;
  format: 'ZIP' | '7Z';
  status: 'READY' | 'CREATING' | 'FAILED';
  downloadUrl?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  device: string;
  result: string;
}

export interface SystemSettings {
  monitoredFolders: string[];
  rapidModThreshold: number; // e.g. 5 mods / 10s
  massRenameThreshold: number; // e.g. 4 renames / 10s
  massDeleteThreshold: number; // e.g. 5 deletes / 10s
  ransomwareExtensions: string[];
  backendApiUrl: string;
  enableRaspberryPiSync: boolean;
  raspberryPiAddress: string;
}

export interface DetectionResult {
  risk_score: number;
  severity: RiskSeverity;
  reason: string;
  recommended_action: 'NONE' | 'MONITOR' | 'ALERT' | 'CONTAIN';
}

export type UserRole = 'admin' | 'analyst';

export interface UserProfile {
  uid: string;
  email: string;
  displayName?: string;
  role: UserRole;
  createdAt: string;
}
