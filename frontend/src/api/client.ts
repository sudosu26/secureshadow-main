import {
  AuthResponse,
  Asset,
  SecurityControl,
  CommunicationPath,
  SecurityProperty,
  BaselineStats,
  DriftDetectionResponse,
  DecayReport,
  RepairResponse,
  Remediation,
  RemediationVerifyResponse,
  AuditLog,
} from '../types';

const API_BASE = '/api/v1';
const GET_CACHE_TTL_MS = 5000;
const GET_CACHE_MAX_ENTRIES = 100;
const getCache = new Map<string, { expiresAt: number; value: any }>();
const inFlightRequests = new Map<string, Promise<any>>();

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
    this.name = 'ApiError';
  }
}

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('secureshadow_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function invalidateGetCache(prefix?: string) {
  for (const key of Array.from(getCache.keys())) {
    if (!prefix || key.startsWith(prefix)) {
      getCache.delete(key);
    }
  }
}

function cacheGetResponse(key: string, value: any) {
  const now = Date.now();
  for (const [cachedKey, entry] of getCache) {
    if (entry.expiresAt <= now) {
      getCache.delete(cachedKey);
    }
  }

  getCache.delete(key);
  while (getCache.size >= GET_CACHE_MAX_ENTRIES) {
    const oldestKey = getCache.keys().next().value;
    if (oldestKey === undefined) break;
    getCache.delete(oldestKey);
  }

  getCache.set(key, { expiresAt: now + GET_CACHE_TTL_MS, value });
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const isGetRequest = method === 'GET';
  const authToken = localStorage.getItem('secureshadow_token') || '';
  const cacheKey = `${method}:${endpoint}:${authToken}`;

  if (isGetRequest) {
    const cached = getCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value as T;
    }

    const inFlight = inFlightRequests.get(cacheKey);
    if (inFlight) {
      return inFlight as T;
    }
  }

  const headers: Record<string, string> = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...getAuthHeader(),
    ...(options.headers as Record<string, string> || {}),
  };

  const requestPromise = fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  }).then(async (response) => {
    if (response.status === 401) {
      localStorage.removeItem('secureshadow_token');
      localStorage.removeItem('secureshadow_user');
      invalidateGetCache();
      if (!window.location.pathname.includes('/login')) {
        window.dispatchEvent(new Event('auth:unauthorized'));
      }
    }

    const contentType = response.headers.get('content-type');
    let data: any = null;
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    }

    if (!response.ok) {
      const errorMsg = data?.detail || `API Request Failed with status ${response.status}`;
      throw new ApiError(response.status, errorMsg, data);
    }

    if (isGetRequest) {
      cacheGetResponse(cacheKey, data);
    } else {
      invalidateGetCache('GET:');
    }

    return data as T;
  }).finally(() => {
    if (isGetRequest) {
      inFlightRequests.delete(cacheKey);
    }
  });

  if (isGetRequest) {
    inFlightRequests.set(cacheKey, requestPromise);
  }

  return requestPromise;
}

export const api = {
  clearCache: () => {
    invalidateGetCache();
    inFlightRequests.clear();
  },

  // Auth
  login: async (username: string, password: string): Promise<AuthResponse> => {
    return request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },

  getMe: async (): Promise<{ username: string; is_admin: boolean }> => {
    return request<{ username: string; is_admin: boolean }>('/auth/me');
  },

  changePassword: async (current_password: string, new_password: string): Promise<{ status: string; message: string }> => {
    return request<{ status: string; message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    });
  },

  // Baseline
  captureBaseline: async (source: 'demo' | 'terraform' = 'demo', terraform_json?: any): Promise<any> => {
    return request<any>('/baseline', {
      method: 'POST',
      body: JSON.stringify({ source, terraform_json }),
    });
  },

  getBaseline: async (): Promise<BaselineStats> => {
    return request<BaselineStats>('/baseline');
  },

  // Drift & Current State
  submitCurrentState: async (source: 'demo_drift' | 'terraform' = 'demo_drift', terraform_json?: any): Promise<any> => {
    return request<any>('/current', {
      method: 'POST',
      body: JSON.stringify({ source, terraform_json }),
    });
  },

  detectDrift: async (): Promise<DriftDetectionResponse> => {
    return request<DriftDetectionResponse>('/detect', {
      method: 'POST',
    });
  },

  // Decay
  getDecayReport: async (): Promise<DecayReport> => {
    return request<DecayReport>('/decay');
  },

  // Repairs
  getRepairs: async (minImprovement: number = 50.0): Promise<RepairResponse> => {
    return request<RepairResponse>(`/repairs?min_improvement=${minImprovement}`);
  },

  // Remediations Lifecycle
  applyRemediation: async (data: {
    repair_id: string;
    description: string;
    action_type: string;
    target_entity?: string;
  }): Promise<Remediation> => {
    return request<Remediation>('/remediations', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  listRemediations: async (): Promise<Remediation[]> => {
    return request<Remediation[]>('/remediations');
  },

  updateRemediationStatus: async (remediationId: string, status: string): Promise<Remediation> => {
    return request<Remediation>(`/remediations/${remediationId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  },

  verifyRemediation: async (remediationId: string): Promise<RemediationVerifyResponse> => {
    return request<RemediationVerifyResponse>(`/remediations/${remediationId}/verify`, {
      method: 'POST',
    });
  },

  // Inventory CRUD
  listAssets: async (): Promise<Asset[]> => {
    return request<Asset[]>('/assets');
  },

  createAsset: async (asset: { asset_id: string; name: string; asset_type: string; ip_address?: string | null }): Promise<Asset> => {
    return request<Asset>('/assets', {
      method: 'POST',
      body: JSON.stringify(asset),
    });
  },

  deleteAsset: async (assetId: string): Promise<{ status: string }> => {
    return request<{ status: string }>(`/assets/${assetId}`, {
      method: 'DELETE',
    });
  },

  listControls: async (): Promise<SecurityControl[]> => {
    return request<SecurityControl[]>('/controls');
  },

  createControl: async (ctrl: { control_id: string; name: string; control_type: string; status?: string }): Promise<SecurityControl> => {
    return request<SecurityControl>('/controls', {
      method: 'POST',
      body: JSON.stringify(ctrl),
    });
  },

  deleteControl: async (controlId: string): Promise<{ status: string }> => {
    return request<{ status: string }>(`/controls/${controlId}`, {
      method: 'DELETE',
    });
  },

  listPaths: async (): Promise<CommunicationPath[]> => {
    return request<CommunicationPath[]>('/paths');
  },

  createPath: async (path: { path_id: string; source_id: string; destination_id: string; protocol?: string }): Promise<CommunicationPath> => {
    return request<CommunicationPath>('/paths', {
      method: 'POST',
      body: JSON.stringify(path),
    });
  },

  deletePath: async (pathId: string): Promise<{ status: string }> => {
    return request<{ status: string }>(`/paths/${pathId}`, {
      method: 'DELETE',
    });
  },

  listProperties: async (): Promise<SecurityProperty[]> => {
    return request<SecurityProperty[]>('/properties');
  },

  // Audit Logs
  listAuditLogs: async (limit: number = 100): Promise<AuditLog[]> => {
    return request<AuditLog[]>(`/audit-logs?limit=${limit}`);
  },
};
