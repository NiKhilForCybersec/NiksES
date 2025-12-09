/**
 * NiksES Settings Service
 * 
 * API calls for settings and API key management.
 */

import { get, post, put, del } from './api';
import type {
  SettingsResponse,
  APIKeyStatus,
  APIKeyTestResult,
  HealthResponse,
  DetailedHealthResponse,
} from '../types';

// =============================================================================
// SETTINGS
// =============================================================================

/**
 * Get all settings
 */
export async function getSettings(): Promise<SettingsResponse> {
  return get<SettingsResponse>('/settings');
}

/**
 * Update settings
 */
export async function updateSettings(
  settings: Record<string, string | number | boolean>
): Promise<SettingsResponse> {
  return put<SettingsResponse>('/settings', settings);
}

// =============================================================================
// API KEYS
// =============================================================================

/**
 * Get all API key statuses
 */
export async function getAPIKeys(): Promise<APIKeyStatus[]> {
  return get<APIKeyStatus[]>('/settings/apikeys');
}

/**
 * Add or update an API key
 */
export async function setAPIKey(service: string, key: string): Promise<APIKeyStatus> {
  return post<APIKeyStatus>('/settings/apikeys', { service, key });
}

/**
 * Delete an API key
 */
export async function deleteAPIKey(service: string): Promise<void> {
  return del<void>(`/settings/apikeys/${service}`);
}

/**
 * Test an API key
 */
export async function testAPIKey(service: string): Promise<APIKeyTestResult> {
  return post<APIKeyTestResult>(`/settings/apikeys/${service}/test`);
}

/**
 * Enable or disable an API key
 */
export async function toggleAPIKey(service: string, enabled: boolean): Promise<APIKeyStatus> {
  return put<APIKeyStatus>(`/settings/apikeys/${service}`, { is_enabled: enabled });
}

// =============================================================================
// HEALTH
// =============================================================================

/**
 * Get basic health status
 */
export async function getHealth(): Promise<HealthResponse> {
  return get<HealthResponse>('/health');
}

/**
 * Get detailed health status
 */
export async function getDetailedHealth(): Promise<DetailedHealthResponse> {
  return get<DetailedHealthResponse>('/health/detailed');
}
