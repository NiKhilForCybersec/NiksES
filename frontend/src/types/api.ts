/**
 * NiksES API Types
 * 
 * TypeScript interfaces for API requests and responses.
 */

import type { AnalysisResult, AnalysisListResponse, ExtractedIOCs } from './analysis';
import type { SettingsResponse, APIKeyStatus, APIKeyTestResult, AnalysisOptions } from './settings';

// =============================================================================
// API RESPONSE WRAPPER
// =============================================================================

export interface APIResponse<T> {
  data: T;
  status: number;
  message?: string;
}

export interface APIError {
  status: number;
  message: string;
  detail?: string;
}

// =============================================================================
// ANALYSIS ENDPOINTS
// =============================================================================

export interface AnalyzeRequest {
  file?: File;
  raw_email?: string;
  options?: AnalysisOptions;
}

export type AnalyzeResponse = AnalysisResult;

export interface AnalysisListParams {
  limit?: number;
  offset?: number;
  risk_level?: string;
  classification?: string;
  search?: string;
}

export type AnalysisListResponseType = AnalysisListResponse;

// =============================================================================
// EXPORT ENDPOINTS
// =============================================================================

export type ExportFormat = 'json' | 'csv' | 'markdown' | 'iocs' | 'pdf' | 'executive-pdf' | 'stix';

export interface ExportRequest {
  analysis_id: string;
  format: ExportFormat;
}

export type ExportResponse = string | Blob;

// =============================================================================
// SETTINGS ENDPOINTS
// =============================================================================

export type GetSettingsResponse = SettingsResponse;

export interface UpdateSettingsRequest {
  [key: string]: string | number | boolean;
}

export type GetAPIKeysResponse = APIKeyStatus[];

export interface CreateAPIKeyRequest {
  service: string;
  key: string;
}

export type TestAPIKeyResponse = APIKeyTestResult;

// =============================================================================
// HEALTH ENDPOINTS
// =============================================================================

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  database: 'connected' | 'disconnected';
}

export interface DetailedHealthResponse extends HealthResponse {
  api_services: Record<string, {
    configured: boolean;
    enabled: boolean;
    last_test: string | null;
    status: 'ok' | 'error' | 'unknown';
  }>;
  uptime_seconds: number;
  analyses_count: number;
}
