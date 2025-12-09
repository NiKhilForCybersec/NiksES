/**
 * NiksES Settings Types
 * 
 * TypeScript interfaces for settings and configuration.
 */

export type APIService = 
  | 'virustotal'
  | 'abuseipdb'
  | 'urlhaus'
  | 'phishtank'
  | 'whois'
  | 'openai'
  | 'shodan'
  | 'greynoise';

export interface APIKeyStatus {
  service: APIService;
  is_configured: boolean;
  is_enabled: boolean;
  last_tested: string | null;
  last_test_result: 'success' | 'failed' | 'rate_limited' | null;
  masked_key: string | null;
}

export interface APIKeyCreate {
  service: APIService;
  key: string;
}

export interface APIKeyTestResult {
  success: boolean;
  message: string;
  response_time_ms?: number;
}

export interface SettingValue {
  key: string;
  value: string | number | boolean;
  value_type: 'string' | 'int' | 'float' | 'bool' | 'json';
  category: string;
  description: string;
}

export interface SettingsResponse {
  settings: SettingValue[];
  api_keys: APIKeyStatus[];
}

export interface SettingsUpdate {
  [key: string]: string | number | boolean;
}

export interface AnalysisOptions {
  skip_enrichment?: boolean;
  skip_ai?: boolean;
  follow_redirects?: boolean;
}
