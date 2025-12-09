/**
 * NiksES History Service
 * 
 * API calls for analysis history operations.
 */

import { get, del } from './api';
import type { AnalysisResult, AnalysisListResponse, ExtractedIOCs } from '../types';

export interface HistoryFilters {
  limit?: number;
  offset?: number;
  risk_level?: string;
  classification?: string;
  search?: string;
  start_date?: string;
  end_date?: string;
}

/**
 * Get list of past analyses
 */
export async function getAnalyses(filters?: HistoryFilters): Promise<AnalysisListResponse> {
  return get<AnalysisListResponse>('/analyses', { params: filters });
}

/**
 * Get a single analysis by ID
 */
export async function getAnalysis(analysisId: string): Promise<AnalysisResult> {
  return get<AnalysisResult>(`/analyses/${analysisId}`);
}

/**
 * Delete an analysis
 */
export async function deleteAnalysis(analysisId: string): Promise<void> {
  return del<void>(`/analyses/${analysisId}`);
}

/**
 * Get IOCs for an analysis
 */
export async function getAnalysisIOCs(analysisId: string): Promise<ExtractedIOCs> {
  return get<ExtractedIOCs>(`/analyses/${analysisId}/iocs`);
}

/**
 * Search analyses
 */
export async function searchAnalyses(query: string, limit = 50): Promise<AnalysisListResponse> {
  return get<AnalysisListResponse>('/analyses', {
    params: { search: query, limit },
  });
}

/**
 * Get recent analyses
 */
export async function getRecentAnalyses(limit = 10): Promise<AnalysisListResponse> {
  return get<AnalysisListResponse>('/analyses', {
    params: { limit, offset: 0 },
  });
}
