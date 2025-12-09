/**
 * NiksES Analysis Service
 * 
 * API calls for email analysis operations.
 */

import { get, post, uploadFile, downloadBlob } from './api';
import type { AnalysisResult, AnalysisOptions, ExportFormat, EnhancedAnalysisResult } from '../types';

/**
 * Analyze an email file (standard analysis)
 */
export async function analyzeFile(
  file: File,
  options?: AnalysisOptions,
  onProgress?: (progress: number) => void
): Promise<AnalysisResult> {
  const additionalData: Record<string, string> = {};
  
  if (options) {
    if (options.skip_enrichment !== undefined) {
      additionalData.skip_enrichment = String(options.skip_enrichment);
    }
    if (options.skip_ai !== undefined) {
      additionalData.skip_ai = String(options.skip_ai);
    }
    if (options.follow_redirects !== undefined) {
      additionalData.follow_redirects = String(options.follow_redirects);
    }
  }

  return uploadFile<AnalysisResult>('/analyze', file, additionalData, onProgress);
}

/**
 * Enhanced analysis with multi-dimensional scoring
 * 
 * Features:
 * - Social Engineering Analysis
 * - Content Deconstruction
 * - Lookalike Domain Detection
 * - Unified TI Fusion (with 4-retry logic)
 * - Multi-dimensional Risk Scoring
 */
export async function analyzeFileEnhanced(
  file: File,
  options?: {
    enable_ti?: boolean;
    enable_llm?: boolean;
  },
  onProgress?: (progress: number) => void
): Promise<EnhancedAnalysisResult> {
  const additionalData: Record<string, string> = {
    enable_ti: String(options?.enable_ti ?? true),
    enable_llm: String(options?.enable_llm ?? true),
  };

  return uploadFile<EnhancedAnalysisResult>('/analyze/enhanced', file, additionalData, onProgress);
}

/**
 * Analyze raw email text
 */
export async function analyzeRawEmail(
  rawEmail: string,
  options?: AnalysisOptions
): Promise<AnalysisResult> {
  return post<AnalysisResult>('/analyze', {
    raw_email: rawEmail,
    options,
  });
}

/**
 * Re-analyze an existing analysis with new options
 */
export async function reanalyze(
  analysisId: string,
  options?: AnalysisOptions
): Promise<AnalysisResult> {
  return post<AnalysisResult>(`/analyses/${analysisId}/reanalyze`, { options });
}

// =============================================================================
// EXPORT FUNCTIONS
// =============================================================================

/**
 * Export analysis in the specified format
 */
export async function exportAnalysis(
  analysisId: string,
  format: ExportFormat
): Promise<Blob> {
  if (format === 'executive-pdf') {
    return downloadBlob(`/export/${analysisId}/executive-pdf`);
  }
  return downloadBlob(`/export/${analysisId}`, { format });
}

/**
 * Export as Executive PDF (professional report for forwarding)
 */
export async function exportExecutivePDF(analysisId: string): Promise<Blob> {
  return downloadBlob(`/export/${analysisId}/executive-pdf`);
}

/**
 * Export as Technical PDF (detailed technical report)
 */
export async function exportTechnicalPDF(analysisId: string): Promise<Blob> {
  return downloadBlob(`/export/${analysisId}`, { format: 'pdf' });
}

/**
 * Export as STIX 2.1 bundle
 */
export async function exportSTIX(analysisId: string): Promise<Blob> {
  return downloadBlob(`/export/${analysisId}`, { format: 'stix' });
}

/**
 * Export as Markdown
 */
export async function exportMarkdown(analysisId: string): Promise<Blob> {
  return downloadBlob(`/export/${analysisId}`, { format: 'markdown' });
}

/**
 * Export as JSON
 */
export async function exportJSON(analysisId: string): Promise<string> {
  return get<string>(`/export/${analysisId}`, { params: { format: 'json' } });
}

/**
 * Export IOCs only (text format)
 */
export async function exportIOCs(analysisId: string): Promise<Blob> {
  return downloadBlob(`/export/${analysisId}`, { format: 'iocs' });
}

/**
 * Get appropriate filename for export format
 */
export function getExportFilename(analysisId: string, format: ExportFormat): string {
  const timestamp = new Date().toISOString().slice(0, 10);
  const shortId = analysisId.slice(0, 8);
  
  const extensions: Record<ExportFormat, string> = {
    json: 'json',
    csv: 'csv',
    markdown: 'md',
    iocs: 'txt',
    pdf: 'pdf',
    'executive-pdf': 'pdf',
    stix: 'json',
  };
  
  const prefixes: Record<ExportFormat, string> = {
    json: 'analysis',
    csv: 'analysis',
    markdown: 'report',
    iocs: 'iocs',
    pdf: 'technical-report',
    'executive-pdf': 'executive-report',
    stix: 'stix-bundle',
  };
  
  return `nikses-${prefixes[format]}-${shortId}-${timestamp}.${extensions[format]}`;
}

/**
 * Download export with automatic filename
 */
export async function downloadExport(analysisId: string, format: ExportFormat): Promise<void> {
  const blob = await exportAnalysis(analysisId, format);
  const filename = getExportFilename(analysisId, format);
  
  // Create download link
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
