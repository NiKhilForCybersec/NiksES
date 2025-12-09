/**
 * NiksES Analysis Hook
 * 
 * Hook for managing email analysis operations.
 */

import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { useAnalysisStore, useHistoryStore } from '../store';
import { analyzeFile, analyzeRawEmail } from '../services/analysisService';
import type { AnalysisOptions, AnalysisSummary } from '../types';

export function useAnalysis() {
  const {
    currentAnalysis,
    isAnalyzing,
    analysisProgress,
    analysisError,
    setCurrentAnalysis,
    setIsAnalyzing,
    setAnalysisProgress,
    setAnalysisError,
    clearAnalysis,
  } = useAnalysisStore();

  const { addAnalysis } = useHistoryStore();

  /**
   * Analyze an email file
   */
  const analyzeEmailFile = useCallback(
    async (file: File, options?: AnalysisOptions) => {
      setIsAnalyzing(true);
      setAnalysisProgress(0);
      setAnalysisError(null);

      try {
        const result = await analyzeFile(file, options, (progress) => {
          setAnalysisProgress(progress);
        });

        setCurrentAnalysis(result);
        
        // Add to history
        const summary: AnalysisSummary = {
          analysis_id: result.analysis_id,
          analyzed_at: result.analyzed_at,
          subject: result.email.subject,
          sender_email: result.email.sender?.email || null,
          sender_domain: result.email.sender?.domain || null,
          risk_score: result.detection.risk_score,
          risk_level: result.detection.risk_level,
          classification: result.detection.primary_classification,
          has_attachments: result.email.attachments.length > 0,
          has_urls: result.email.urls.length > 0,
          attachment_count: result.email.attachments.length,
          url_count: result.email.urls.length,
          ai_summary: result.ai_triage?.summary || null,
        };
        addAnalysis(summary);

        toast.success('Analysis complete!');
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Analysis failed';
        setAnalysisError(message);
        toast.error(message);
        throw error;
      } finally {
        setIsAnalyzing(false);
      }
    },
    [setCurrentAnalysis, setIsAnalyzing, setAnalysisProgress, setAnalysisError, addAnalysis]
  );

  /**
   * Analyze raw email text
   */
  const analyzeRawEmailText = useCallback(
    async (rawEmail: string, options?: AnalysisOptions) => {
      setIsAnalyzing(true);
      setAnalysisProgress(0);
      setAnalysisError(null);

      try {
        // Simulate progress for raw text (no file upload progress)
        setAnalysisProgress(30);
        
        const result = await analyzeRawEmail(rawEmail, options);
        
        setAnalysisProgress(100);
        setCurrentAnalysis(result);
        
        // Add to history
        const summary: AnalysisSummary = {
          analysis_id: result.analysis_id,
          analyzed_at: result.analyzed_at,
          subject: result.email.subject,
          sender_email: result.email.sender?.email || null,
          sender_domain: result.email.sender?.domain || null,
          risk_score: result.detection.risk_score,
          risk_level: result.detection.risk_level,
          classification: result.detection.primary_classification,
          has_attachments: result.email.attachments.length > 0,
          has_urls: result.email.urls.length > 0,
          attachment_count: result.email.attachments.length,
          url_count: result.email.urls.length,
          ai_summary: result.ai_triage?.summary || null,
        };
        addAnalysis(summary);

        toast.success('Analysis complete!');
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Analysis failed';
        setAnalysisError(message);
        toast.error(message);
        throw error;
      } finally {
        setIsAnalyzing(false);
      }
    },
    [setCurrentAnalysis, setIsAnalyzing, setAnalysisProgress, setAnalysisError, addAnalysis]
  );

  return {
    currentAnalysis,
    isAnalyzing,
    analysisProgress,
    analysisError,
    analyzeEmailFile,
    analyzeRawEmailText,
    clearAnalysis,
  };
}

export default useAnalysis;
