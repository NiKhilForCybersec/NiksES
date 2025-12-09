/**
 * NiksES History Hook
 * 
 * Hook for managing analysis history.
 */

import { useCallback, useEffect } from 'react';
import toast from 'react-hot-toast';
import { useHistoryStore, useAnalysisStore } from '../store';
import {
  getAnalyses,
  getAnalysis,
  deleteAnalysis,
  searchAnalyses,
} from '../services/historyService';

export function useHistory() {
  const {
    analyses,
    totalCount,
    isLoading,
    error,
    searchQuery,
    riskLevelFilter,
    classificationFilter,
    currentPage,
    pageSize,
    setAnalyses,
    removeAnalysis,
    setIsLoading,
    setError,
    setSearchQuery,
    setRiskLevelFilter,
    setClassificationFilter,
    setCurrentPage,
    clearFilters,
  } = useHistoryStore();

  const { setCurrentAnalysis } = useAnalysisStore();

  /**
   * Fetch analyses with current filters
   */
  const fetchAnalyses = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await getAnalyses({
        limit: pageSize,
        offset: (currentPage - 1) * pageSize,
        risk_level: riskLevelFilter || undefined,
        classification: classificationFilter || undefined,
        search: searchQuery || undefined,
      });

      setAnalyses(result.analyses, result.total);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch history';
      setError(message);
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  }, [
    pageSize,
    currentPage,
    riskLevelFilter,
    classificationFilter,
    searchQuery,
    setAnalyses,
    setIsLoading,
    setError,
  ]);

  /**
   * Load a specific analysis
   */
  const loadAnalysis = useCallback(
    async (analysisId: string) => {
      setIsLoading(true);
      setError(null);

      try {
        const result = await getAnalysis(analysisId);
        setCurrentAnalysis(result);
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to load analysis';
        setError(message);
        toast.error(message);
        throw error;
      } finally {
        setIsLoading(false);
      }
    },
    [setCurrentAnalysis, setIsLoading, setError]
  );

  /**
   * Delete an analysis
   */
  const removeAnalysisById = useCallback(
    async (analysisId: string) => {
      try {
        await deleteAnalysis(analysisId);
        removeAnalysis(analysisId);
        toast.success('Analysis deleted');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to delete analysis';
        toast.error(message);
        throw error;
      }
    },
    [removeAnalysis]
  );

  /**
   * Search analyses
   */
  const search = useCallback(
    async (query: string) => {
      setSearchQuery(query);
    },
    [setSearchQuery]
  );

  // Fetch analyses when filters change
  useEffect(() => {
    fetchAnalyses();
  }, [fetchAnalyses]);

  return {
    analyses,
    totalCount,
    isLoading,
    error,
    searchQuery,
    riskLevelFilter,
    classificationFilter,
    currentPage,
    pageSize,
    totalPages: Math.ceil(totalCount / pageSize),
    fetchAnalyses,
    loadAnalysis,
    removeAnalysisById,
    search,
    setRiskLevelFilter,
    setClassificationFilter,
    setCurrentPage,
    clearFilters,
  };
}

export default useHistory;
