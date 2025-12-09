/**
 * NiksES History Store Slice
 * 
 * State management for analysis history.
 */

import { StateCreator } from 'zustand';
import type { AnalysisSummary } from '../types';

export interface HistoryState {
  // History list
  analyses: AnalysisSummary[];
  totalCount: number;
  isLoading: boolean;
  error: string | null;
  
  // Filters
  searchQuery: string;
  riskLevelFilter: string | null;
  classificationFilter: string | null;
  
  // Pagination
  currentPage: number;
  pageSize: number;
  
  // Actions
  setAnalyses: (analyses: AnalysisSummary[], total: number) => void;
  addAnalysis: (analysis: AnalysisSummary) => void;
  removeAnalysis: (analysisId: string) => void;
  setIsLoading: (isLoading: boolean) => void;
  setError: (error: string | null) => void;
  setSearchQuery: (query: string) => void;
  setRiskLevelFilter: (level: string | null) => void;
  setClassificationFilter: (classification: string | null) => void;
  setCurrentPage: (page: number) => void;
  clearFilters: () => void;
}

export const createHistorySlice: StateCreator<HistoryState> = (set) => ({
  // Initial state
  analyses: [],
  totalCount: 0,
  isLoading: false,
  error: null,
  searchQuery: '',
  riskLevelFilter: null,
  classificationFilter: null,
  currentPage: 1,
  pageSize: 50,
  
  // Actions
  setAnalyses: (analyses, total) => set({ analyses, totalCount: total }),
  addAnalysis: (analysis) => set((state) => ({
    analyses: [analysis, ...state.analyses],
    totalCount: state.totalCount + 1,
  })),
  removeAnalysis: (analysisId) => set((state) => ({
    analyses: state.analyses.filter((a) => a.analysis_id !== analysisId),
    totalCount: state.totalCount - 1,
  })),
  setIsLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
  setSearchQuery: (query) => set({ searchQuery: query, currentPage: 1 }),
  setRiskLevelFilter: (level) => set({ riskLevelFilter: level, currentPage: 1 }),
  setClassificationFilter: (classification) => set({ classificationFilter: classification, currentPage: 1 }),
  setCurrentPage: (page) => set({ currentPage: page }),
  clearFilters: () => set({
    searchQuery: '',
    riskLevelFilter: null,
    classificationFilter: null,
    currentPage: 1,
  }),
});
