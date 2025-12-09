/**
 * NiksES Analysis Store Slice
 * 
 * State management for current analysis.
 */

import { StateCreator } from 'zustand';
import type { AnalysisResult } from '../types';

export interface AnalysisState {
  // Current analysis
  currentAnalysis: AnalysisResult | null;
  isAnalyzing: boolean;
  analysisProgress: number;
  analysisError: string | null;
  
  // Active tab
  activeTab: string;
  
  // Actions
  setCurrentAnalysis: (analysis: AnalysisResult | null) => void;
  setIsAnalyzing: (isAnalyzing: boolean) => void;
  setAnalysisProgress: (progress: number) => void;
  setAnalysisError: (error: string | null) => void;
  setActiveTab: (tab: string) => void;
  clearAnalysis: () => void;
}

export const createAnalysisSlice: StateCreator<AnalysisState> = (set) => ({
  // Initial state
  currentAnalysis: null,
  isAnalyzing: false,
  analysisProgress: 0,
  analysisError: null,
  activeTab: 'summary',
  
  // Actions
  setCurrentAnalysis: (analysis) => set({ currentAnalysis: analysis, analysisError: null }),
  setIsAnalyzing: (isAnalyzing) => set({ isAnalyzing }),
  setAnalysisProgress: (progress) => set({ analysisProgress: progress }),
  setAnalysisError: (error) => set({ analysisError: error, isAnalyzing: false }),
  setActiveTab: (tab) => set({ activeTab: tab }),
  clearAnalysis: () => set({
    currentAnalysis: null,
    isAnalyzing: false,
    analysisProgress: 0,
    analysisError: null,
  }),
});
