/**
 * NiksES Store
 * 
 * Combined Zustand store with all slices.
 */

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { createAnalysisSlice, AnalysisState } from './analysisSlice';
import { createHistorySlice, HistoryState } from './historySlice';
import { createSettingsSlice, SettingsState } from './settingsSlice';

// Combined store type
export type AppState = AnalysisState & HistoryState & SettingsState;

// Create combined store with persistence
export const useAppStore = create<AppState>()(
  persist(
    (...args) => ({
      ...createAnalysisSlice(...args),
      ...createHistorySlice(...args),
      ...createSettingsSlice(...args),
    }),
    {
      name: 'nikses-storage',
      storage: createJSONStorage(() => localStorage),
      // Only persist certain state
      partialize: (state) => ({
        // Persist history filters
        searchQuery: state.searchQuery,
        riskLevelFilter: state.riskLevelFilter,
        classificationFilter: state.classificationFilter,
        pageSize: state.pageSize,
        // Persist active tab preference
        activeTab: state.activeTab,
        activeSettingsTab: state.activeSettingsTab,
      }),
    }
  )
);

// Convenience hooks for specific slices
export const useAnalysisStore = () => {
  return useAppStore((state) => ({
    currentAnalysis: state.currentAnalysis,
    isAnalyzing: state.isAnalyzing,
    analysisProgress: state.analysisProgress,
    analysisError: state.analysisError,
    activeTab: state.activeTab,
    setCurrentAnalysis: state.setCurrentAnalysis,
    setIsAnalyzing: state.setIsAnalyzing,
    setAnalysisProgress: state.setAnalysisProgress,
    setAnalysisError: state.setAnalysisError,
    setActiveTab: state.setActiveTab,
    clearAnalysis: state.clearAnalysis,
  }));
};

export const useHistoryStore = () => {
  return useAppStore((state) => ({
    analyses: state.analyses,
    totalCount: state.totalCount,
    isLoading: state.isLoading,
    error: state.error,
    searchQuery: state.searchQuery,
    riskLevelFilter: state.riskLevelFilter,
    classificationFilter: state.classificationFilter,
    currentPage: state.currentPage,
    pageSize: state.pageSize,
    setAnalyses: state.setAnalyses,
    addAnalysis: state.addAnalysis,
    removeAnalysis: state.removeAnalysis,
    setIsLoading: state.setIsLoading,
    setError: state.setError,
    setSearchQuery: state.setSearchQuery,
    setRiskLevelFilter: state.setRiskLevelFilter,
    setClassificationFilter: state.setClassificationFilter,
    setCurrentPage: state.setCurrentPage,
    clearFilters: state.clearFilters,
  }));
};

export const useSettingsStore = () => {
  return useAppStore((state) => ({
    settings: state.settings,
    apiKeys: state.apiKeys,
    isLoading: state.isLoading,
    error: state.error,
    isSettingsModalOpen: state.isSettingsModalOpen,
    activeSettingsTab: state.activeSettingsTab,
    setSettings: state.setSettings,
    setSetting: state.setSetting,
    setApiKeys: state.setApiKeys,
    updateApiKey: state.updateApiKey,
    setIsLoading: state.setIsLoading,
    setError: state.setError,
    openSettingsModal: state.openSettingsModal,
    closeSettingsModal: state.closeSettingsModal,
    setActiveSettingsTab: state.setActiveSettingsTab,
  }));
};

export default useAppStore;
