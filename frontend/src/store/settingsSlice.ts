/**
 * NiksES Settings Store Slice
 * 
 * State management for application settings.
 */

import { StateCreator } from 'zustand';
import type { APIKeyStatus, SettingValue } from '../types';

export interface SettingsState {
  // Settings
  settings: Record<string, SettingValue>;
  apiKeys: APIKeyStatus[];
  isLoading: boolean;
  error: string | null;
  
  // UI State
  isSettingsModalOpen: boolean;
  activeSettingsTab: string;
  
  // Actions
  setSettings: (settings: SettingValue[]) => void;
  setSetting: (key: string, value: string | number | boolean) => void;
  setApiKeys: (apiKeys: APIKeyStatus[]) => void;
  updateApiKey: (service: string, status: Partial<APIKeyStatus>) => void;
  setIsLoading: (isLoading: boolean) => void;
  setError: (error: string | null) => void;
  openSettingsModal: () => void;
  closeSettingsModal: () => void;
  setActiveSettingsTab: (tab: string) => void;
}

export const createSettingsSlice: StateCreator<SettingsState> = (set) => ({
  // Initial state
  settings: {},
  apiKeys: [],
  isLoading: false,
  error: null,
  isSettingsModalOpen: false,
  activeSettingsTab: 'api-keys',
  
  // Actions
  setSettings: (settingsArray) => {
    const settings: Record<string, SettingValue> = {};
    settingsArray.forEach((s) => {
      settings[s.key] = s;
    });
    set({ settings });
  },
  setSetting: (key, value) => set((state) => ({
    settings: {
      ...state.settings,
      [key]: { ...state.settings[key], value },
    },
  })),
  setApiKeys: (apiKeys) => set({ apiKeys }),
  updateApiKey: (service, status) => set((state) => ({
    apiKeys: state.apiKeys.map((k) =>
      k.service === service ? { ...k, ...status } : k
    ),
  })),
  setIsLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
  openSettingsModal: () => set({ isSettingsModalOpen: true }),
  closeSettingsModal: () => set({ isSettingsModalOpen: false }),
  setActiveSettingsTab: (tab) => set({ activeSettingsTab: tab }),
});
