/**
 * Settings Context
 * 
 * Global context for settings state management across the application.
 * Provides real-time API status indicators and settings synchronization.
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { apiClient } from '../services/api';

export interface SettingsState {
  enrichment_enabled: boolean;
  ai_enabled: boolean;
  ai_provider: 'anthropic' | 'openai';
  api_keys_configured: Record<string, boolean>;
  detection_rules_count: number;
}

interface SettingsContextValue {
  settings: SettingsState | null;
  loading: boolean;
  error: string | null;
  configuredServicesCount: number;
  totalServicesCount: number;
  isAIReady: boolean;
  isThreatIntelReady: boolean;
  refreshSettings: () => Promise<void>;
}

const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSettings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/settings');
      setSettings(response.data);
    } catch (err) {
      console.error('Failed to load settings:', err);
      setError('Unable to connect to server');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
    
    // Poll for settings changes every 30 seconds
    const interval = setInterval(fetchSettings, 30000);
    return () => clearInterval(interval);
  }, [fetchSettings]);

  const configuredServicesCount = settings 
    ? Object.values(settings.api_keys_configured).filter(Boolean).length 
    : 0;
  
  const totalServicesCount = 6;
  
  const isAIReady = settings 
    ? settings.ai_enabled && (settings.api_keys_configured?.anthropic || settings.api_keys_configured?.openai)
    : false;
  
  const isThreatIntelReady = settings 
    ? settings.enrichment_enabled && (
        settings.api_keys_configured?.virustotal || 
        settings.api_keys_configured?.abuseipdb
      )
    : false;

  return (
    <SettingsContext.Provider value={{
      settings,
      loading,
      error,
      configuredServicesCount,
      totalServicesCount,
      isAIReady,
      isThreatIntelReady,
      refreshSettings: fetchSettings,
    }}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettingsContext() {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useSettingsContext must be used within a SettingsProvider');
  }
  return context;
}

export default SettingsContext;
