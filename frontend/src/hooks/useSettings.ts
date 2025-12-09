/**
 * NiksES Settings Hook
 * 
 * Hook for managing application settings.
 */

import { useCallback, useEffect } from 'react';
import toast from 'react-hot-toast';
import { useSettingsStore } from '../store';
import {
  getSettings,
  updateSettings,
  getAPIKeys,
  setAPIKey,
  deleteAPIKey,
  testAPIKey,
  toggleAPIKey,
} from '../services/settingsService';

export function useSettings() {
  const {
    settings,
    apiKeys,
    isLoading,
    error,
    isSettingsModalOpen,
    activeSettingsTab,
    setSettings,
    setSetting,
    setApiKeys,
    updateApiKey,
    setIsLoading,
    setError,
    openSettingsModal,
    closeSettingsModal,
    setActiveSettingsTab,
  } = useSettingsStore();

  /**
   * Fetch all settings
   */
  const fetchSettings = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await getSettings();
      setSettings(result.settings);
      setApiKeys(result.api_keys);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch settings';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [setSettings, setApiKeys, setIsLoading, setError]);

  /**
   * Update a setting
   */
  const updateSetting = useCallback(
    async (key: string, value: string | number | boolean) => {
      try {
        await updateSettings({ [key]: value });
        setSetting(key, value);
        toast.success('Setting updated');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to update setting';
        toast.error(message);
        throw error;
      }
    },
    [setSetting]
  );

  /**
   * Add or update an API key
   */
  const saveAPIKey = useCallback(
    async (service: string, key: string) => {
      try {
        const result = await setAPIKey(service, key);
        updateApiKey(service, result);
        toast.success(`${service} API key saved`);
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to save API key';
        toast.error(message);
        throw error;
      }
    },
    [updateApiKey]
  );

  /**
   * Remove an API key
   */
  const removeAPIKey = useCallback(
    async (service: string) => {
      try {
        await deleteAPIKey(service);
        updateApiKey(service, {
          is_configured: false,
          masked_key: null,
          last_tested: null,
          last_test_result: null,
        });
        toast.success(`${service} API key removed`);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to remove API key';
        toast.error(message);
        throw error;
      }
    },
    [updateApiKey]
  );

  /**
   * Test an API key
   */
  const testKey = useCallback(
    async (service: string) => {
      try {
        const result = await testAPIKey(service);
        updateApiKey(service, {
          last_tested: new Date().toISOString(),
          last_test_result: result.success ? 'success' : 'failed',
        });
        
        if (result.success) {
          toast.success(`${service} API key is valid`);
        } else {
          toast.error(`${service} API key test failed: ${result.message}`);
        }
        
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to test API key';
        toast.error(message);
        throw error;
      }
    },
    [updateApiKey]
  );

  /**
   * Toggle API key enabled state
   */
  const toggleKey = useCallback(
    async (service: string, enabled: boolean) => {
      try {
        const result = await toggleAPIKey(service, enabled);
        updateApiKey(service, result);
        toast.success(`${service} ${enabled ? 'enabled' : 'disabled'}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to toggle API key';
        toast.error(message);
        throw error;
      }
    },
    [updateApiKey]
  );

  // Fetch settings on mount
  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  return {
    settings,
    apiKeys,
    isLoading,
    error,
    isSettingsModalOpen,
    activeSettingsTab,
    fetchSettings,
    updateSetting,
    saveAPIKey,
    removeAPIKey,
    testKey,
    toggleKey,
    openSettingsModal,
    closeSettingsModal,
    setActiveSettingsTab,
  };
}

export default useSettings;
