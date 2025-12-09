/**
 * NiksES Keyboard Shortcuts Hook
 * 
 * Hook for handling keyboard shortcuts.
 */

import { useEffect, useCallback } from 'react';
import { useAnalysisStore } from '../store';
import { KEYBOARD_SHORTCUTS, RESULTS_TABS } from '../utils/constants';

interface KeyboardShortcutHandlers {
  onAnalyze?: () => void;
  onSearch?: () => void;
  onOpenSettings?: () => void;
  onCloseModal?: () => void;
}

export function useKeyboardShortcuts(handlers: KeyboardShortcutHandlers = {}) {
  const { setActiveTab } = useAnalysisStore();

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      const { key, ctrlKey, metaKey } = event;
      const modKey = ctrlKey || metaKey;

      // Don't trigger shortcuts when typing in inputs
      const target = event.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        // Allow Escape in inputs
        if (key !== 'Escape') {
          return;
        }
      }

      // Ctrl/Cmd + Enter - Analyze
      if (modKey && key === 'Enter') {
        event.preventDefault();
        handlers.onAnalyze?.();
        return;
      }

      // Ctrl/Cmd + K - Search
      if (modKey && key === 'k') {
        event.preventDefault();
        handlers.onSearch?.();
        return;
      }

      // Ctrl/Cmd + , - Settings
      if (modKey && key === ',') {
        event.preventDefault();
        handlers.onOpenSettings?.();
        return;
      }

      // Escape - Close modal
      if (key === 'Escape') {
        event.preventDefault();
        handlers.onCloseModal?.();
        return;
      }

      // Ctrl/Cmd + 1-5 - Switch tabs
      if (modKey && ['1', '2', '3', '4', '5'].includes(key)) {
        event.preventDefault();
        const tabIndex = parseInt(key, 10) - 1;
        const tab = RESULTS_TABS[tabIndex];
        if (tab) {
          setActiveTab(tab.id);
        }
        return;
      }
    },
    [handlers, setActiveTab]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);

  return {
    shortcuts: KEYBOARD_SHORTCUTS,
  };
}

export default useKeyboardShortcuts;
