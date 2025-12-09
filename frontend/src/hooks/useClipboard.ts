/**
 * NiksES Clipboard Hook
 * 
 * Hook for clipboard operations.
 */

import { useState, useCallback } from 'react';
import toast from 'react-hot-toast';
import { copyToClipboard } from '../utils/helpers';

export function useClipboard(timeout = 2000) {
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const copy = useCallback(
    async (text: string, successMessage = 'Copied to clipboard') => {
      const success = await copyToClipboard(text);
      
      if (success) {
        setCopiedText(text);
        toast.success(successMessage);
        
        // Reset after timeout
        setTimeout(() => {
          setCopiedText(null);
        }, timeout);
      } else {
        toast.error('Failed to copy to clipboard');
      }
      
      return success;
    },
    [timeout]
  );

  const isCopied = useCallback(
    (text: string) => {
      return copiedText === text;
    },
    [copiedText]
  );

  return { copy, isCopied, copiedText };
}

export default useClipboard;
