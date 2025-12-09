/**
 * API Setup Banner Component
 * 
 * Shows a dismissible banner when API keys are not configured.
 */

import React, { useState } from 'react';
import { AlertTriangle, X, Settings, ExternalLink } from 'lucide-react';

interface APISetupBannerProps {
  configuredCount: number;
  totalCount: number;
  onOpenSettings: () => void;
}

export function APISetupBanner({ configuredCount, totalCount, onOpenSettings }: APISetupBannerProps) {
  const [dismissed, setDismissed] = useState(false);

  // Don't show if all configured or user dismissed
  if (configuredCount >= 2 || dismissed) {
    return null;
  }

  return (
    <div className="bg-amber-900/50 border-b border-amber-700 px-6 py-2">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <div className="text-sm">
            <span className="text-amber-200 font-medium">
              {configuredCount === 0 
                ? 'No API keys configured' 
                : `Only ${configuredCount} API${configuredCount > 1 ? 's' : ''} configured`
              }
            </span>
            <span className="text-amber-300/80 ml-2">
              Add API keys to enable threat intelligence and AI analysis features.
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenSettings}
            className="flex items-center gap-1.5 px-3 py-1 bg-amber-600 hover:bg-amber-700 text-white text-sm rounded-lg transition"
          >
            <Settings className="w-4 h-4" />
            Configure
          </button>
          <button
            onClick={() => setDismissed(true)}
            className="p-1 text-amber-400 hover:text-amber-200 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default APISetupBanner;
