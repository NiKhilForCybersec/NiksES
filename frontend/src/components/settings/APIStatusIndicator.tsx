/**
 * API Status Indicator Component
 * 
 * Shows a compact view of configured API services in the header.
 * Clicking opens the full settings modal.
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Brain,
  Globe,
  Server,
  AlertCircle,
  CheckCircle,
  XCircle,
  Settings,
  ChevronDown,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react';

interface APIStatusIndicatorProps {
  settings: {
    enrichment_enabled: boolean;
    ai_enabled: boolean;
    ai_provider: 'anthropic' | 'openai';
    api_keys_configured: Record<string, boolean>;
    detection_rules_count: number;
  } | null;
  onOpenSettings: () => void;
}

export function APIStatusIndicator({ settings, onOpenSettings }: APIStatusIndicatorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!settings) {
    return (
      <button
        onClick={onOpenSettings}
        className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg transition text-sm"
      >
        <WifiOff className="w-4 h-4 text-slate-400" />
        <span className="text-slate-300">No Connection</span>
      </button>
    );
  }

  const configuredCount = Object.values(settings.api_keys_configured).filter(Boolean).length;
  const threatIntelConfigured = settings.api_keys_configured?.virustotal || settings.api_keys_configured?.abuseipdb;
  const aiConfigured = settings.api_keys_configured?.anthropic || settings.api_keys_configured?.openai;
  
  const getStatusColor = () => {
    if (configuredCount === 0) return 'bg-red-500';
    if (configuredCount < 3) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const services = [
    {
      name: 'VirusTotal',
      key: 'virustotal',
      icon: Globe,
      color: 'blue',
      category: 'Threat Intel',
    },
    {
      name: 'AbuseIPDB',
      key: 'abuseipdb',
      icon: Shield,
      color: 'orange',
      category: 'Threat Intel',
    },
    {
      name: 'PhishTank',
      key: 'phishtank',
      icon: AlertCircle,
      color: 'yellow',
      category: 'Threat Intel',
    },
    {
      name: 'MXToolbox',
      key: 'mxtoolbox',
      icon: Server,
      color: 'purple',
      category: 'Threat Intel',
    },
    {
      name: 'Anthropic',
      key: 'anthropic',
      icon: Brain,
      color: 'orange',
      category: 'AI',
    },
    {
      name: 'OpenAI',
      key: 'openai',
      icon: Zap,
      color: 'green',
      category: 'AI',
    },
  ];

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg transition text-sm group"
      >
        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${getStatusColor()}`} />
          <span className="text-slate-300">{configuredCount}/6 APIs</span>
        </div>
        <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-50 overflow-hidden">
          {/* Header */}
          <div className="p-3 border-b border-slate-700 bg-slate-900/50">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-white">API Services Status</span>
              <div className="flex items-center gap-1">
                <span className={`w-2 h-2 rounded-full ${getStatusColor()}`} />
                <span className="text-xs text-slate-400">{configuredCount} configured</span>
              </div>
            </div>
          </div>

          {/* Status Summary */}
          <div className="p-3 grid grid-cols-2 gap-2 border-b border-slate-700">
            <div className={`p-2 rounded-lg ${threatIntelConfigured && settings.enrichment_enabled ? 'bg-green-900/30 border border-green-700' : 'bg-slate-900/50 border border-slate-600'}`}>
              <div className="flex items-center gap-2">
                <Shield className={`w-4 h-4 ${threatIntelConfigured && settings.enrichment_enabled ? 'text-green-400' : 'text-slate-500'}`} />
                <span className={`text-xs font-medium ${threatIntelConfigured && settings.enrichment_enabled ? 'text-green-400' : 'text-slate-500'}`}>
                  Threat Intel
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {threatIntelConfigured && settings.enrichment_enabled ? 'Active' : 'Not configured'}
              </p>
            </div>
            <div className={`p-2 rounded-lg ${aiConfigured && settings.ai_enabled ? 'bg-purple-900/30 border border-purple-700' : 'bg-slate-900/50 border border-slate-600'}`}>
              <div className="flex items-center gap-2">
                <Brain className={`w-4 h-4 ${aiConfigured && settings.ai_enabled ? 'text-purple-400' : 'text-slate-500'}`} />
                <span className={`text-xs font-medium ${aiConfigured && settings.ai_enabled ? 'text-purple-400' : 'text-slate-500'}`}>
                  AI Analysis
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {aiConfigured && settings.ai_enabled ? `${settings.ai_provider === 'anthropic' ? 'Claude' : 'GPT-4'}` : 'Not configured'}
              </p>
            </div>
          </div>

          {/* Service List */}
          <div className="p-2 max-h-64 overflow-y-auto">
            {services.map((service) => {
              const isConfigured = settings.api_keys_configured[service.key];
              const Icon = service.icon;
              
              return (
                <div
                  key={service.key}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-700/50"
                >
                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 text-${service.color}-400`} />
                    <div>
                      <span className="text-sm text-white">{service.name}</span>
                      <span className="text-xs text-slate-500 ml-2">{service.category}</span>
                    </div>
                  </div>
                  {isConfigured ? (
                    <div className="flex items-center gap-1 text-green-400">
                      <CheckCircle className="w-4 h-4" />
                      <span className="text-xs">Ready</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 text-slate-500">
                      <XCircle className="w-4 h-4" />
                      <span className="text-xs">Not set</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-slate-700 bg-slate-900/50">
            <button
              onClick={() => {
                setIsOpen(false);
                onOpenSettings();
              }}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition text-sm font-medium"
            >
              <Settings className="w-4 h-4" />
              Open Settings
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default APIStatusIndicator;
