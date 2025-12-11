/**
 * SettingsModal Component
 * 
 * Comprehensive settings management with dark theme styling.
 * Manages API keys, threat intelligence, AI analysis, and detection configuration.
 */

import React, { useState, useEffect } from 'react';
import {
  X,
  Settings,
  Key,
  Shield,
  Brain,
  Globe,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  RefreshCw,
  Save,
  Loader2,
  ExternalLink,
  Info,
  Zap,
  AlertCircle,
  AlertTriangle,
  Server,
  Wifi,
  WifiOff,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { apiClient } from '../../services/api';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSettingsChange?: (settings: SettingsState) => void;
}

interface APIKeyConfig {
  virustotal_api_key?: string;
  abuseipdb_api_key?: string;
  phishtank_api_key?: string;
  mxtoolbox_api_key?: string;
  hybrid_analysis_api_key?: string;
  anthropic_api_key?: string;
  openai_api_key?: string;
}

export interface SettingsState {
  enrichment_enabled: boolean;
  ai_enabled: boolean;
  ai_provider: 'anthropic' | 'openai';
  api_keys_configured: Record<string, boolean>;
  detection_rules_count: number;
}

interface DetectionConfig {
  config: {
    custom_suspicious_tlds: string[];
    custom_spam_keywords: string[];
    custom_romance_keywords: string[];
    custom_freemail_domains: string[];
    whitelisted_domains: string[];
    whitelisted_senders: string[];
    high_risk_countries: string[];
    custom_financial_domains: string[];
    risk_threshold_high: number;
    risk_threshold_critical: number;
    enable_geoip: boolean;
    enable_whois: boolean;
    enable_ai_description: boolean;
  };
  effective: {
    all_suspicious_tlds: string[];
    all_spam_keywords: string[];
    all_freemail_domains: string[];
    all_financial_domains: string[];
  };
}

export function SettingsModal({ isOpen, onClose, onSettingsChange }: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState<'threat-intel' | 'ai' | 'detection' | 'advanced'>('threat-intel');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [detectionConfig, setDetectionConfig] = useState<DetectionConfig | null>(null);
  
  // API Keys state
  const [apiKeys, setApiKeys] = useState<APIKeyConfig>({});
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [testingProvider, setTestingProvider] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({});
  
  // Toggles
  const [enrichmentEnabled, setEnrichmentEnabled] = useState(true);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiProvider, setAiProvider] = useState<'anthropic' | 'openai'>('openai');

  // Whitelist inputs
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('');
  const [newWhitelistSender, setNewWhitelistSender] = useState('');

  // Load settings on mount
  useEffect(() => {
    if (isOpen) {
      loadSettings();
      loadDetectionConfig();
    }
  }, [isOpen]);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('/settings');
      const data = response.data;
      setSettings(data);
      setEnrichmentEnabled(data.enrichment_enabled);
      setAiEnabled(data.ai_enabled);
      setAiProvider(data.ai_provider || 'openai');
      onSettingsChange?.(data);
    } catch (error) {
      console.error('Failed to load settings:', error);
      toast.error('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const loadDetectionConfig = async () => {
    try {
      const response = await apiClient.get('/settings/detection-config');
      setDetectionConfig(response.data);
    } catch (error) {
      console.error('Failed to load detection config:', error);
    }
  };

  const saveSettings = async () => {
    try {
      setSaving(true);
      
      const updates: any = {
        enable_enrichment: enrichmentEnabled,
        enable_ai: aiEnabled,
        ai_provider: aiProvider,
      };
      
      // Only include non-empty API keys
      const keysToSave: APIKeyConfig = {};
      Object.entries(apiKeys).forEach(([key, value]) => {
        if (value && value.trim()) {
          (keysToSave as any)[key] = value.trim();
        }
      });
      
      if (Object.keys(keysToSave).length > 0) {
        updates.api_keys = keysToSave;
      }
      
      await apiClient.patch('/settings', updates);
      toast.success('Settings saved successfully');
      setApiKeys({}); // Clear entered keys
      await loadSettings();
    } catch (error: any) {
      console.error('Failed to save settings:', error);
      toast.error(error?.response?.data?.detail || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async (provider: string) => {
    try {
      setTestingProvider(provider);
      setTestResults(prev => ({ ...prev, [provider]: { success: false } }));
      
      const response = await apiClient.post(`/settings/test-connection/${provider}`);
      const result = response.data;
      
      setTestResults(prev => ({
        ...prev,
        [provider]: { success: result.success, message: result.message || result.error }
      }));
      
      if (result.success) {
        toast.success(`${provider} connection successful!`);
      } else {
        toast.error(`${provider} connection failed: ${result.error || 'Unknown error'}`);
      }
    } catch (error: any) {
      setTestResults(prev => ({
        ...prev,
        [provider]: { success: false, message: 'Connection failed' }
      }));
      toast.error(`Failed to test ${provider} connection`);
    } finally {
      setTestingProvider(null);
    }
  };

  const toggleShowKey = (key: string) => {
    setShowKeys(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleKeyChange = (key: keyof APIKeyConfig, value: string) => {
    setApiKeys(prev => ({ ...prev, [key]: value }));
  };

  const addWhitelistDomain = async () => {
    if (!newWhitelistDomain.trim()) return;
    try {
      const response = await apiClient.post(`/settings/detection-config/whitelist-domain?domain=${encodeURIComponent(newWhitelistDomain)}`);
      const result = response.data;
      if (result.success) {
        toast.success(result.message);
        setNewWhitelistDomain('');
        loadDetectionConfig();
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error('Failed to add domain');
    }
  };

  const addWhitelistSender = async () => {
    if (!newWhitelistSender.trim()) return;
    try {
      const response = await apiClient.post(`/settings/detection-config/whitelist-sender?email=${encodeURIComponent(newWhitelistSender)}`);
      const result = response.data;
      if (result.success) {
        toast.success(result.message);
        setNewWhitelistSender('');
        loadDetectionConfig();
      } else {
        toast.error(result.message);
      }
    } catch (error) {
      toast.error('Failed to add sender');
    }
  };

  if (!isOpen) return null;

  const configuredCount = settings ? Object.values(settings.api_keys_configured).filter(Boolean).length : 0;
  const totalProviders = 6;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden border border-slate-700">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Settings className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">Settings</h2>
              <p className="text-sm text-slate-400">
                {configuredCount}/{totalProviders} services configured
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-700 bg-slate-900/50">
          <button
            onClick={() => setActiveTab('threat-intel')}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition-colors ${
              activeTab === 'threat-intel'
                ? 'text-blue-400 border-b-2 border-blue-400 bg-slate-800/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4" />
            Threat Intelligence
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition-colors ${
              activeTab === 'ai'
                ? 'text-purple-400 border-b-2 border-purple-400 bg-slate-800/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Brain className="w-4 h-4" />
            AI Analysis
          </button>
          <button
            onClick={() => setActiveTab('detection')}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition-colors ${
              activeTab === 'detection'
                ? 'text-green-400 border-b-2 border-green-400 bg-slate-800/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Zap className="w-4 h-4" />
            Detection Engine
          </button>
          <button
            onClick={() => setActiveTab('advanced')}
            className={`flex items-center gap-2 px-6 py-3 font-medium transition-colors ${
              activeTab === 'advanced'
                ? 'text-orange-400 border-b-2 border-orange-400 bg-slate-800/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-4 h-4" />
            Advanced
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[60vh]">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
            </div>
          ) : (
            <>
              {/* Threat Intelligence Tab */}
              {activeTab === 'threat-intel' && (
                <div className="space-y-6">
                  {/* Master Toggle */}
                  <div className="flex items-center justify-between p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${enrichmentEnabled ? 'bg-green-500' : 'bg-slate-500'}`} />
                      <div>
                        <h3 className="font-medium text-white">Enable Threat Intelligence</h3>
                        <p className="text-sm text-slate-400">Query external threat feeds during analysis</p>
                      </div>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={enrichmentEnabled}
                        onChange={(e) => setEnrichmentEnabled(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>

                  {/* VirusTotal */}
                  <APIKeyInput
                    name="VirusTotal"
                    description="Scan URLs, domains, and file hashes against VT database"
                    keyName="virustotal_api_key"
                    value={apiKeys.virustotal_api_key || ''}
                    onChange={(value) => handleKeyChange('virustotal_api_key', value)}
                    showKey={showKeys['virustotal'] || false}
                    onToggleShow={() => toggleShowKey('virustotal')}
                    isConfigured={settings?.api_keys_configured?.virustotal || false}
                    onTest={() => testConnection('virustotal')}
                    isTesting={testingProvider === 'virustotal'}
                    testResult={testResults['virustotal']}
                    signupUrl="https://www.virustotal.com/gui/join-us"
                    icon={<Globe className="w-5 h-5 text-blue-400" />}
                    rateLimit="4 req/min (free tier)"
                  />

                  {/* AbuseIPDB */}
                  <APIKeyInput
                    name="AbuseIPDB"
                    description="Check IP reputation and abuse reports"
                    keyName="abuseipdb_api_key"
                    value={apiKeys.abuseipdb_api_key || ''}
                    onChange={(value) => handleKeyChange('abuseipdb_api_key', value)}
                    showKey={showKeys['abuseipdb'] || false}
                    onToggleShow={() => toggleShowKey('abuseipdb')}
                    isConfigured={settings?.api_keys_configured?.abuseipdb || false}
                    onTest={() => testConnection('abuseipdb')}
                    isTesting={testingProvider === 'abuseipdb'}
                    testResult={testResults['abuseipdb']}
                    signupUrl="https://www.abuseipdb.com/register"
                    icon={<Shield className="w-5 h-5 text-orange-400" />}
                    rateLimit="1000 req/day (free tier)"
                  />

                  {/* PhishTank */}
                  <APIKeyInput
                    name="PhishTank"
                    description="Check URLs against known phishing database"
                    keyName="phishtank_api_key"
                    value={apiKeys.phishtank_api_key || ''}
                    onChange={(value) => handleKeyChange('phishtank_api_key', value)}
                    showKey={showKeys['phishtank'] || false}
                    onToggleShow={() => toggleShowKey('phishtank')}
                    isConfigured={settings?.api_keys_configured?.phishtank || false}
                    onTest={() => testConnection('phishtank')}
                    isTesting={testingProvider === 'phishtank'}
                    testResult={testResults['phishtank']}
                    signupUrl="https://phishtank.org/register.php"
                    icon={<AlertCircle className="w-5 h-5 text-yellow-400" />}
                    rateLimit="Optional API key"
                  />

                  {/* MXToolbox */}
                  <APIKeyInput
                    name="MXToolbox"
                    description="DNS, MX records, SPF/DKIM/DMARC validation, blacklist checks"
                    keyName="mxtoolbox_api_key"
                    value={apiKeys.mxtoolbox_api_key || ''}
                    onChange={(value) => handleKeyChange('mxtoolbox_api_key', value)}
                    showKey={showKeys['mxtoolbox'] || false}
                    onToggleShow={() => toggleShowKey('mxtoolbox')}
                    isConfigured={settings?.api_keys_configured?.mxtoolbox || false}
                    onTest={() => testConnection('mxtoolbox')}
                    isTesting={testingProvider === 'mxtoolbox'}
                    testResult={testResults['mxtoolbox']}
                    signupUrl="https://mxtoolbox.com/User/Api/"
                    icon={<Server className="w-5 h-5 text-purple-400" />}
                    rateLimit="Varies by plan"
                  />

                  {/* Hybrid Analysis - Sandbox */}
                  <APIKeyInput
                    name="Hybrid Analysis"
                    description="Dynamic malware sandbox for attachment analysis. Detects malware, MITRE ATT&CK techniques, network IOCs."
                    keyName="hybrid_analysis_api_key"
                    value={apiKeys.hybrid_analysis_api_key || ''}
                    onChange={(value) => handleKeyChange('hybrid_analysis_api_key', value)}
                    showKey={showKeys['hybrid_analysis'] || false}
                    onToggleShow={() => toggleShowKey('hybrid_analysis')}
                    isConfigured={settings?.api_keys_configured?.hybrid_analysis || false}
                    onTest={() => testConnection('hybrid_analysis')}
                    isTesting={testingProvider === 'hybrid_analysis'}
                    testResult={testResults['hybrid_analysis']}
                    signupUrl="https://www.hybrid-analysis.com/apikeys/info"
                    icon={<Shield className="w-5 h-5 text-pink-400" />}
                    rateLimit="100 submissions/month (free)"
                  />

                  <div className="p-4 bg-blue-900/30 rounded-lg border border-blue-700">
                    <div className="flex items-start gap-3">
                      <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-blue-200">
                        <p className="font-medium">Free Tier APIs Available</p>
                        <p className="text-blue-300/80">VirusTotal, AbuseIPDB, and PhishTank all offer free API access for personal/research use. Requests are automatically throttled to respect rate limits.</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* AI Analysis Tab */}
              {activeTab === 'ai' && (
                <div className="space-y-6">
                  {/* Master Toggle */}
                  <div className="flex items-center justify-between p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${aiEnabled ? 'bg-purple-500' : 'bg-slate-500'}`} />
                      <div>
                        <h3 className="font-medium text-white">Enable AI Analysis</h3>
                        <p className="text-sm text-slate-400">Use AI to generate insights and recommendations</p>
                      </div>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={aiEnabled}
                        onChange={(e) => setAiEnabled(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-purple-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                    </label>
                  </div>

                  {/* AI Provider Selection */}
                  <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <h3 className="font-medium text-white mb-3">Preferred AI Provider</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <label className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                        aiProvider === 'anthropic' 
                          ? 'border-orange-500 bg-orange-500/10' 
                          : 'border-slate-600 hover:border-slate-500 bg-slate-800/50'
                      }`}>
                        <input
                          type="radio"
                          name="ai-provider"
                          value="anthropic"
                          checked={aiProvider === 'anthropic'}
                          onChange={() => setAiProvider('anthropic')}
                          className="sr-only"
                        />
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-orange-900/50 rounded-lg flex items-center justify-center">
                            <Brain className="w-5 h-5 text-orange-400" />
                          </div>
                          <div>
                            <div className="font-medium text-white">Anthropic Claude</div>
                            <div className="text-sm text-slate-400">claude-3-sonnet</div>
                          </div>
                          {settings?.api_keys_configured?.anthropic && (
                            <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />
                          )}
                        </div>
                      </label>
                      <label className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                        aiProvider === 'openai' 
                          ? 'border-green-500 bg-green-500/10' 
                          : 'border-slate-600 hover:border-slate-500 bg-slate-800/50'
                      }`}>
                        <input
                          type="radio"
                          name="ai-provider"
                          value="openai"
                          checked={aiProvider === 'openai'}
                          onChange={() => setAiProvider('openai')}
                          className="sr-only"
                        />
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-green-900/50 rounded-lg flex items-center justify-center">
                            <Zap className="w-5 h-5 text-green-400" />
                          </div>
                          <div>
                            <div className="font-medium text-white">OpenAI</div>
                            <div className="text-sm text-slate-400">gpt-4-turbo</div>
                          </div>
                          {settings?.api_keys_configured?.openai && (
                            <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />
                          )}
                        </div>
                      </label>
                    </div>
                  </div>

                  {/* Anthropic */}
                  <APIKeyInput
                    name="Anthropic"
                    description="Claude AI for threat analysis and recommendations"
                    keyName="anthropic_api_key"
                    value={apiKeys.anthropic_api_key || ''}
                    onChange={(value) => handleKeyChange('anthropic_api_key', value)}
                    showKey={showKeys['anthropic'] || false}
                    onToggleShow={() => toggleShowKey('anthropic')}
                    isConfigured={settings?.api_keys_configured?.anthropic || false}
                    onTest={() => testConnection('anthropic')}
                    isTesting={testingProvider === 'anthropic'}
                    testResult={testResults['anthropic']}
                    signupUrl="https://console.anthropic.com/"
                    icon={<Brain className="w-5 h-5 text-orange-400" />}
                    rateLimit="Pay per token"
                  />

                  {/* OpenAI */}
                  <APIKeyInput
                    name="OpenAI"
                    description="GPT-4 for threat analysis and recommendations"
                    keyName="openai_api_key"
                    value={apiKeys.openai_api_key || ''}
                    onChange={(value) => handleKeyChange('openai_api_key', value)}
                    showKey={showKeys['openai'] || false}
                    onToggleShow={() => toggleShowKey('openai')}
                    isConfigured={settings?.api_keys_configured?.openai || false}
                    onTest={() => testConnection('openai')}
                    isTesting={testingProvider === 'openai'}
                    testResult={testResults['openai']}
                    signupUrl="https://platform.openai.com/signup"
                    icon={<Zap className="w-5 h-5 text-green-400" />}
                    rateLimit="Pay per token"
                  />

                  <div className="p-4 bg-purple-900/30 rounded-lg border border-purple-700">
                    <div className="flex items-start gap-3">
                      <Brain className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-purple-200">
                        <p className="font-medium">AI-Powered Analysis Features</p>
                        <p className="text-purple-300/80">When enabled, AI will analyze email content and provide threat assessment, key findings, social engineering detection, and MITRE ATT&CK technique mapping.</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Detection Engine Tab */}
              {activeTab === 'detection' && (
                <div className="space-y-6">
                  <div className="p-6 bg-slate-900/50 rounded-lg border border-slate-700">
                    <div className="flex items-center gap-4 mb-4">
                      <div className="w-16 h-16 bg-green-900/50 rounded-xl flex items-center justify-center">
                        <Zap className="w-8 h-8 text-green-400" />
                      </div>
                      <div>
                        <h3 className="text-xl font-semibold text-white">Detection Engine</h3>
                        <p className="text-slate-400">Built-in rule-based threat detection</p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-4 mt-6">
                      <div className="p-4 bg-slate-800 rounded-lg border border-slate-700">
                        <div className="text-3xl font-bold text-green-400">
                          {settings?.detection_rules_count || 51}
                        </div>
                        <div className="text-sm text-slate-400">Detection Rules</div>
                      </div>
                      <div className="p-4 bg-slate-800 rounded-lg border border-slate-700">
                        <div className="text-3xl font-bold text-blue-400">7</div>
                        <div className="text-sm text-slate-400">Categories</div>
                      </div>
                      <div className="p-4 bg-slate-800 rounded-lg border border-slate-700">
                        <div className="flex items-center gap-2">
                          <Wifi className="w-6 h-6 text-green-400" />
                          <span className="text-lg font-bold text-green-400">Active</span>
                        </div>
                        <div className="text-sm text-slate-400">Engine Status</div>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h4 className="font-medium text-white">Rule Categories</h4>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { name: 'Phishing Detection', count: 12, bgColor: 'bg-red-900/30', textColor: 'text-red-400', borderColor: 'border-red-800' },
                        { name: 'BEC Detection', count: 8, bgColor: 'bg-orange-900/30', textColor: 'text-orange-400', borderColor: 'border-orange-800' },
                        { name: 'Brand Impersonation', count: 6, bgColor: 'bg-yellow-900/30', textColor: 'text-yellow-400', borderColor: 'border-yellow-800' },
                        { name: 'Social Engineering', count: 8, bgColor: 'bg-purple-900/30', textColor: 'text-purple-400', borderColor: 'border-purple-800' },
                        { name: 'Malware Indicators', count: 5, bgColor: 'bg-pink-900/30', textColor: 'text-pink-400', borderColor: 'border-pink-800' },
                        { name: 'Authentication', count: 6, bgColor: 'bg-blue-900/30', textColor: 'text-blue-400', borderColor: 'border-blue-800' },
                        { name: 'Lookalike Domains', count: 4, bgColor: 'bg-cyan-900/30', textColor: 'text-cyan-400', borderColor: 'border-cyan-800' },
                        { name: 'IP Reputation', count: 2, bgColor: 'bg-green-900/30', textColor: 'text-green-400', borderColor: 'border-green-800' },
                      ].map(category => (
                        <div key={category.name} className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                          <span className="text-sm text-slate-300">{category.name}</span>
                          <span className={`px-2 py-1 text-xs font-medium rounded ${category.bgColor} ${category.textColor} border ${category.borderColor}`}>
                            {category.count} rules
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-green-900/30 rounded-lg border border-green-700">
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-green-200">
                        <p className="font-medium">No API Key Required</p>
                        <p className="text-green-300/80">The detection engine runs locally and doesn't require any external API keys. All rules include MITRE ATT&CK mapping.</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Advanced Tab */}
              {activeTab === 'advanced' && (
                <div className="space-y-6">
                  {/* Whitelisted Domains */}
                  <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <h4 className="font-medium text-white mb-3 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-green-400" />
                      Whitelisted Domains
                    </h4>
                    <p className="text-sm text-slate-400 mb-3">Domains in this list will not trigger detection rules.</p>
                    
                    <div className="flex gap-2 mb-3">
                      <input
                        type="text"
                        value={newWhitelistDomain}
                        onChange={(e) => setNewWhitelistDomain(e.target.value)}
                        placeholder="example.com"
                        className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        onKeyDown={(e) => e.key === 'Enter' && addWhitelistDomain()}
                      />
                      <button
                        onClick={addWhitelistDomain}
                        className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition"
                      >
                        Add
                      </button>
                    </div>
                    
                    <div className="flex flex-wrap gap-2">
                      {detectionConfig?.config.whitelisted_domains && detectionConfig.config.whitelisted_domains.length > 0 ? (
                        detectionConfig.config.whitelisted_domains.map((domain, i) => (
                          <span key={i} className="px-2 py-1 bg-green-900/30 text-green-400 text-sm rounded border border-green-700 flex items-center gap-1">
                            {domain}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-sm">No domains whitelisted</span>
                      )}
                    </div>
                  </div>

                  {/* Whitelisted Senders */}
                  <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <h4 className="font-medium text-white mb-3 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-blue-400" />
                      Whitelisted Senders
                    </h4>
                    <p className="text-sm text-slate-400 mb-3">Emails from these senders will bypass detection.</p>
                    
                    <div className="flex gap-2 mb-3">
                      <input
                        type="email"
                        value={newWhitelistSender}
                        onChange={(e) => setNewWhitelistSender(e.target.value)}
                        placeholder="user@example.com"
                        className="flex-1 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        onKeyDown={(e) => e.key === 'Enter' && addWhitelistSender()}
                      />
                      <button
                        onClick={addWhitelistSender}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition"
                      >
                        Add
                      </button>
                    </div>
                    
                    <div className="flex flex-wrap gap-2">
                      {detectionConfig?.config.whitelisted_senders && detectionConfig.config.whitelisted_senders.length > 0 ? (
                        detectionConfig.config.whitelisted_senders.map((sender, i) => (
                          <span key={i} className="px-2 py-1 bg-blue-900/30 text-blue-400 text-sm rounded border border-blue-700 flex items-center gap-1">
                            {sender}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-sm">No senders whitelisted</span>
                      )}
                    </div>
                  </div>

                  {/* Risk Thresholds */}
                  <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <h4 className="font-medium text-white mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      Risk Thresholds
                    </h4>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm text-slate-400">High Risk Threshold</label>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-2xl font-bold text-yellow-400">
                            {detectionConfig?.config.risk_threshold_high || 40}
                          </span>
                          <span className="text-slate-500">/ 100</span>
                        </div>
                      </div>
                      <div>
                        <label className="text-sm text-slate-400">Critical Risk Threshold</label>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-2xl font-bold text-red-400">
                            {detectionConfig?.config.risk_threshold_critical || 70}
                          </span>
                          <span className="text-slate-500">/ 100</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Feature Toggles */}
                  <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
                    <h4 className="font-medium text-white mb-3">Feature Toggles</h4>
                    <div className="space-y-3">
                      {[
                        { name: 'GeoIP Lookup', enabled: detectionConfig?.config.enable_geoip, desc: 'Resolve IP locations' },
                        { name: 'WHOIS Lookup', enabled: detectionConfig?.config.enable_whois, desc: 'Query domain registration' },
                        { name: 'AI Descriptions', enabled: detectionConfig?.config.enable_ai_description, desc: 'Generate AI threat summaries' },
                      ].map(feature => (
                        <div key={feature.name} className="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                          <div>
                            <span className="text-sm text-white">{feature.name}</span>
                            <p className="text-xs text-slate-500">{feature.desc}</p>
                          </div>
                          <div className={`px-2 py-1 text-xs rounded ${feature.enabled ? 'bg-green-900/50 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
                            {feature.enabled ? 'Enabled' : 'Disabled'}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-700 bg-slate-900">
          <button
            onClick={loadSettings}
            className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-slate-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={saveSettings}
              disabled={saving}
              className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {saving ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// API Key Input Component
interface APIKeyInputProps {
  name: string;
  description: string;
  keyName: string;
  value: string;
  onChange: (value: string) => void;
  showKey: boolean;
  onToggleShow: () => void;
  isConfigured: boolean;
  onTest: () => void;
  isTesting: boolean;
  testResult?: { success: boolean; message?: string };
  signupUrl: string;
  icon: React.ReactNode;
  rateLimit?: string;
}

function APIKeyInput({
  name,
  description,
  value,
  onChange,
  showKey,
  onToggleShow,
  isConfigured,
  onTest,
  isTesting,
  testResult,
  signupUrl,
  icon,
  rateLimit,
}: APIKeyInputProps) {
  return (
    <div className="p-4 bg-slate-900/50 rounded-lg border border-slate-700">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-slate-800 rounded-lg flex items-center justify-center">
            {icon}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="font-medium text-white">{name}</h4>
              {isConfigured ? (
                <span className="flex items-center gap-1 px-2 py-0.5 bg-green-900/50 text-green-400 text-xs rounded-full border border-green-700">
                  <CheckCircle className="w-3 h-3" />
                  Configured
                </span>
              ) : (
                <span className="flex items-center gap-1 px-2 py-0.5 bg-slate-700 text-slate-400 text-xs rounded-full">
                  <XCircle className="w-3 h-3" />
                  Not configured
                </span>
              )}
              {testResult && (
                <span className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded-full ${
                  testResult.success 
                    ? 'bg-green-900/50 text-green-400 border border-green-700' 
                    : 'bg-red-900/50 text-red-400 border border-red-700'
                }`}>
                  {testResult.success ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  {testResult.success ? 'Connected' : 'Failed'}
                </span>
              )}
            </div>
            <p className="text-sm text-slate-400">{description}</p>
            {rateLimit && (
              <p className="text-xs text-slate-500 mt-1">Rate limit: {rateLimit}</p>
            )}
          </div>
        </div>
        <a
          href={signupUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300"
        >
          Get API Key
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>
      
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Key className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type={showKey ? 'text' : 'password'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={isConfigured ? '••••••••••••••••' : 'Enter API key...'}
            className="w-full pl-10 pr-10 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
          <button
            type="button"
            onClick={onToggleShow}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-500 hover:text-slate-300"
          >
            {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        <button
          type="button"
          onClick={onTest}
          disabled={isTesting || (!isConfigured && !value)}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-slate-300"
        >
          {isTesting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          Test
        </button>
      </div>
    </div>
  );
}

export default SettingsModal;
