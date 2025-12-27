/**
 * NiksES SOC Tools Panel
 * 
 * Comprehensive SOC analyst utilities including:
 * - IOC Quick Actions (copy, export, defang)
 * - YARA/Sigma Rule Generator
 * - Incident Ticket Generator
 * - Response Playbook
 * - User Notification Templates
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Copy,
  Download,
  Shield,
  FileText,
  CheckSquare,
  Mail,
  ChevronDown,
  ChevronRight,
  Check,
  Clipboard,
  Code,
  Users,
  Clock,
  Target,
  FileCode,
  Zap,
  Globe,
  Link2,
  Eye,
} from 'lucide-react';
import { apiClient } from '../../services/api';

interface SOCToolsProps {
  analysisResult: any;
}

type TabType = 'iocs' | 'rules' | 'ticket' | 'playbook' | 'notification';

const SOCToolsPanel: React.FC<SOCToolsProps> = ({ analysisResult }) => {
  const [activeTab, setActiveTab] = useState<TabType>('iocs');
  const [quickActionsData, setQuickActionsData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copySuccess, setCopySuccess] = useState<string | null>(null);
  const [defangMode, setDefangMode] = useState<'none' | 'brackets' | 'full'>('brackets');
  const [exportFormat, setExportFormat] = useState<'text' | 'csv' | 'json'>('text');
  const [siemFormat, setSiemFormat] = useState<'generic' | 'splunk' | 'elastic' | 'sentinel'>('generic');
  const [ticketFormat, setTicketFormat] = useState<'generic' | 'servicenow' | 'jira' | 'markdown'>('generic');
  const [notificationType, setNotificationType] = useState('phishing_warning');
  const [playbook, setPlaybook] = useState<any>(null);
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [generatedNotification, setGeneratedNotification] = useState<any>(null);
  const [generatingNotification, setGeneratingNotification] = useState(false);

  // Fallback: extract IOCs locally if API didn't return data
  const localIOCs = useMemo(() => {
    if (!analysisResult) return null;
    
    const email = analysisResult.email || {};
    const enrichment = analysisResult.enrichment || {};
    
    const domains = new Set<string>();
    const urls = new Set<string>();
    const ips = new Set<string>();
    const hashes = new Set<string>();
    
    // Extract from sender
    if (email.sender?.domain) domains.add(email.sender.domain);
    if (email.sender?.email) {
      const senderDomain = email.sender.email.split('@')[1];
      if (senderDomain) domains.add(senderDomain);
    }
    
    // Extract URLs
    (email.urls || []).forEach((u: any) => {
      if (typeof u === 'string') urls.add(u);
      else if (u?.url) urls.add(u.url);
      if (u?.domain) domains.add(u.domain);
    });
    
    // Extract from attachments
    (email.attachments || []).forEach((a: any) => {
      if (a?.md5) hashes.add(a.md5);
      if (a?.sha256) hashes.add(a.sha256);
    });
    
    // Extract IP from enrichment
    if (enrichment?.originating_ip?.ip) ips.add(enrichment.originating_ip.ip);
    
    return {
      data: {
        domains: Array.from(domains).filter(Boolean),
        urls: Array.from(urls).filter(Boolean),
        ips: Array.from(ips).filter(Boolean),
        hashes_md5: [],
        hashes_sha256: Array.from(hashes).filter(Boolean),
      },
      counts: {
        domains: domains.size,
        urls: urls.size,
        ips: ips.size,
        hashes: hashes.size,
        total: domains.size + urls.size + ips.size + hashes.size,
      },
      formatted: {
        text: `Domains:\n${Array.from(domains).filter(Boolean).join('\n')}\n\nURLs:\n${Array.from(urls).filter(Boolean).join('\n')}\n\nIPs:\n${Array.from(ips).filter(Boolean).join('\n')}`,
      },
    };
  }, [analysisResult]);

  const fetchQuickActions = async () => {
    if (!analysisResult) return;
    
    setLoading(true);
    try {
      const response = await apiClient.post('/soc/quick-actions', analysisResult);
      setQuickActionsData(response.data);
      setPlaybook(response.data.playbook);
    } catch (error) {
      console.error('Failed to fetch quick actions:', error);
    } finally {
      setLoading(false);
    }
  };

  // Fetch quick actions data when analysis result changes
  useEffect(() => {
    if (analysisResult) {
      fetchQuickActions();
    }
  }, [analysisResult]);

  // Early return if no analysis result
  if (!analysisResult) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8 text-center">
        <Shield className="w-12 h-12 mx-auto mb-3 text-gray-600" />
        <h3 className="text-lg font-semibold text-gray-400">No Analysis Data</h3>
        <p className="text-gray-500 text-sm mt-1">Run an email, URL, or SMS analysis to access SOC tools</p>
      </div>
    );
  }

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopySuccess(label);
      setTimeout(() => setCopySuccess(null), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  const downloadFile = (content: string, filename: string, type: string = 'text/plain') => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const toggleStepComplete = (stepId: string) => {
    const newCompleted = new Set(completedSteps);
    if (newCompleted.has(stepId)) {
      newCompleted.delete(stepId);
    } else {
      newCompleted.add(stepId);
    }
    setCompletedSteps(newCompleted);
  };

  // Tab Button Component
  const TabButton: React.FC<{
    tab: TabType;
    icon: React.ReactNode;
    label: string;
    count?: number;
  }> = ({ tab, icon, label, count }) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all text-sm font-medium ${
        activeTab === tab
          ? 'bg-indigo-600 text-white'
          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
      }`}
    >
      {icon}
      <span>{label}</span>
      {count !== undefined && count > 0 && (
        <span className={`px-1.5 py-0.5 rounded text-xs ${
          activeTab === tab ? 'bg-indigo-500 text-white' : 'bg-gray-700 text-gray-300'
        }`}>
          {count}
        </span>
      )}
    </button>
  );

  // IOC Panel
  const IOCPanel = () => {
    const iocs = quickActionsData?.iocs;
    const displayIOCs = iocs || localIOCs;
    
    if (!displayIOCs || displayIOCs.counts?.total === 0) {
      return (
        <div className="text-center py-8">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-gray-400">No IOCs extracted from this email</p>
          <p className="text-sm mt-1 text-gray-500">This email may not contain observable indicators</p>
        </div>
      );
    }

    const getFormattedIOCs = () => {
      if (!displayIOCs.formatted) return displayIOCs.data ? 
        `Domains:\n${displayIOCs.data.domains?.join('\n') || ''}\n\nURLs:\n${displayIOCs.data.urls?.join('\n') || ''}\n\nIPs:\n${displayIOCs.data.ips?.join('\n') || ''}` : '';
      if (defangMode === 'full') return displayIOCs.formatted.defanged_full || displayIOCs.formatted.text;
      if (exportFormat === 'csv') return displayIOCs.formatted.csv || displayIOCs.formatted.text;
      if (exportFormat === 'json') return displayIOCs.formatted.json || displayIOCs.formatted.text;
      return displayIOCs.formatted.text;
    };

    return (
      <div className="space-y-4">
        {/* Quick Stats */}
        <div className="grid grid-cols-3 md:grid-cols-5 gap-2 md:gap-3">
          <div className="bg-blue-900/30 border border-blue-700/50 rounded-lg p-2 md:p-3 text-center">
            <div className="text-lg md:text-2xl font-bold text-blue-400">{displayIOCs.counts?.domains || 0}</div>
            <div className="text-[10px] md:text-xs text-gray-400">Domains</div>
          </div>
          <div className="bg-purple-900/30 border border-purple-700/50 rounded-lg p-2 md:p-3 text-center">
            <div className="text-lg md:text-2xl font-bold text-purple-400">{displayIOCs.counts?.urls || 0}</div>
            <div className="text-[10px] md:text-xs text-gray-400">URLs</div>
          </div>
          <div className="bg-green-900/30 border border-green-700/50 rounded-lg p-2 md:p-3 text-center">
            <div className="text-lg md:text-2xl font-bold text-green-400">{displayIOCs.counts?.ips || 0}</div>
            <div className="text-[10px] md:text-xs text-gray-400">IPs</div>
          </div>
          <div className="bg-orange-900/30 border border-orange-700/50 rounded-lg p-2 md:p-3 text-center hidden md:block">
            <div className="text-lg md:text-2xl font-bold text-orange-400">{displayIOCs.counts?.hashes || 0}</div>
            <div className="text-[10px] md:text-xs text-gray-400">Hashes</div>
          </div>
          <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-2 md:p-3 text-center hidden md:block">
            <div className="text-lg md:text-2xl font-bold text-red-400">{displayIOCs.counts?.total || 0}</div>
            <div className="text-[10px] md:text-xs text-gray-400">Total</div>
          </div>
        </div>

        {/* Options */}
        <div className="flex flex-col sm:flex-row flex-wrap gap-3 md:gap-4 p-3 bg-gray-800/50 rounded-lg border border-gray-700">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Defang:</label>
            <select
              value={defangMode}
              onChange={(e) => setDefangMode(e.target.value as any)}
              className="bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-sm text-gray-200 flex-1 sm:flex-none"
            >
              <option value="none">None (raw)</option>
              <option value="brackets">Brackets [.]</option>
              <option value="full">Full (hxxps://[.])</option>
            </select>
          </div>
          
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Format:</label>
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as any)}
              className="bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-sm text-gray-200 flex-1 sm:flex-none"
            >
              <option value="text">Plain Text</option>
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
          </div>

          {exportFormat === 'json' && (
            <div className="flex items-center gap-2">
              <label className="text-sm text-gray-400">SIEM:</label>
              <select
                value={siemFormat}
                onChange={(e) => setSiemFormat(e.target.value as any)}
                className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
              >
                <option value="generic">Generic</option>
                <option value="splunk">Splunk</option>
                <option value="elastic">Elastic</option>
                <option value="sentinel">Sentinel</option>
              </select>
            </div>
          )}
        </div>

        {/* Quick Copy Buttons */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => copyToClipboard(getFormattedIOCs(), 'all-iocs')}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm"
          >
            <Copy className="w-4 h-4" />
            Copy All IOCs
            {copySuccess === 'all-iocs' && <Check className="w-4 h-4" />}
          </button>
          
          {displayIOCs?.data?.domains?.length > 0 && (
            <button
              onClick={() => copyToClipboard(displayIOCs.data.domains.join('\n'), 'domains')}
              className="flex items-center gap-2 px-3 py-2 bg-blue-600/20 text-blue-400 border border-blue-600/50 rounded-lg hover:bg-blue-600/30 text-sm"
            >
              <Copy className="w-4 h-4" />
              Domains ({displayIOCs.data.domains.length})
              {copySuccess === 'domains' && <Check className="w-4 h-4" />}
            </button>
          )}
          
          {displayIOCs?.data?.ips?.length > 0 && (
            <button
              onClick={() => copyToClipboard(displayIOCs.data.ips.join('\n'), 'ips')}
              className="flex items-center gap-2 px-3 py-2 bg-green-600/20 text-green-400 border border-green-600/50 rounded-lg hover:bg-green-600/30 text-sm"
            >
              <Copy className="w-4 h-4" />
              IPs ({displayIOCs.data.ips.length})
              {copySuccess === 'ips' && <Check className="w-4 h-4" />}
            </button>
          )}
          
          <button
            onClick={() => {
              const ext = exportFormat === 'json' ? 'json' : exportFormat === 'csv' ? 'csv' : 'txt';
              downloadFile(getFormattedIOCs(), `iocs-${Date.now()}.${ext}`);
            }}
            className="flex items-center gap-2 px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 text-sm"
          >
            <Download className="w-4 h-4" />
            Download
          </button>
        </div>

        {/* IOC Preview */}
        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 flex justify-between items-center">
            <span className="text-sm font-medium text-gray-300">IOC Preview</span>
            <button
              onClick={() => copyToClipboard(getFormattedIOCs(), 'preview')}
              className="text-sm text-indigo-400 hover:text-indigo-300"
            >
              {copySuccess === 'preview' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <pre className="p-3 md:p-4 text-xs md:text-sm overflow-auto max-h-48 md:max-h-64 bg-gray-900 font-mono text-gray-300">
            {getFormattedIOCs().slice(0, 2000)}
            {getFormattedIOCs().length > 2000 && '\n... (truncated)'}
          </pre>
        </div>

        {/* Individual IOC Lists */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 md:gap-4">
          {displayIOCs?.data?.domains?.length > 0 && (
            <div className="border border-gray-700 rounded-lg p-3 bg-gray-800/50">
              <h4 className="font-medium mb-2 flex items-center gap-2 text-gray-200 text-sm md:text-base">
                <Globe className="w-4 h-4 text-blue-400" />
                Domains ({displayIOCs.data.domains.length})
              </h4>
              <ul className="text-xs md:text-sm space-y-1 max-h-32 overflow-auto">
                {displayIOCs.data.domains.map((d: string, i: number) => (
                  <li key={i} className="font-mono text-gray-400 hover:text-gray-200 hover:bg-gray-700 px-2 py-1.5 rounded cursor-pointer"
                      onClick={() => copyToClipboard(d, `domain-${i}`)}>
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          )}
          
          {displayIOCs?.data?.urls?.length > 0 && (
            <div className="border border-gray-700 rounded-lg p-3 bg-gray-800/50">
              <h4 className="font-medium mb-2 flex items-center gap-2 text-gray-200 text-sm md:text-base">
                <Link2 className="w-4 h-4 text-purple-400" />
                URLs ({displayIOCs.data.urls.length})
              </h4>
              <ul className="text-xs md:text-sm space-y-1 max-h-32 overflow-auto">
                {displayIOCs.data.urls.slice(0, 10).map((u: string, i: number) => (
                  <li key={i} className="font-mono text-gray-400 hover:text-gray-200 hover:bg-gray-700 px-2 py-1.5 rounded cursor-pointer truncate"
                      onClick={() => copyToClipboard(u, `url-${i}`)}
                      title={u}>
                    {u.length > 40 ? u.slice(0, 40) + '...' : u}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Rules Panel
  const RulesPanel = () => {
    const rules = quickActionsData?.rules;
    const triggeredRules = analysisResult?.detection?.rules_triggered || analysisResult?.rules_triggered || [];
    
    const hasContent = rules || triggeredRules.length > 0;
    
    if (!hasContent) return (
      <div className="text-center py-8">
        <FileCode className="w-12 h-12 mx-auto mb-3 text-gray-600" />
        <p className="text-gray-400">No detection rules</p>
        <p className="text-sm mt-1 text-gray-500">Rules will be generated after analysis</p>
      </div>
    );

    return (
      <div className="space-y-6">
        {/* Section 1: Triggered Detection Rules */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-gray-200 flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-400" />
              Triggered Detection Rules
              <span className={`ml-2 px-2 py-0.5 rounded text-xs ${
                triggeredRules.length > 0 ? 'bg-red-900/50 text-red-400' : 'bg-gray-700 text-gray-400'
              }`}>
                {triggeredRules.length} matched
              </span>
            </h3>
          </div>
          
          {triggeredRules.length === 0 ? (
            <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4 text-center">
              <Check className="w-8 h-8 mx-auto mb-2 text-green-400" />
              <p className="text-green-400 font-medium">No Detection Rules Triggered</p>
              <p className="text-sm text-gray-500 mt-1">Email passed all detection rule checks</p>
            </div>
          ) : (
            <div className="border border-red-700/50 rounded-lg overflow-hidden">
              <div className="bg-red-900/30 px-4 py-2 border-b border-red-700/50 flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-400" />
                <span className="font-medium text-red-300">Rules That Matched ({triggeredRules.length})</span>
              </div>
              <div className="divide-y divide-gray-700 max-h-80 overflow-y-auto">
                {triggeredRules.map((rule: any, i: number) => (
                  <div key={i} className="p-3 bg-gray-800/50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium text-gray-200">{rule.rule_name || rule.name || `Rule ${i + 1}`}</span>
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            (rule.severity || '').toLowerCase() === 'critical' ? 'bg-red-900/50 text-red-400 border border-red-700' :
                            (rule.severity || '').toLowerCase() === 'high' ? 'bg-orange-900/50 text-orange-400 border border-orange-700' :
                            (rule.severity || '').toLowerCase() === 'medium' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-700' :
                            'bg-gray-700 text-gray-300'
                          }`}>
                            {rule.severity || 'medium'}
                          </span>
                          {rule.category && (
                            <span className="px-2 py-0.5 rounded text-xs bg-purple-900/50 text-purple-400 border border-purple-700">
                              {rule.category}
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-400">{rule.description || 'No description'}</p>
                        {rule.evidence && rule.evidence.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs text-gray-500 mb-1">Evidence:</p>
                            <ul className="text-xs text-gray-400 space-y-0.5">
                              {rule.evidence.slice(0, 3).map((ev: string, j: number) => (
                                <li key={j} className="flex items-start gap-1">
                                  <span className="text-yellow-400">•</span>
                                  <span className="break-all">{ev}</span>
                                </li>
                              ))}
                              {rule.evidence.length > 3 && (
                                <li className="text-gray-500">+{rule.evidence.length - 3} more</li>
                              )}
                            </ul>
                          </div>
                        )}
                        {rule.mitre_techniques && rule.mitre_techniques.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {rule.mitre_techniques.map((technique: string, j: number) => (
                              <span key={j} className="px-1.5 py-0.5 rounded text-xs bg-blue-900/50 text-blue-400 font-mono">
                                {technique}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="text-right ml-3">
                        <span className={`text-lg font-bold ${
                          (rule.weight_score || rule.score || 0) >= 20 ? 'text-red-400' :
                          (rule.weight_score || rule.score || 0) >= 10 ? 'text-orange-400' :
                          'text-yellow-400'
                        }`}>
                          +{rule.weight_score || rule.score || 0}
                        </span>
                        <p className="text-xs text-gray-500">points</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Divider */}
        {rules && (
          <div className="border-t border-gray-700 pt-4">
            <p className="text-xs text-gray-500 mb-4 text-center">
              ↓ Generated hunting rules based on IOCs found ↓
            </p>
          </div>
        )}

        {/* Section 2: Generated YARA/Sigma Rules */}
        {rules && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-200 flex items-center gap-2">
                <FileCode className="w-5 h-5 text-indigo-400" />
                Generated Hunting Rules
                <span className="ml-2 px-2 py-0.5 rounded text-xs bg-indigo-900/50 text-indigo-400">
                  {(rules.yara?.length || 0) + (rules.sigma?.length || 0)} rules
                </span>
              </h3>
              <button
                onClick={() => {
                  const allRules = [...(rules.yara || []), ...(rules.sigma || [])]
                    .map((r: any) => `# ${r.rule_name}\n${r.rule_content}`)
                    .join('\n\n---\n\n');
                  downloadFile(allRules, `detection-rules-${Date.now()}.txt`);
                }}
                className="flex items-center gap-2 px-3 py-1 bg-indigo-600/20 text-indigo-400 border border-indigo-600/50 rounded hover:bg-indigo-600/30 text-sm"
              >
                <Download className="w-4 h-4" />
                Download All
              </button>
            </div>

            {/* YARA Rules */}
            {rules.yara && rules.yara.length > 0 && (
              <div className="border border-gray-700 rounded-lg overflow-hidden">
                <div className="bg-orange-900/30 px-4 py-2 border-b border-gray-700 flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-orange-400" />
                  <span className="font-medium text-orange-300">YARA Rules ({rules.yara.length})</span>
                </div>
                <div className="divide-y divide-gray-700">
                  {rules.yara.map((rule: any, i: number) => (
                    <div key={i} className="p-3 bg-gray-800/50">
                      <div
                        className="flex items-center justify-between cursor-pointer"
                        onClick={() => setExpandedRule(expandedRule === `yara-${i}` ? null : `yara-${i}`)}
                      >
                        <div className="flex items-center gap-2">
                          {expandedRule === `yara-${i}` ? 
                            <ChevronDown className="w-4 h-4 text-gray-400" /> : 
                            <ChevronRight className="w-4 h-4 text-gray-400" />
                          }
                          <span className="font-mono text-sm text-gray-200">{rule.rule_name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            rule.severity === 'high' ? 'bg-red-900/50 text-red-400' :
                            rule.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-400' :
                            'bg-gray-700 text-gray-300'
                          }`}>
                            {rule.severity}
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(rule.rule_content, `yara-${i}`);
                            }}
                            className="text-indigo-400 hover:text-indigo-300"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                      {expandedRule === `yara-${i}` && (
                        <pre className="mt-2 p-3 bg-gray-900 text-green-400 text-xs rounded overflow-auto max-h-64 font-mono border border-gray-700">
                          {rule.rule_content}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sigma Rules */}
            {rules.sigma && rules.sigma.length > 0 && (
              <div className="border border-gray-700 rounded-lg overflow-hidden">
                <div className="bg-blue-900/30 px-4 py-2 border-b border-gray-700 flex items-center gap-2">
                  <Code className="w-5 h-5 text-blue-400" />
                  <span className="font-medium text-blue-300">Sigma Rules ({rules.sigma.length})</span>
                </div>
                <div className="divide-y divide-gray-700">
                  {rules.sigma.map((rule: any, i: number) => (
                    <div key={i} className="p-3 bg-gray-800/50">
                      <div
                        className="flex items-center justify-between cursor-pointer"
                        onClick={() => setExpandedRule(expandedRule === `sigma-${i}` ? null : `sigma-${i}`)}
                      >
                        <div className="flex items-center gap-2">
                          {expandedRule === `sigma-${i}` ? 
                            <ChevronDown className="w-4 h-4 text-gray-400" /> : 
                            <ChevronRight className="w-4 h-4 text-gray-400" />
                          }
                          <span className="font-mono text-sm text-gray-200">{rule.rule_name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            rule.severity === 'high' ? 'bg-red-900/50 text-red-400' :
                            rule.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-400' :
                            'bg-gray-700 text-gray-300'
                          }`}>
                            {rule.severity}
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(rule.rule_content, `sigma-${i}`);
                            }}
                            className="text-indigo-400 hover:text-indigo-300"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                      {expandedRule === `sigma-${i}` && (
                        <pre className="mt-2 p-3 bg-gray-900 text-cyan-400 text-xs rounded overflow-auto max-h-64 font-mono border border-gray-700">
                          {rule.rule_content}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {(!rules.yara || rules.yara.length === 0) && (!rules.sigma || rules.sigma.length === 0) && (
              <div className="text-center py-4 text-gray-500">
                <p>No YARA/Sigma rules generated</p>
                <p className="text-sm">Insufficient IOCs to generate hunting rules</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // Ticket Panel
  const TicketPanel = () => {
    const ticket = quickActionsData?.ticket;
    if (!ticket) return (
      <div className="text-center py-8">
        <FileText className="w-12 h-12 mx-auto mb-3 text-gray-600" />
        <p className="text-gray-400">No ticket data available</p>
      </div>
    );

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-4">
          <label className="text-sm text-gray-400">Format:</label>
          <select
            value={ticketFormat}
            onChange={(e) => setTicketFormat(e.target.value as any)}
            className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-gray-200"
          >
            <option value="generic">Generic</option>
            <option value="servicenow">ServiceNow</option>
            <option value="jira">Jira</option>
            <option value="markdown">Markdown</option>
          </select>
        </div>

        <div className="border border-gray-700 rounded-lg overflow-hidden">
          <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 flex justify-between items-center">
            <span className="font-medium text-gray-300">Incident Ticket Preview</span>
            <div className="flex gap-2">
              <button
                onClick={() => copyToClipboard(ticket.description || ticket.content, 'ticket')}
                className="flex items-center gap-1 px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700"
              >
                <Copy className="w-4 h-4" />
                Copy
                {copySuccess === 'ticket' && <Check className="w-4 h-4" />}
              </button>
              <button
                onClick={() => downloadFile(ticket.description || ticket.content, `incident-ticket-${Date.now()}.txt`)}
                className="flex items-center gap-1 px-3 py-1 bg-gray-700 text-gray-300 rounded text-sm hover:bg-gray-600"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
            </div>
          </div>
          
          {/* Ticket Header Info */}
          <div className="p-4 bg-gray-800/50 border-b border-gray-700 grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Title: </span>
              <span className="font-medium text-gray-200">{ticket.title || ticket.summary || 'Security Incident'}</span>
            </div>
            <div>
              <span className="text-gray-500">Priority: </span>
              <span className={`font-medium ${
                ticket.priority?.includes('1') || ticket.priority === 'Highest' ? 'text-red-400' :
                ticket.priority?.includes('2') || ticket.priority === 'High' ? 'text-orange-400' :
                'text-yellow-400'
              }`}>{ticket.priority}</span>
            </div>
          </div>
          
          <pre className="p-4 text-sm overflow-auto max-h-96 whitespace-pre-wrap font-mono bg-gray-900 text-gray-300">
            {ticket.description || ticket.content}
          </pre>
        </div>
      </div>
    );
  };

  // Playbook Panel
  const PlaybookPanel = () => {
    if (!playbook || !playbook.steps || playbook.steps.length === 0) {
      return (
        <div className="text-center py-8">
          <CheckSquare className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-gray-400">No playbook generated</p>
          <p className="text-sm mt-1 text-gray-500">A response playbook will be created based on threat classification</p>
        </div>
      );
    }

    // Check if this is a clean/minimal result
    const isCleanResult = playbook.playbook_type === 'clean' || playbook.severity === 'low';
    
    if (isCleanResult && playbook.steps.length <= 2) {
      return (
        <div className="space-y-4">
          {/* Clean Result Banner */}
          <div className="bg-green-900/30 border border-green-700 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-green-600 rounded-full flex items-center justify-center">
                <Check className="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 className="font-semibold text-green-400">{playbook.title || 'No Action Required'}</h3>
                <p className="text-sm text-gray-400">{playbook.description || 'This analysis found no significant threats.'}</p>
              </div>
            </div>
          </div>
          
          {/* Minimal Steps */}
          <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
            <h4 className="text-sm font-medium text-gray-400 mb-3">Optional Verification Steps</h4>
            {playbook.steps.map((step: any) => (
              <div key={step.id} className="flex items-start gap-3 py-2">
                <button
                  onClick={() => toggleStepComplete(step.id)}
                  className={`mt-0.5 w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 ${
                    completedSteps.has(step.id) 
                      ? 'bg-green-600 border-green-600 text-white' 
                      : 'border-gray-600 hover:border-green-500'
                  }`}
                >
                  {completedSteps.has(step.id) && <Check className="w-3 h-3" />}
                </button>
                <div>
                  <span className={`text-gray-300 ${completedSteps.has(step.id) ? 'line-through text-gray-500' : ''}`}>
                    {step.title}
                  </span>
                  <p className="text-xs text-gray-500">{step.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }

    // Group steps by category
    const stepsByCategory: Record<string, any[]> = {};
    playbook.steps.forEach((step: any) => {
      const cat = step.category || 'general';
      if (!stepsByCategory[cat]) stepsByCategory[cat] = [];
      stepsByCategory[cat].push(step);
    });

    const completedCount = completedSteps.size;
    const totalSteps = playbook.steps.length;
    const progress = totalSteps > 0 ? Math.round((completedCount / totalSteps) * 100) : 0;

    const categoryColors: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
      containment: { bg: 'bg-red-900/30', text: 'text-red-400', icon: <Shield className="w-4 h-4" /> },
      investigation: { bg: 'bg-blue-900/30', text: 'text-blue-400', icon: <Target className="w-4 h-4" /> },
      eradication: { bg: 'bg-orange-900/30', text: 'text-orange-400', icon: <Zap className="w-4 h-4" /> },
      recovery: { bg: 'bg-green-900/30', text: 'text-green-400', icon: <Check className="w-4 h-4" /> },
      lessons_learned: { bg: 'bg-purple-900/30', text: 'text-purple-400', icon: <FileText className="w-4 h-4" /> },
      verification: { bg: 'bg-gray-800/50', text: 'text-gray-400', icon: <Eye className="w-4 h-4" /> },
      documentation: { bg: 'bg-gray-800/50', text: 'text-gray-400', icon: <FileText className="w-4 h-4" /> },
    };

    return (
      <div className="space-y-4">
        {/* Progress Bar */}
        <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-gray-400">Progress</span>
            <span className="text-gray-300">{completedCount}/{totalSteps} steps ({progress}%)</span>
          </div>
          <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-green-500 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Steps by Category */}
        {Object.entries(stepsByCategory).map(([category, steps]) => {
          const colors = categoryColors[category] || { bg: 'bg-gray-800/50', text: 'text-gray-400', icon: <FileText className="w-4 h-4" /> };
          return (
            <div key={category} className="border border-gray-700 rounded-lg overflow-hidden">
              <div className={`px-4 py-2 border-b border-gray-700 font-medium capitalize flex items-center gap-2 ${colors.bg} ${colors.text}`}>
                {colors.icon}
                {category.replace('_', ' ')}
                <span className="text-sm font-normal text-gray-400">({steps.length} steps)</span>
              </div>
              <div className="divide-y divide-gray-700">
                {steps.map((step: any) => (
                  <div 
                    key={step.id} 
                    className={`p-3 flex items-start gap-3 ${completedSteps.has(step.id) ? 'bg-green-900/20' : 'bg-gray-800/30'}`}
                  >
                    <button
                      onClick={() => toggleStepComplete(step.id)}
                      className={`mt-0.5 w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 ${
                        completedSteps.has(step.id) 
                          ? 'bg-green-600 border-green-600 text-white' 
                          : 'border-gray-600 hover:border-green-500'
                      }`}
                    >
                      {completedSteps.has(step.id) && <Check className="w-3 h-3" />}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`font-medium text-gray-200 ${completedSteps.has(step.id) ? 'line-through text-gray-500' : ''}`}>
                          {step.title}
                        </span>
                        {step.automated && (
                          <span className="px-2 py-0.5 bg-blue-900/50 text-blue-400 text-xs rounded">
                            Automated
                          </span>
                        )}
                        <span className={`px-2 py-0.5 text-xs rounded ${
                          step.priority === 1 ? 'bg-red-900/50 text-red-400' :
                          step.priority === 2 ? 'bg-yellow-900/50 text-yellow-400' :
                          'bg-gray-700 text-gray-400'
                        }`}>
                          P{step.priority}
                        </span>
                      </div>
                      <p className="text-sm text-gray-400 mt-1">{step.description}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                        <span className="flex items-center gap-1">
                          <Users className="w-3 h-3" />
                          {step.responsible_team}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          ~{step.estimated_time_minutes} min
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  // Notification Panel
  const NotificationPanel = () => {
    const generateNotification = async () => {
      setGeneratingNotification(true);
      try {
        const response = await apiClient.post('/soc/notification/generate', {
          notification_type: notificationType,
          analysis_result: analysisResult,
          recipient_name: 'User',
        });
        setGeneratedNotification(response.data);
      } catch (error) {
        console.error('Failed to generate notification:', error);
      } finally {
        setGeneratingNotification(false);
      }
    };

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-4 flex-wrap">
          <label className="text-sm text-gray-400">Template:</label>
          <select
            value={notificationType}
            onChange={(e) => setNotificationType(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 flex-1 min-w-[200px] text-gray-200"
          >
            <option value="phishing_warning">Phishing Warning</option>
            <option value="credential_compromise">Credential Compromise (Urgent)</option>
            <option value="malware_warning">Malware Warning</option>
            <option value="bec_attempt">BEC Attempt</option>
            <option value="account_secured">Account Secured</option>
            <option value="general_warning">General Warning</option>
          </select>
          <button
            onClick={generateNotification}
            disabled={generatingNotification}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 text-sm"
          >
            {generatingNotification ? 'Generating...' : 'Generate'}
          </button>
        </div>

        {generatedNotification && (
          <div className="border border-gray-700 rounded-lg overflow-hidden">
            <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 flex justify-between items-center">
              <span className="font-medium text-gray-300">Email Preview</span>
              <div className="flex gap-2">
                <button
                  onClick={() => copyToClipboard(`Subject: ${generatedNotification.subject}\n\n${generatedNotification.body}`, 'notification')}
                  className="flex items-center gap-1 px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700"
                >
                  <Copy className="w-4 h-4" />
                  Copy
                </button>
              </div>
            </div>
            
            <div className="p-4 bg-gray-800/50 border-b border-gray-700">
              <span className="text-sm text-gray-500">Subject: </span>
              <span className="font-medium text-gray-200">{generatedNotification.subject}</span>
            </div>
            
            <pre className="p-4 text-sm overflow-auto max-h-96 whitespace-pre-wrap bg-gray-900 text-gray-300">
              {generatedNotification.body}
            </pre>
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8 text-center">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-indigo-600 border-t-transparent mx-auto"></div>
        <p className="mt-2 text-gray-400">Loading SOC Tools...</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <h2 className="text-lg font-semibold flex items-center gap-2 text-gray-100">
          <Shield className="w-5 h-5 text-indigo-400" />
          SOC Analyst Tools
        </h2>
        <p className="text-sm text-gray-500 mt-1">
          Quick actions, detection rules, tickets, playbooks, and user notifications
        </p>
      </div>

      {/* Tabs */}
      <div className="px-4 py-3 border-b border-gray-700 flex flex-wrap gap-2">
        <TabButton 
          tab="iocs" 
          icon={<Clipboard className="w-4 h-4" />} 
          label="IOCs" 
          count={quickActionsData?.iocs?.counts?.total}
        />
        <TabButton 
          tab="rules" 
          icon={<Code className="w-4 h-4" />} 
          label="Detection Rules"
          count={(analysisResult?.detection?.rules_triggered?.length || analysisResult?.rules_triggered?.length || 0) + (quickActionsData?.rules?.yara?.length || 0) + (quickActionsData?.rules?.sigma?.length || 0)}
        />
        <TabButton 
          tab="ticket" 
          icon={<FileText className="w-4 h-4" />} 
          label="Incident Ticket"
        />
        <TabButton 
          tab="playbook" 
          icon={<CheckSquare className="w-4 h-4" />} 
          label="Response Playbook"
          count={playbook?.steps?.length}
        />
        <TabButton 
          tab="notification" 
          icon={<Mail className="w-4 h-4" />} 
          label="User Notification"
        />
      </div>

      {/* Content */}
      <div className="p-4">
        {activeTab === 'iocs' && <IOCPanel />}
        {activeTab === 'rules' && <RulesPanel />}
        {activeTab === 'ticket' && <TicketPanel />}
        {activeTab === 'playbook' && <PlaybookPanel />}
        {activeTab === 'notification' && <NotificationPanel />}
      </div>
    </div>
  );
};

export default SOCToolsPanel;
