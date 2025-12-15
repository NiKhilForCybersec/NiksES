/**
 * NiksES Advanced Analysis View for SOC Analysts
 * 
 * Comprehensive email threat analysis display with:
 * - Authentication chain (SPF/DKIM/DMARC)
 * - Threat intelligence results
 * - IOC extraction with OSINT pivots
 * - MITRE ATT&CK mapping
 * - Full header analysis
 * - Sandbox dynamic analysis
 */

import React, { useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Mail, User, Calendar, Link as LinkIcon, Paperclip,
  AlertTriangle, CheckCircle, XCircle, Info,
  ChevronDown, ChevronRight, Globe, Server, Key, Hash,
  Copy, Download, Brain, Target, Eye, ExternalLink,
  FileText, Clock, Tag, MapPin, Building, Activity,
  Zap, Search, AlertCircle, Database, Network,
  ArrowRight, Lock, Unlock, HelpCircle, TrendingUp,
  Bug
} from 'lucide-react';
import SandboxResultsPanel from './SandboxResultsPanel';

interface AdvancedAnalysisViewProps {
  result: any;
  onExport: (format: string) => void;
  onBack: () => void;
}

const AdvancedAnalysisView: React.FC<AdvancedAnalysisViewProps> = ({ result, onExport, onBack }) => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['auth', 'threatintel', 'rules', 'iocs'])
  );
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Early return if no result
  if (!result) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
          <h2 className="text-xl font-semibold text-gray-400 mb-2">No Analysis Data</h2>
          <p className="text-gray-500 mb-4">Analysis result not available</p>
          <button
            onClick={onBack}
            className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }

  // Toggle section expansion
  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  // Copy to clipboard
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Defang URL/IP for safe display
  const defang = (text: string): string => {
    return text
      .replace(/\./g, '[.]')
      .replace(/http/gi, 'hxxp')
      .replace(/@/g, '[@]');
  };

  // Convert country code to flag emoji
  const getFlagEmoji = (countryCode: string): string => {
    if (!countryCode || countryCode.length !== 2) return '🌍';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  // Extract numeric score from risk_score (can be number or MultiDimensionalRiskScore object)
  const extractScore = (score: any): number => {
    if (typeof score === 'number') return score;
    if (score && typeof score === 'object' && 'overall_score' in score) return score.overall_score;
    return 0;
  };

  // Get unified score - prioritize orchestrator's score over detection engine
  // The orchestrator applies false positive suppression and multi-dimensional analysis
  const unifiedScore = (result as any).overall_score ?? 
                       extractScore((result as any).risk_score) ?? 
                       extractScore(result.detection?.risk_score) ?? 0;
  
  const unifiedLevel = ((result as any).overall_level ?? 
                       (result as any).risk_score?.overall_level ?? 
                       result.detection?.risk_level ?? 'unknown').toString().toLowerCase();
  
  const unifiedClassification = ((result as any).classification ?? 
                                (result as any).risk_score?.primary_classification ?? 
                                result.detection?.primary_classification ?? 'unknown').toString();

  // Get authentication status
  const getAuthStatus = (result?: string) => {
    if (!result) return { icon: HelpCircle, color: 'text-gray-400', bg: 'bg-gray-800', label: 'Not Checked' };
    const r = result.toLowerCase();
    if (r === 'pass') return { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/30', label: 'PASS' };
    if (r === 'fail') return { icon: XCircle, color: 'text-red-400', bg: 'bg-red-900/30', label: 'FAIL' };
    if (r === 'softfail') return { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-900/30', label: 'SOFTFAIL' };
    if (r === 'neutral' || r === 'none') return { icon: Info, color: 'text-gray-400', bg: 'bg-gray-800', label: r.toUpperCase() };
    if (r === 'present') return { icon: CheckCircle, color: 'text-blue-400', bg: 'bg-blue-900/30', label: 'PRESENT' };
    return { icon: HelpCircle, color: 'text-gray-400', bg: 'bg-gray-800', label: result.toUpperCase() };
  };

  // Get verdict colors
  const getVerdictStyle = (verdict: string) => {
    const v = verdict?.toLowerCase() || '';
    if (v === 'malicious') return { bg: 'bg-red-600', text: 'text-red-400', border: 'border-red-500' };
    if (v === 'suspicious') return { bg: 'bg-orange-600', text: 'text-orange-400', border: 'border-orange-500' };
    if (v === 'clean') return { bg: 'bg-green-600', text: 'text-green-400', border: 'border-green-500' };
    return { bg: 'bg-gray-600', text: 'text-gray-400', border: 'border-gray-500' };
  };

  // Get risk level colors
  const getRiskColor = (level: string) => {
    const l = level?.toLowerCase() || '';
    if (l === 'critical') return 'text-red-400 bg-red-900/50 border-red-500';
    if (l === 'high') return 'text-orange-400 bg-orange-900/50 border-orange-500';
    if (l === 'medium') return 'text-yellow-400 bg-yellow-900/50 border-yellow-500';
    if (l === 'low') return 'text-blue-400 bg-blue-900/50 border-blue-500';
    return 'text-green-400 bg-green-900/50 border-green-500';
  };

  // OSINT pivot links
  const getOsintLinks = (type: string, value: string) => {
    const encoded = encodeURIComponent(value);
    const links: { name: string; url: string; }[] = [];
    
    if (type === 'domain' || type === 'url') {
      links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${encoded}` });
      links.push({ name: 'URLScan', url: `https://urlscan.io/search/#${encoded}` });
      links.push({ name: 'Shodan', url: `https://www.shodan.io/search?query=${encoded}` });
    }
    if (type === 'ip') {
      links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${encoded}` });
      links.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${encoded}` });
      links.push({ name: 'Shodan', url: `https://www.shodan.io/host/${encoded}` });
      links.push({ name: 'GreyNoise', url: `https://viz.greynoise.io/ip/${encoded}` });
    }
    if (type === 'hash') {
      links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${encoded}` });
      links.push({ name: 'MalwareBazaar', url: `https://bazaar.abuse.ch/browse.php?search=sha256:${encoded}` });
    }
    if (type === 'email') {
      links.push({ name: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encoded}` });
    }
    
    return links;
  };

  // Extract authentication from result - try multiple paths
  const getAuthResult = (type: 'spf' | 'dkim' | 'dmarc') => {
    // Priority 1: Top-level header_analysis with flat fields (backend format)
    const resultKey = `${type}_result`;
    if (result.header_analysis?.[resultKey]) {
      return { result: result.header_analysis[resultKey], details: null };
    }
    // Priority 2: Top-level authentication object (from build_response_dict)
    if (result.authentication?.[type]?.result) {
      return result.authentication[type];
    }
    // Priority 3: email.header_analysis (legacy format)
    if (result.email?.header_analysis?.[type]?.result) {
      return result.email.header_analysis[type];
    }
    // Priority 4: email auth result objects
    if (result.email?.[resultKey]?.result) {
      return result.email[resultKey];
    }
    // Default
    return { result: 'none', details: null };
  };

  const spf = getAuthResult('spf');
  const dkim = getAuthResult('dkim');
  const dmarc = getAuthResult('dmarc');

  // Extract enhanced analysis data
  const seAnalysis = result.se_analysis;
  const contentAnalysis = result.content_analysis;
  const lookalikeAnalysis = result.lookalike_analysis;
  const tiResults = result.ti_results;
  const riskScore = result.risk_score;
  const headerAnalysis = result.header_analysis || result.email?.header_analysis || {};

  // Extract enrichment data
  const enrichment = result.enrichment || {};
  const senderDomain = enrichment.sender_domain;
  const originatingIp = enrichment.originating_ip;
  const urlEnrichments = enrichment.urls || [];  // Fixed: backend uses 'urls' not 'url_enrichments'
  const attachmentEnrichments = enrichment.attachments || [];  // Fixed: backend uses 'attachments'

  // Tabs
  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'insights', label: 'Advanced Insights', icon: TrendingUp },
    { id: 'headers', label: 'Headers', icon: FileText },
    { id: 'threatintel', label: 'Threat Intel', icon: Database },
    { id: 'iocs', label: 'IOCs', icon: Target },
    { id: 'rules', label: 'Detection', icon: Shield },
    { id: 'ai', label: 'AI Analysis', icon: Brain },
    // Add Sandbox tab if sandbox analysis available or attachments present
    ...(result.sandbox_analysis || (result.email?.attachments?.length > 0)
      ? [{ id: 'sandbox', label: 'Sandbox', icon: Bug }] 
      : []),
    // Add Enhanced tab if enhanced results available
    ...(result.se_analysis || result.content_analysis || result.lookalike_analysis 
      ? [{ id: 'enhanced', label: 'Enhanced', icon: Zap }] 
      : []),
  ];

  try {
    return (
      <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={onBack}
              className="text-gray-400 hover:text-white transition-colors"
            >
              ← Back
            </button>
            <div>
              <h1 className="text-xl font-bold flex items-center">
                <ShieldAlert className="w-6 h-6 mr-2 text-orange-400" />
                Email Threat Analysis
              </h1>
              <p className="text-sm text-gray-400">
                ID: {result.analysis_id?.slice(0, 8) || 'N/A'} | 
                Analyzed: {result.analyzed_at ? new Date(result.analyzed_at).toLocaleString() : 'N/A'} |
                Duration: {result.analysis_duration_ms || 0}ms
              </p>
            </div>
          </div>
          
          {/* Export Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onExport('executive-pdf')}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 rounded text-sm flex items-center font-medium"
            >
              <Download className="w-4 h-4 mr-1" /> Executive PDF
            </button>
            <button
              onClick={() => onExport('pdf')}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center"
            >
              <FileText className="w-4 h-4 mr-1" /> Technical PDF
            </button>
            <button
              onClick={() => onExport('json')}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center"
            >
              <Download className="w-4 h-4 mr-1" /> JSON
            </button>
            <button
              onClick={() => onExport('markdown')}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center"
            >
              <FileText className="w-4 h-4 mr-1" /> Report
            </button>
            <button
              onClick={() => onExport('stix')}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center"
            >
              <Database className="w-4 h-4 mr-1" /> STIX
            </button>
          </div>
        </div>
      </div>

      {/* Risk Score Banner */}
      <div className={`px-6 py-4 ${getRiskColor(unifiedLevel)}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <div className="text-center">
              <div className="text-4xl font-bold">{unifiedScore}</div>
              <div className="text-xs uppercase tracking-wider opacity-80">Risk Score</div>
            </div>
            <div className="h-12 w-px bg-current opacity-30" />
            <div>
              <div className="text-lg font-semibold uppercase">{unifiedLevel}</div>
              <div className="text-sm opacity-80">{unifiedClassification.replace(/_/g, ' ')}</div>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-center">
              <div className="text-2xl font-bold">{result.detection?.rules_triggered?.length || 0}</div>
              <div className="text-xs opacity-80">Rules Triggered</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{(result.iocs?.domains?.length || 0) + (result.iocs?.urls?.length || 0)}</div>
              <div className="text-xs opacity-80">IOCs Found</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-gray-800 border-b border-gray-700 px-6">
        <div className="flex space-x-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 flex items-center space-x-2 border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Email Summary */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Mail className="w-5 h-5 mr-2 text-blue-400" />
                Email Summary
              </h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-gray-500 uppercase">Subject</label>
                  <p className="text-white font-medium">{result.email?.subject || 'No Subject'}</p>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase">Date</label>
                  <p className="text-white">{result.email?.date || 'Unknown'}</p>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase">From</label>
                  <p className="text-white font-mono text-sm">
                    {result.email?.sender?.display_name && (
                      <span className="text-gray-400">{result.email.sender.display_name} </span>
                    )}
                    &lt;{result.email?.sender?.email || 'unknown'}&gt;
                  </p>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase">To</label>
                  <p className="text-white font-mono text-sm">
                    {result.email?.to_recipients?.map((r: any) => r.email).join(', ') || 'Unknown'}
                  </p>
                </div>
                {result.email?.reply_to && result.email.reply_to.length > 0 && (() => {
                  // Extract reply-to emails
                  const replyToEmails = result.email.reply_to.map((r: any) => 
                    (r.email || r).toLowerCase().trim()
                  );
                  // Get sender email
                  const senderEmail = (result.email?.sender?.email || '').toLowerCase().trim();
                  // Check if any reply-to is different from sender
                  const isDifferent = replyToEmails.some((email: string) => email !== senderEmail);
                  
                  return (
                    <div className="col-span-2">
                      <label className="text-xs text-gray-500 uppercase flex items-center">
                        {isDifferent ? (
                          <>
                            <AlertTriangle className="w-3 h-3 mr-1 text-yellow-400" />
                            Reply-To (Different from Sender!)
                          </>
                        ) : (
                          <>Reply-To</>
                        )}
                      </label>
                      <p className={`font-mono text-sm ${isDifferent ? 'text-yellow-400' : 'text-gray-300'}`}>
                        {result.email.reply_to.map((r: any) => r.email || r).join(', ')}
                      </p>
                    </div>
                  );
                })()}
              </div>
            </div>

            {/* Authentication Results */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Key className="w-5 h-5 mr-2 text-purple-400" />
                Email Authentication
              </h2>
              <div className="grid grid-cols-3 gap-4">
                {/* SPF */}
                <div className={`rounded-lg p-4 ${getAuthStatus(spf?.result).bg} border border-gray-600`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">SPF</span>
                    {React.createElement(getAuthStatus(spf?.result).icon, {
                      className: `w-6 h-6 ${getAuthStatus(spf?.result).color}`
                    })}
                  </div>
                  <div className={`text-2xl font-bold ${getAuthStatus(spf?.result).color}`}>
                    {getAuthStatus(spf?.result).label}
                  </div>
                  {spf?.details && (
                    <p className="text-xs text-gray-400 mt-2 truncate" title={spf.details}>
                      {spf.details}
                    </p>
                  )}
                </div>

                {/* DKIM */}
                <div className={`rounded-lg p-4 ${getAuthStatus(dkim?.result).bg} border border-gray-600`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">DKIM</span>
                    {React.createElement(getAuthStatus(dkim?.result).icon, {
                      className: `w-6 h-6 ${getAuthStatus(dkim?.result).color}`
                    })}
                  </div>
                  <div className={`text-2xl font-bold ${getAuthStatus(dkim?.result).color}`}>
                    {getAuthStatus(dkim?.result).label}
                  </div>
                  {dkim?.details && (
                    <p className="text-xs text-gray-400 mt-2 truncate" title={dkim.details}>
                      {dkim.details}
                    </p>
                  )}
                </div>

                {/* DMARC */}
                <div className={`rounded-lg p-4 ${getAuthStatus(dmarc?.result).bg} border border-gray-600`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">DMARC</span>
                    {React.createElement(getAuthStatus(dmarc?.result).icon, {
                      className: `w-6 h-6 ${getAuthStatus(dmarc?.result).color}`
                    })}
                  </div>
                  <div className={`text-2xl font-bold ${getAuthStatus(dmarc?.result).color}`}>
                    {getAuthStatus(dmarc?.result).label}
                  </div>
                  {dmarc?.details && (
                    <p className="text-xs text-gray-400 mt-2 truncate" title={dmarc.details}>
                      {dmarc.details}
                    </p>
                  )}
                </div>
              </div>
              
              {(!spf && !dkim && !dmarc) && (
                <div className="mt-4 p-3 bg-yellow-900/30 border border-yellow-700 rounded-lg flex items-start">
                  <AlertTriangle className="w-5 h-5 text-yellow-400 mr-2 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-yellow-400 font-medium">No Authentication Found</p>
                    <p className="text-sm text-gray-400">
                      This email has no SPF, DKIM, or DMARC records. This is a significant red flag 
                      as legitimate organizations typically implement email authentication.
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Quick IOC Summary */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Target className="w-5 h-5 mr-2 text-red-400" />
                Indicators of Compromise (IOCs)
              </h2>
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-gray-900 rounded p-3 text-center">
                  <Globe className="w-6 h-6 mx-auto mb-2 text-blue-400" />
                  <div className="text-2xl font-bold">{result.iocs?.domains?.length || 0}</div>
                  <div className="text-xs text-gray-400">Domains</div>
                </div>
                <div className="bg-gray-900 rounded p-3 text-center">
                  <LinkIcon className="w-6 h-6 mx-auto mb-2 text-purple-400" />
                  <div className="text-2xl font-bold">{result.iocs?.urls?.length || 0}</div>
                  <div className="text-xs text-gray-400">URLs</div>
                </div>
                <div className="bg-gray-900 rounded p-3 text-center">
                  <Server className="w-6 h-6 mx-auto mb-2 text-green-400" />
                  <div className="text-2xl font-bold">{result.iocs?.ips?.length || 0}</div>
                  <div className="text-xs text-gray-400">IP Addresses</div>
                </div>
                <div className="bg-gray-900 rounded p-3 text-center">
                  <Hash className="w-6 h-6 mx-auto mb-2 text-orange-400" />
                  <div className="text-2xl font-bold">{result.iocs?.file_hashes_sha256?.length || 0}</div>
                  <div className="text-xs text-gray-400">File Hashes</div>
                </div>
              </div>
            </div>

            {/* AI Summary (if available) */}
            {result.ai_triage && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Brain className="w-5 h-5 mr-2 text-cyan-400" />
                  AI Threat Assessment
                </h2>
                <p className="text-gray-300 mb-4">{result.ai_triage.summary}</p>
                
                {result.ai_triage.key_findings?.length > 0 && (
                  <div className="mb-4">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Key Findings</h3>
                    <ul className="space-y-1">
                      {result.ai_triage.key_findings.slice(0, 5).map((finding: string, idx: number) => (
                        <li key={idx} className="flex items-start text-sm text-gray-300">
                          <AlertCircle className="w-4 h-4 mr-2 text-yellow-400 flex-shrink-0 mt-0.5" />
                          {finding}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.ai_triage.recommended_actions?.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Recommended Actions</h3>
                    <ul className="space-y-1">
                      {result.ai_triage.recommended_actions.slice(0, 3).map((action: any, idx: number) => (
                        <li key={idx} className="flex items-start text-sm">
                          <Zap className="w-4 h-4 mr-2 text-green-400 flex-shrink-0 mt-0.5" />
                          <span className="font-medium mr-2">{action.action}:</span>
                          <span className="text-gray-400">{action.details}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Advanced Insights Tab - Multi-Dimensional Scoring Tree */}
        {activeTab === 'insights' && (
          <div className="space-y-6">
            {/* Overall Risk Score Header */}
            <div className={`rounded-lg p-6 border-2 ${
              unifiedScore >= 70 ? 'bg-red-900/30 border-red-500' :
              unifiedScore >= 40 ? 'bg-orange-900/30 border-orange-500' :
              unifiedScore >= 20 ? 'bg-yellow-900/30 border-yellow-500' :
              'bg-green-900/30 border-green-500'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-4">
                  <div className={`w-20 h-20 rounded-full flex items-center justify-center text-3xl font-bold ${
                    unifiedScore >= 70 ? 'bg-red-600' :
                    unifiedScore >= 40 ? 'bg-orange-600' :
                    unifiedScore >= 20 ? 'bg-yellow-600 text-black' :
                    'bg-green-600'
                  }`}>
                    {unifiedScore}
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold">Overall Risk Assessment</h2>
                    <p className={`text-lg font-semibold ${
                      (unifiedLevel) === 'critical' ? 'text-red-400' :
                      (unifiedLevel) === 'high' ? 'text-orange-400' :
                      (unifiedLevel) === 'medium' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {unifiedLevel.toUpperCase()}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-400">Classification</div>
                  <div className={`text-lg font-bold px-3 py-1 rounded ${
                    result.detection?.primary_classification?.toLowerCase() === 'phishing' ? 'bg-red-600' :
                    result.detection?.primary_classification?.toLowerCase() === 'bec' ? 'bg-orange-600' :
                    result.detection?.primary_classification?.toLowerCase() === 'malware' ? 'bg-purple-600' :
                    result.detection?.primary_classification?.toLowerCase() === 'spam' ? 'bg-yellow-600 text-black' :
                    'bg-green-600'
                  }`}>
                    {(result.detection?.primary_classification || 'Unknown').toUpperCase()}
                  </div>
                </div>
              </div>
            </div>

            {/* Multi-Dimensional Scoring Tree */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-xl font-bold mb-6 flex items-center">
                <Activity className="w-6 h-6 mr-2 text-blue-400" />
                Multi-Dimensional Risk Breakdown
              </h2>

              <div className="font-mono text-sm space-y-1">
                {/* Root */}
                <div className={`font-bold text-lg ${
                  unifiedScore >= 70 ? 'text-red-400' :
                  unifiedScore >= 40 ? 'text-orange-400' :
                  'text-green-400'
                }`}>
                  Overall Risk: {unifiedScore}/100 ({unifiedLevel})
                  {unifiedScore >= 70 && ' ⚠️'}
                </div>

                {/* Social Engineering Branch */}
                {result.se_analysis && (
                  <div className="ml-4 border-l-2 border-gray-600 pl-4 mt-4">
                    <div className={`flex items-center space-x-2 ${
                      result.se_analysis.se_score >= 70 ? 'text-red-400' :
                      result.se_analysis.se_score >= 40 ? 'text-orange-400' :
                      'text-green-400'
                    }`}>
                      <span className="text-gray-500">├──</span>
                      <Brain className="w-4 h-4" />
                      <span className="font-semibold">Social Engineering: {result.se_analysis.se_score}/100</span>
                      {result.se_analysis.se_score >= 70 && <span>⚠️</span>}
                    </div>
                    
                    {/* SE Breakdown */}
                    {result.se_analysis.heuristic_breakdown && (
                      <div className="ml-8 space-y-1 mt-2">
                        {Object.entries(result.se_analysis.heuristic_breakdown).map(([key, value]: [string, any], idx: number, arr: any[]) => (
                          <div key={key} className="flex items-center space-x-2 text-gray-400">
                            <span className="text-gray-600">{idx === arr.length - 1 ? '└──' : '├──'}</span>
                            <span className="capitalize">{key}:</span>
                            <span className={`font-semibold ${
                              value >= 70 ? 'text-red-400' :
                              value >= 40 ? 'text-yellow-400' :
                              'text-green-400'
                            }`}>{value}/100</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* SE Techniques */}
                    {result.se_analysis.techniques?.length > 0 && (
                      <div className="ml-8 mt-2">
                        <div className="text-gray-500 text-xs mb-1">Techniques detected:</div>
                        <div className="flex flex-wrap gap-1">
                          {result.se_analysis.techniques.map((tech: string, idx: number) => (
                            <span key={idx} className="px-2 py-0.5 bg-purple-900/50 text-purple-400 text-xs rounded">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Brand Impersonation Branch */}
                {result.lookalike_analysis && result.lookalike_analysis.matches?.length > 0 && (
                  <div className="ml-4 border-l-2 border-gray-600 pl-4 mt-4">
                    <div className="flex items-center space-x-2 text-orange-400">
                      <span className="text-gray-500">├──</span>
                      <Building className="w-4 h-4" />
                      <span className="font-semibold">Brand Impersonation: {Math.round((result.lookalike_analysis.highest_confidence || 0) * 100)}/100 ⚠️</span>
                    </div>
                    
                    <div className="ml-8 space-y-2 mt-2">
                      {result.lookalike_analysis.matches.slice(0, 3).map((match: any, idx: number) => (
                        <div key={idx} className="bg-gray-900 rounded p-2">
                          {/* Show the suspicious domain first */}
                          {match.suspicious_domain && (
                            <div className="flex items-center space-x-2 text-red-400 mb-1">
                              <span className="text-gray-600">├──</span>
                              <span>Suspicious domain: <span className="font-bold font-mono">{match.suspicious_domain}</span></span>
                            </div>
                          )}
                          <div className="flex items-center space-x-2 text-orange-400">
                            <span className="text-gray-600">├──</span>
                            <span>Impersonating: <span className="font-bold capitalize">{match.target_brand || match.brand || match.target}</span></span>
                          </div>
                          {match.legitimate_domain && (
                            <div className="ml-8 text-green-400 text-xs">
                              Real domain: {match.legitimate_domain}
                            </div>
                          )}
                          {match.description && (
                            <div className="ml-8 text-yellow-400/80 text-xs mt-1">
                              {match.description}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Content Analysis Branch */}
                {result.content_analysis && (
                  <div className="ml-4 border-l-2 border-gray-600 pl-4 mt-4">
                    <div className={`flex items-center space-x-2 ${
                      result.content_analysis.intent_score >= 70 ? 'text-red-400' :
                      result.content_analysis.intent_score >= 40 ? 'text-orange-400' :
                      'text-green-400'
                    }`}>
                      <span className="text-gray-500">├──</span>
                      <FileText className="w-4 h-4" />
                      <span className="font-semibold">Content Analysis: {result.content_analysis.intent_score || 50}/100</span>
                    </div>
                    
                    <div className="ml-8 space-y-1 mt-2">
                      {result.content_analysis.primary_intent && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">├──</span>
                          <span>Intent:</span>
                          <span className="text-yellow-400 font-semibold">{result.content_analysis.primary_intent}</span>
                        </div>
                      )}
                      {result.content_analysis.target && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">├──</span>
                          <span>Target:</span>
                          <span className="text-orange-400">{result.content_analysis.target}</span>
                        </div>
                      )}
                      {result.content_analysis.action_requested && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">└──</span>
                          <span>Action:</span>
                          <span className="text-red-400">{result.content_analysis.action_requested}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Threat Intelligence Branch */}
                {(result.ti_results || result.enrichment) && (
                  <div className="ml-4 border-l-2 border-gray-600 pl-4 mt-4">
                    <div className={`flex items-center space-x-2 ${
                      (result.ti_results?.fused_verdict || '').toLowerCase() === 'malicious' ? 'text-red-400' :
                      (result.ti_results?.fused_verdict || '').toLowerCase() === 'suspicious' ? 'text-orange-400' :
                      'text-green-400'
                    }`}>
                      <span className="text-gray-500">├──</span>
                      <Database className="w-4 h-4" />
                      <span className="font-semibold">Threat Intelligence: {result.ti_results?.fused_score || 0}/100</span>
                      {(result.ti_results?.fused_verdict || '').toLowerCase() === 'malicious' && ' 🔴'}
                    </div>
                    
                    <div className="ml-8 space-y-1 mt-2">
                      {/* VirusTotal */}
                      {result.enrichment?.domain?.virustotal && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">├──</span>
                          <span>VirusTotal:</span>
                          <span className={result.enrichment.domain.virustotal.malicious > 0 ? 'text-red-400' : 'text-green-400'}>
                            {result.enrichment.domain.virustotal.malicious > 0 
                              ? `${result.enrichment.domain.virustotal.malicious} detections` 
                              : 'CLEAN'}
                          </span>
                        </div>
                      )}
                      
                      {/* URLhaus */}
                      {result.ti_results?.sources?.urlhaus && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">├──</span>
                          <span>URLhaus:</span>
                          <span className={
                            result.ti_results.sources.urlhaus.verdict === 'malicious' ? 'text-red-400 font-bold' :
                            result.ti_results.sources.urlhaus.verdict === 'suspicious' ? 'text-orange-400' :
                            'text-green-400'
                          }>
                            {(result.ti_results.sources.urlhaus.verdict || 'CLEAN').toUpperCase()}
                          </span>
                        </div>
                      )}
                      
                      {/* AbuseIPDB */}
                      {result.enrichment?.ip?.abuseipdb && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">├──</span>
                          <span>AbuseIPDB:</span>
                          <span className={
                            result.enrichment.ip.abuseipdb.abuse_confidence_score > 50 ? 'text-red-400' :
                            result.enrichment.ip.abuseipdb.abuse_confidence_score > 20 ? 'text-orange-400' :
                            'text-green-400'
                          }>
                            {result.enrichment.ip.abuseipdb.abuse_confidence_score}% abuse confidence
                          </span>
                        </div>
                      )}

                      {/* Domain Age */}
                      {result.enrichment?.domain?.whois?.domain_age_days !== undefined && (
                        <div className="flex items-center space-x-2 text-gray-400">
                          <span className="text-gray-600">└──</span>
                          <span>Domain Age:</span>
                          <span className={
                            result.enrichment.domain.whois.domain_age_days < 30 ? 'text-red-400' :
                            result.enrichment.domain.whois.domain_age_days < 90 ? 'text-orange-400' :
                            'text-green-400'
                          }>
                            {result.enrichment.domain.whois.domain_age_days} days
                            {result.enrichment.domain.whois.domain_age_days < 30 && ' ⚠️ NEW'}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Technical Indicators Branch */}
                <div className="ml-4 border-l-2 border-gray-600 pl-4 mt-4">
                  <div className="flex items-center space-x-2 text-blue-400">
                    <span className="text-gray-500">└──</span>
                    <Server className="w-4 h-4" />
                    <span className="font-semibold">Technical Indicators</span>
                  </div>
                  
                  <div className="ml-8 space-y-1 mt-2">
                    {/* Authentication */}
                    <div className="flex items-center space-x-2 text-gray-400">
                      <span className="text-gray-600">├──</span>
                      <Key className="w-3 h-3" />
                      <span>SPF:</span>
                      <span className={
                        spf.result === 'pass' ? 'text-green-400' :
                        spf.result === 'fail' ? 'text-red-400' :
                        'text-yellow-400'
                      }>
                        {(spf.result || 'none').toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="flex items-center space-x-2 text-gray-400">
                      <span className="text-gray-600">├──</span>
                      <Key className="w-3 h-3" />
                      <span>DKIM:</span>
                      <span className={
                        dkim.result === 'pass' ? 'text-green-400' :
                        dkim.result === 'fail' ? 'text-red-400' :
                        'text-yellow-400'
                      }>
                        {(dkim.result || 'none').toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="flex items-center space-x-2 text-gray-400">
                      <span className="text-gray-600">├──</span>
                      <Key className="w-3 h-3" />
                      <span>DMARC:</span>
                      <span className={
                        dmarc.result === 'pass' ? 'text-green-400' :
                        dmarc.result === 'fail' ? 'text-red-400' :
                        'text-yellow-400'
                      }>
                        {(dmarc.result || 'none').toUpperCase()}
                      </span>
                    </div>

                    {/* TLD */}
                    {result.email?.sender?.domain && (
                      <div className="flex items-center space-x-2 text-gray-400">
                        <span className="text-gray-600">├──</span>
                        <Globe className="w-3 h-3" />
                        <span>TLD:</span>
                        <span className={
                          ['.xyz', '.top', '.club', '.work', '.click', '.link', '.buzz'].some(
                            tld => result.email.sender.domain.endsWith(tld)
                          ) ? 'text-orange-400' : 'text-gray-300'
                        }>
                          .{result.email.sender.domain.split('.').pop()}
                          {['.xyz', '.top', '.club', '.work', '.click', '.link', '.buzz'].some(
                            tld => result.email.sender.domain.endsWith(tld)
                          ) && ' ⚠️ Suspicious'}
                        </span>
                      </div>
                    )}

                    {/* Attachments */}
                    <div className="flex items-center space-x-2 text-gray-400">
                      <span className="text-gray-600">├──</span>
                      <Paperclip className="w-3 h-3" />
                      <span>Attachments:</span>
                      <span className={result.email?.attachments?.length > 0 ? 'text-yellow-400' : 'text-gray-500'}>
                        {result.email?.attachments?.length || 0}
                        {result.email?.attachments?.some((a: any) => 
                          ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.iso', '.img'].some(
                            ext => a.filename?.toLowerCase().endsWith(ext)
                          )
                        ) && ' ⚠️ Executable'}
                      </span>
                    </div>

                    {/* URLs */}
                    <div className="flex items-center space-x-2 text-gray-400">
                      <span className="text-gray-600">└──</span>
                      <LinkIcon className="w-3 h-3" />
                      <span>URLs:</span>
                      <span className={result.email?.urls?.length > 0 ? 'text-yellow-400' : 'text-gray-500'}>
                        {result.email?.urls?.length || 0}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Detection Rules Summary */}
            {result.detection?.rules_triggered?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h2 className="text-xl font-bold mb-4 flex items-center">
                  <Shield className="w-6 h-6 mr-2 text-orange-400" />
                  Triggered Detection Rules ({result.detection.rules_triggered.length})
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {result.detection.rules_triggered.map((rule: any, idx: number) => (
                    <div key={idx} className={`p-3 rounded-lg border ${
                      rule.severity?.toLowerCase() === 'critical' ? 'bg-red-900/30 border-red-500' :
                      rule.severity?.toLowerCase() === 'high' ? 'bg-orange-900/30 border-orange-500' :
                      rule.severity?.toLowerCase() === 'medium' ? 'bg-yellow-900/30 border-yellow-500' :
                      'bg-blue-900/30 border-blue-500'
                    }`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
                          rule.severity?.toLowerCase() === 'critical' ? 'bg-red-600' :
                          rule.severity?.toLowerCase() === 'high' ? 'bg-orange-600' :
                          rule.severity?.toLowerCase() === 'medium' ? 'bg-yellow-600 text-black' :
                          'bg-blue-600'
                        }`}>
                          {rule.severity || 'INFO'}
                        </span>
                        {rule.mitre_id && (
                          <span className="text-xs text-gray-500">{rule.mitre_id}</span>
                        )}
                      </div>
                      <div className="font-semibold text-sm text-white">{rule.name || rule.rule_name}</div>
                      {rule.matched_content && (
                        <div className="text-xs text-gray-400 mt-1 truncate">
                          Match: {rule.matched_content}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Key Findings Summary */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-xl font-bold mb-4 flex items-center">
                <AlertTriangle className="w-6 h-6 mr-2 text-yellow-400" />
                Key Findings
              </h2>

              <div className="space-y-3">
                {/* Auto-generated key findings based on analysis */}
                {unifiedScore >= 70 && (
                  <div className="flex items-start space-x-3 p-3 bg-red-900/30 rounded-lg border border-red-500">
                    <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-red-400">Critical Risk Detected</div>
                      <div className="text-sm text-gray-300">
                        This email exhibits multiple high-risk indicators consistent with {result.detection?.primary_classification || 'malicious'} activity.
                      </div>
                    </div>
                  </div>
                )}

                {result.se_analysis && result.se_analysis.se_score >= 60 && (
                  <div className="flex items-start space-x-3 p-3 bg-purple-900/30 rounded-lg border border-purple-500">
                    <Brain className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-purple-400">Social Engineering Tactics Detected</div>
                      <div className="text-sm text-gray-300">
                        {result.se_analysis.techniques?.length > 0 
                          ? `Uses ${result.se_analysis.techniques.slice(0, 3).join(', ')} to manipulate the recipient.`
                          : 'Email uses psychological manipulation techniques to influence recipient behavior.'}
                      </div>
                    </div>
                  </div>
                )}

                {result.lookalike_analysis?.matches?.length > 0 && (
                  <div className="flex items-start space-x-3 p-3 bg-orange-900/30 rounded-lg border border-orange-500">
                    <Building className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-orange-400">Brand Impersonation</div>
                      <div className="text-sm text-gray-300">
                        Domain appears to impersonate {result.lookalike_analysis.matches[0]?.brand || result.lookalike_analysis.matches[0]?.target}.
                        {result.lookalike_analysis.matches[0]?.description && ` ${result.lookalike_analysis.matches[0].description}`}
                      </div>
                    </div>
                  </div>
                )}

                {spf.result === 'fail' && (
                  <div className="flex items-start space-x-3 p-3 bg-red-900/30 rounded-lg border border-red-500">
                    <Key className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-red-400">Email Authentication Failed</div>
                      <div className="text-sm text-gray-300">
                        SPF check failed, indicating the sender may be spoofing their email address.
                      </div>
                    </div>
                  </div>
                )}

                {result.ti_results?.fused_verdict === 'malicious' && (
                  <div className="flex items-start space-x-3 p-3 bg-red-900/30 rounded-lg border border-red-500">
                    <Database className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-red-400">Known Threat Indicators</div>
                      <div className="text-sm text-gray-300">
                        Threat intelligence sources have flagged elements in this email as malicious.
                      </div>
                    </div>
                  </div>
                )}

                {/* If nothing notable */}
                {unifiedScore < 20 && (
                  <div className="flex items-start space-x-3 p-3 bg-green-900/30 rounded-lg border border-green-500">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-green-400">Low Risk Email</div>
                      <div className="text-sm text-gray-300">
                        No significant threat indicators detected in this email.
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Recommendations */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-xl font-bold mb-4 flex items-center">
                <CheckCircle className="w-6 h-6 mr-2 text-green-400" />
                Recommended Actions
              </h2>

              <div className="space-y-2">
                {unifiedScore >= 70 ? (
                  <>
                    <div className="flex items-center space-x-2 text-red-400">
                      <span className="font-bold">1.</span>
                      <span>Block sender and domain immediately</span>
                    </div>
                    <div className="flex items-center space-x-2 text-red-400">
                      <span className="font-bold">2.</span>
                      <span>Alert users who may have received similar emails</span>
                    </div>
                    <div className="flex items-center space-x-2 text-orange-400">
                      <span className="font-bold">3.</span>
                      <span>Search mail logs for related messages</span>
                    </div>
                    <div className="flex items-center space-x-2 text-yellow-400">
                      <span className="font-bold">4.</span>
                      <span>Submit IOCs to threat intelligence platform</span>
                    </div>
                  </>
                ) : unifiedScore >= 40 ? (
                  <>
                    <div className="flex items-center space-x-2 text-orange-400">
                      <span className="font-bold">1.</span>
                      <span>Verify sender through alternate channel</span>
                    </div>
                    <div className="flex items-center space-x-2 text-yellow-400">
                      <span className="font-bold">2.</span>
                      <span>Do not click links or open attachments until verified</span>
                    </div>
                    <div className="flex items-center space-x-2 text-blue-400">
                      <span className="font-bold">3.</span>
                      <span>Monitor for similar messages</span>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="flex items-center space-x-2 text-green-400">
                      <span className="font-bold">1.</span>
                      <span>No immediate action required</span>
                    </div>
                    <div className="flex items-center space-x-2 text-blue-400">
                      <span className="font-bold">2.</span>
                      <span>Continue standard security practices</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Headers Tab */}
        {activeTab === 'headers' && (
          <div className="space-y-6">
            {/* Received Chain */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Network className="w-5 h-5 mr-2 text-blue-400" />
                Email Routing (Received Chain)
              </h2>
              
              {(headerAnalysis as any)?.received_chain?.length > 0 ? (
                <div className="space-y-2">
                  {((headerAnalysis as any).received_chain || []).map((hop: any, idx: number) => (
                    <div key={idx} className="flex items-start bg-gray-900 rounded p-3">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-sm font-bold mr-3">
                        {idx + 1}
                      </div>
                      <div className="flex-grow">
                        <div className="flex items-center space-x-2 mb-1">
                          {hop.from_host && (
                            <>
                              <span className="font-mono text-sm text-gray-300">{hop.from_host}</span>
                              {hop.from_ip && (
                                <span className="text-xs text-gray-500">({hop.from_ip})</span>
                              )}
                              <ArrowRight className="w-4 h-4 text-gray-500" />
                            </>
                          )}
                          <span className="font-mono text-sm text-green-400">{hop.by_host || 'Unknown'}</span>
                        </div>
                        <div className="flex items-center space-x-4 text-xs text-gray-400">
                          {hop.timestamp && (
                            <span className="flex items-center">
                              <Clock className="w-3 h-3 mr-1" />
                              {new Date(hop.timestamp).toLocaleString()}
                            </span>
                          )}
                          {hop.delay_seconds !== undefined && hop.delay_seconds > 0 && (
                            <span className={`${hop.delay_seconds > 60 ? 'text-yellow-400' : ''}`}>
                              +{hop.delay_seconds}s delay
                            </span>
                          )}
                          {hop.protocol && (
                            <span className="bg-gray-700 px-1.5 py-0.5 rounded">
                              {hop.protocol}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-400">No received headers found</p>
              )}
            </div>

            {/* Originating IP Analysis */}
            {(headerAnalysis?.originating_ip || originatingIp) && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <MapPin className="w-5 h-5 mr-2 text-red-400" />
                  Originating IP Analysis
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-gray-500 uppercase">IP Address</label>
                    <p className="text-white font-mono flex items-center">
                      {headerAnalysis?.originating_ip || originatingIp?.ip_address}
                      <button
                        onClick={() => copyToClipboard(headerAnalysis?.originating_ip || originatingIp?.ip_address, 'ip')}
                        className="ml-2 text-gray-400 hover:text-white"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </p>
                  </div>
                  {originatingIp?.country && (
                    <div>
                      <label className="text-xs text-gray-500 uppercase">Location</label>
                      <p className="text-white">{originatingIp.city}, {originatingIp.country}</p>
                    </div>
                  )}
                  {originatingIp?.asn && (
                    <div>
                      <label className="text-xs text-gray-500 uppercase">ASN</label>
                      <p className="text-white">AS{originatingIp.asn} - {originatingIp.as_org}</p>
                    </div>
                  )}
                  {originatingIp?.abuseipdb_score !== undefined && (
                    <div>
                      <label className="text-xs text-gray-500 uppercase">AbuseIPDB Score</label>
                      <p className={`font-bold ${originatingIp.abuseipdb_score > 50 ? 'text-red-400' : 'text-green-400'}`}>
                        {originatingIp.abuseipdb_score}% abuse confidence
                      </p>
                    </div>
                  )}
                </div>
                <div className="mt-3 flex space-x-2">
                  {getOsintLinks('ip', headerAnalysis?.originating_ip || originatingIp?.ip_address).map(link => (
                    <a
                      key={link.name}
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded flex items-center"
                    >
                      <ExternalLink className="w-3 h-3 mr-1" />
                      {link.name}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Raw Headers */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <FileText className="w-5 h-5 mr-2 text-gray-400" />
                Raw Headers
              </h2>
              <div className="bg-gray-900 rounded p-3 font-mono text-xs overflow-x-auto max-h-96 overflow-y-auto">
                {result.email?.raw_headers ? (
                  Object.entries(result.email.raw_headers).map(([key, value]) => (
                    <div key={key} className="mb-1">
                      <span className="text-blue-400">{key}:</span>
                      <span className="text-gray-300 ml-2">{String(value)}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-400">No raw headers available</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Threat Intel Tab */}
        {activeTab === 'threatintel' && (
          <div className="space-y-6">
            {/* TI Summary Banner */}
            <div className={`rounded-lg p-4 border-2 ${
              tiResults?.fused_verdict === 'malicious' ? 'bg-red-900/30 border-red-700' :
              tiResults?.fused_verdict === 'suspicious' ? 'bg-orange-900/30 border-orange-700' :
              'bg-gray-800 border-gray-700'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <Database className={`w-8 h-8 ${
                    tiResults?.fused_verdict === 'malicious' ? 'text-red-400' :
                    tiResults?.fused_verdict === 'suspicious' ? 'text-orange-400' :
                    'text-blue-400'
                  }`} />
                  <div>
                    <h2 className="text-lg font-semibold">Threat Intelligence Summary</h2>
                    <p className="text-sm text-gray-400">
                      {tiResults ? `Fused score: ${tiResults.fused_score}/100` : 'Enrichment data from external sources'}
                    </p>
                  </div>
                </div>
                {tiResults?.fused_verdict && (
                  <span className={`px-3 py-1 rounded-lg font-bold text-sm ${
                    tiResults.fused_verdict === 'malicious' ? 'bg-red-600 text-white' :
                    tiResults.fused_verdict === 'suspicious' ? 'bg-orange-600 text-white' :
                    'bg-green-600 text-white'
                  }`}>
                    {tiResults.fused_verdict.toUpperCase()}
                  </span>
                )}
              </div>
              
              {/* TI Findings */}
              {tiResults?.findings && tiResults.findings.length > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Key Findings</h3>
                  <ul className="space-y-1">
                    {tiResults.findings.map((finding: string, idx: number) => (
                      <li key={idx} className="flex items-start text-sm">
                        <AlertTriangle className="w-4 h-4 mr-2 text-yellow-400 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300">{finding}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Sender Domain Analysis */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Globe className="w-5 h-5 mr-2 text-blue-400" />
                Sender Domain Analysis
              </h2>
              
              {/* Basic Domain Info - Always show */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <label className="text-xs text-gray-500 uppercase block mb-1">Domain</label>
                  <p className="font-mono text-sm text-blue-400">{result.email?.sender?.domain || 'Unknown'}</p>
                </div>
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <label className="text-xs text-gray-500 uppercase block mb-1">Sender</label>
                  <p className="font-mono text-sm text-gray-300 truncate">{result.email?.sender?.email || 'Unknown'}</p>
                </div>
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <label className="text-xs text-gray-500 uppercase block mb-1">Display Name</label>
                  <p className="text-sm text-gray-300">{result.email?.sender?.display_name || 'None'}</p>
                </div>
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <label className="text-xs text-gray-500 uppercase block mb-1">Envelope From</label>
                  <p className="font-mono text-sm text-gray-300 truncate">{result.email?.envelope_from?.email || 'Same as From'}</p>
                </div>
              </div>

              {/* Enriched Domain Data */}
              {senderDomain && (
                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <label className="text-xs text-gray-500 uppercase block mb-1">VirusTotal</label>
                    {senderDomain.virustotal_positives !== undefined ? (
                      <div className={`text-xl font-bold ${senderDomain.virustotal_positives > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {senderDomain.virustotal_positives}/{senderDomain.virustotal_total}
                        <span className="text-sm font-normal text-gray-400 ml-1">detections</span>
                      </div>
                    ) : (
                      <div className="text-gray-500">Not scanned</div>
                    )}
                  </div>
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <label className="text-xs text-gray-500 uppercase block mb-1">Domain Age</label>
                    {senderDomain.creation_date ? (
                      <div className={`text-xl font-bold ${senderDomain.is_newly_registered ? 'text-yellow-400' : 'text-green-400'}`}>
                        {senderDomain.is_newly_registered ? '⚠️ NEW' : '✓ Established'}
                      </div>
                    ) : (
                      <div className="text-gray-500">Unknown</div>
                    )}
                  </div>
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <label className="text-xs text-gray-500 uppercase block mb-1">Registrar</label>
                    <div className="text-sm text-gray-300 truncate">{senderDomain.registrar || 'Unknown'}</div>
                  </div>
                </div>
              )}

              {/* DNS Records */}
              {senderDomain?.dns_records && (
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <h3 className="text-sm font-semibold text-gray-400 mb-2">DNS Security Records</h3>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {senderDomain.dns_records.spf && (
                      <div className="bg-gray-800 rounded p-2">
                        <span className="text-blue-400 font-medium">SPF:</span>
                        <span className="ml-2 font-mono text-xs text-gray-400 break-all">{senderDomain.dns_records.spf}</span>
                      </div>
                    )}
                    {senderDomain.dns_records.dmarc && (
                      <div className="bg-gray-800 rounded p-2">
                        <span className="text-purple-400 font-medium">DMARC:</span>
                        <span className="ml-2 font-mono text-xs text-gray-400 break-all">{senderDomain.dns_records.dmarc}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Blacklist Status */}
              {senderDomain && (senderDomain.blacklist_count > 0 || senderDomain.blacklists_listed?.length > 0) && (
                <div className="bg-red-900/30 rounded-lg p-3 border border-red-700 mt-4">
                  <h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    🚫 Domain Blacklisted ({senderDomain.blacklist_count || senderDomain.blacklists_listed?.length || 0} lists)
                  </h3>
                  {senderDomain.blacklists_listed && senderDomain.blacklists_listed.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {senderDomain.blacklists_listed.map((bl: string, idx: number) => (
                        <span key={idx} className="px-2 py-1 text-xs bg-red-900/50 text-red-300 rounded border border-red-700">
                          {bl}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* No enrichment notice */}
              {!senderDomain && (
                <div className="bg-gray-900/50 rounded-lg p-3 border border-dashed border-gray-700 text-center">
                  <p className="text-sm text-gray-500">
                    <Info className="w-4 h-4 inline mr-1" />
                    Configure VirusTotal API key in Settings for domain reputation data
                  </p>
                </div>
              )}
            </div>

            {/* Originating IP & Geolocation */}
            {(originatingIp || result.email?.originating_ip || result.enrichment?.originating_ip) && (() => {
              const ipData = originatingIp || result.enrichment?.originating_ip || {};
              const ipAddress = ipData.ip || ipData.ip_address || result.email?.originating_ip || 'Unknown';
              
              return (
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <h2 className="text-lg font-semibold mb-4 flex items-center">
                    <MapPin className="w-5 h-5 mr-2 text-green-400" />
                    Originating IP & Geolocation
                  </h2>
                  
                  {/* IP Overview */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                      <label className="text-xs text-gray-500 uppercase block mb-1">IP Address</label>
                      <p className="font-mono text-lg text-green-400">{ipAddress}</p>
                    </div>
                    {(ipData.country || ipData.country_code) && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">Country</label>
                        <p className="text-lg text-gray-200">
                          <span className="mr-2">{ipData.country_code && getFlagEmoji(ipData.country_code)}</span>
                          {ipData.country || ipData.country_code}
                        </p>
                      </div>
                    )}
                    {ipData.city && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">City</label>
                        <p className="text-lg text-gray-200">{ipData.city}{ipData.region ? `, ${ipData.region}` : ''}</p>
                      </div>
                    )}
                    {ipData.timezone && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">Timezone</label>
                        <p className="text-sm text-gray-200">{ipData.timezone}</p>
                      </div>
                    )}
                  </div>

                  {/* Geo Coordinates & Map Link */}
                  {(ipData.lat || ipData.lon) && (
                    <div className="bg-gray-900 rounded-lg p-3 border border-gray-700 mb-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <label className="text-xs text-gray-500 uppercase block mb-1">Coordinates</label>
                          <p className="font-mono text-sm text-gray-300">
                            {ipData.lat?.toFixed(4)}, {ipData.lon?.toFixed(4)}
                          </p>
                        </div>
                        <a
                          href={`https://www.google.com/maps?q=${ipData.lat},${ipData.lon}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm transition-colors"
                        >
                          <MapPin className="w-4 h-4" />
                          View on Map
                        </a>
                      </div>
                    </div>
                  )}

                  {/* Network Info */}
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">
                    {(ipData.isp || ipData.org) && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">ISP / Organization</label>
                        <p className="text-sm text-gray-300">{ipData.isp || ipData.org}</p>
                      </div>
                    )}
                    {(ipData.asn || ipData.as_org) && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">ASN</label>
                        <p className="text-sm text-gray-300">
                          {ipData.asn && <span className="font-mono text-blue-400">AS{ipData.asn}</span>}
                          {ipData.as_org && <span className="ml-2 text-gray-400">{ipData.as_org}</span>}
                        </p>
                      </div>
                    )}
                    {(ipData.abuseipdb_score !== undefined || ipData.abuse_score !== undefined) && (
                      <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <label className="text-xs text-gray-500 uppercase block mb-1">AbuseIPDB Score</label>
                        <div className="flex items-center gap-2">
                          <div className={`text-2xl font-bold ${
                            (ipData.abuseipdb_score || ipData.abuse_score) > 50 ? 'text-red-400' : 
                            (ipData.abuseipdb_score || ipData.abuse_score) > 20 ? 'text-orange-400' : 
                            'text-green-400'
                          }`}>
                            {ipData.abuseipdb_score || ipData.abuse_score}%
                          </div>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            (ipData.abuseipdb_score || ipData.abuse_score) > 50 ? 'bg-red-900/50 text-red-400' : 
                            (ipData.abuseipdb_score || ipData.abuse_score) > 20 ? 'bg-orange-900/50 text-orange-400' : 
                            'bg-green-900/50 text-green-400'
                          }`}>
                            {(ipData.abuseipdb_score || ipData.abuse_score) > 50 ? 'HIGH RISK' : (ipData.abuseipdb_score || ipData.abuse_score) > 20 ? 'MODERATE' : 'LOW RISK'}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Risk Indicators */}
                  {(ipData.is_proxy || ipData.is_datacenter || ipData.is_mobile || ipData.is_tor || ipData.is_vpn) && (
                    <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                      <label className="text-xs text-gray-500 uppercase block mb-2">Risk Indicators</label>
                      <div className="flex flex-wrap gap-2">
                        {ipData.is_proxy && (
                          <span className="px-3 py-1 rounded-lg text-sm bg-orange-900/50 text-orange-400 border border-orange-700 flex items-center gap-1">
                            <AlertTriangle className="w-4 h-4" />
                            Proxy Detected
                          </span>
                        )}
                        {ipData.is_vpn && (
                          <span className="px-3 py-1 rounded-lg text-sm bg-yellow-900/50 text-yellow-400 border border-yellow-700 flex items-center gap-1">
                            <Lock className="w-4 h-4" />
                            VPN Detected
                          </span>
                        )}
                        {ipData.is_tor && (
                          <span className="px-3 py-1 rounded-lg text-sm bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                            <AlertTriangle className="w-4 h-4" />
                            Tor Exit Node
                          </span>
                        )}
                        {ipData.is_datacenter && (
                          <span className="px-3 py-1 rounded-lg text-sm bg-blue-900/50 text-blue-400 border border-blue-700 flex items-center gap-1">
                            <Server className="w-4 h-4" />
                            Datacenter/Hosting
                          </span>
                        )}
                        {ipData.is_mobile && (
                          <span className="px-3 py-1 rounded-lg text-sm bg-purple-900/50 text-purple-400 border border-purple-700 flex items-center gap-1">
                            <Network className="w-4 h-4" />
                            Mobile Network
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* IP Blacklist Status */}
                  {(ipData.blacklist_count > 0 || ipData.blacklists_listed?.length > 0) && (
                    <div className="bg-red-900/30 rounded-lg p-3 border border-red-700 mt-4">
                      <h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center">
                        <AlertTriangle className="w-4 h-4 mr-2" />
                        🚫 IP Blacklisted ({ipData.blacklist_count || ipData.blacklists_listed?.length || 0} lists)
                      </h3>
                      {ipData.blacklists_listed && ipData.blacklists_listed.length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-2">
                          {ipData.blacklists_listed.map((bl: string, idx: number) => (
                            <span key={idx} className="px-2 py-1 text-xs bg-red-900/50 text-red-300 rounded border border-red-700">
                              {bl}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* External IP Lookup Links */}
                  <div className="mt-4 flex flex-wrap gap-2">
                    <a
                      href={`https://www.abuseipdb.com/check/${ipAddress}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm text-gray-300 transition-colors"
                    >
                      <ExternalLink className="w-3 h-3" />
                      AbuseIPDB
                    </a>
                    <a
                      href={`https://www.virustotal.com/gui/ip-address/${ipAddress}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm text-gray-300 transition-colors"
                    >
                      <ExternalLink className="w-3 h-3" />
                      VirusTotal
                    </a>
                    <a
                      href={`https://www.shodan.io/host/${ipAddress}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm text-gray-300 transition-colors"
                    >
                      <ExternalLink className="w-3 h-3" />
                      Shodan
                    </a>
                    <a
                      href={`https://ipinfo.io/${ipAddress}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm text-gray-300 transition-colors"
                    >
                      <ExternalLink className="w-3 h-3" />
                      IPInfo
                    </a>
                  </div>
                </div>
              );
            })()}

            {/* URL Analysis */}
            {result.email?.urls?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <LinkIcon className="w-5 h-5 mr-2 text-purple-400" />
                  URL Analysis ({result.email.urls.length} URLs)
                </h2>
                <div className="space-y-3">
                  {result.email.urls.slice(0, 10).map((url: any, idx: number) => {
                    const urlStr = typeof url === 'string' ? url : url.url;
                    const enriched = urlEnrichments.find((e: any) => e.url === urlStr);
                    const urlObj = typeof url === 'object' ? url : { url: urlStr };
                    
                    // Extract domain from URL for display
                    let urlDomain = '';
                    try {
                      urlDomain = new URL(urlStr).hostname;
                    } catch {
                      urlDomain = urlStr.split('/')[2] || urlStr;
                    }
                    
                    return (
                      <div key={idx} className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                        <div className="flex items-start justify-between">
                          <div className="flex-grow min-w-0">
                            <p className="font-mono text-sm text-yellow-400 break-all">
                              {defang(urlStr)}
                            </p>
                            <div className="flex items-center flex-wrap gap-2 mt-2">
                              {/* Domain badge */}
                              <span className="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-300">
                                {urlDomain}
                              </span>
                              
                              {/* Risk indicators */}
                              {urlObj.is_shortened && (
                                <span className="px-2 py-0.5 rounded text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700">
                                  ⚠️ URL Shortener
                                </span>
                              )}
                              {urlObj.is_data_uri && (
                                <span className="px-2 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-700">
                                  🚨 Data URI
                                </span>
                              )}
                              {urlObj.has_ip_address && (
                                <span className="px-2 py-0.5 rounded text-xs bg-orange-900/50 text-orange-400 border border-orange-700">
                                  ⚠️ IP in URL
                                </span>
                              )}
                              {urlObj.suspicious_tld && (
                                <span className="px-2 py-0.5 rounded text-xs bg-orange-900/50 text-orange-400 border border-orange-700">
                                  ⚠️ Suspicious TLD
                                </span>
                              )}
                              {urlObj.has_at_symbol && (
                                <span className="px-2 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-700">
                                  🚨 @ Symbol
                                </span>
                              )}
                              
                              {/* Enrichment badges */}
                              {enriched?.virustotal_positives !== undefined && (
                                <span className={`px-2 py-0.5 rounded text-xs ${enriched.virustotal_positives > 0 ? 'bg-red-900/50 text-red-400 border border-red-700' : 'bg-green-900/50 text-green-400 border border-green-700'}`}>
                                  VT: {enriched.virustotal_positives}/{enriched.virustotal_total}
                                </span>
                              )}
                              {enriched?.phishtank_in_database && (
                                <span className="px-2 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-700">
                                  🎣 PhishTank: KNOWN PHISH
                                </span>
                              )}
                            </div>
                          </div>
                          <button
                            onClick={() => copyToClipboard(urlStr, `url-${idx}`)}
                            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded ml-2 flex-shrink-0"
                            title="Copy URL"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                  {result.email.urls.length > 10 && (
                    <p className="text-sm text-gray-500 text-center">
                      +{result.email.urls.length - 10} more URLs (see IOCs tab for full list)
                    </p>
                  )}
                </div>
                
                {/* No enrichment notice */}
                {urlEnrichments.length === 0 && (
                  <div className="mt-3 bg-gray-900/50 rounded-lg p-3 border border-dashed border-gray-700 text-center">
                    <p className="text-sm text-gray-500">
                      <Info className="w-4 h-4 inline mr-1" />
                      Configure VirusTotal/URLhaus API keys for URL reputation scanning
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Attachment Analysis */}
            {result.email?.attachments?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Paperclip className="w-5 h-5 mr-2 text-orange-400" />
                  Attachment Analysis ({result.email.attachments.length} files)
                </h2>
                <div className="space-y-4">
                  {result.email.attachments.map((att: any, idx: number) => {
                    const enriched = attachmentEnrichments.find((e: any) => e.sha256 === att.sha256);
                    const threatLevel = att.threat_level?.toLowerCase() || 'unknown';
                    const threatScore = att.threat_score || 0;
                    
                    const getThreatStyles = (level: string, score: number) => {
                      if (level === 'critical' || score >= 70) return { bg: 'bg-red-900/30', border: 'border-red-600', headerBg: 'bg-red-900/50', text: 'text-red-400' };
                      if (level === 'high' || score >= 50) return { bg: 'bg-orange-900/30', border: 'border-orange-600', headerBg: 'bg-orange-900/50', text: 'text-orange-400' };
                      if (level === 'medium' || score >= 25) return { bg: 'bg-yellow-900/30', border: 'border-yellow-600', headerBg: 'bg-yellow-900/50', text: 'text-yellow-400' };
                      if (level === 'low' || score > 0) return { bg: 'bg-blue-900/30', border: 'border-blue-700', headerBg: 'bg-blue-900/50', text: 'text-blue-400' };
                      return { bg: 'bg-gray-900', border: 'border-gray-700', headerBg: 'bg-gray-800', text: 'text-green-400' };
                    };
                    
                    const threatStyles = getThreatStyles(threatLevel, threatScore);
                    
                    return (
                      <div key={idx} className={`${threatStyles.bg} rounded-lg border ${threatStyles.border} overflow-hidden`}>
                        {/* Header */}
                        <div className={`${threatStyles.headerBg} px-4 py-3 flex items-center justify-between`}>
                          <div className="flex items-center space-x-3">
                            <Paperclip className="w-5 h-5 text-gray-400" />
                            <div>
                              <p className="font-medium text-gray-200">{att.filename}</p>
                              <p className="text-xs text-gray-500">
                                {att.content_type} • {((att.size_bytes || att.size || 0) / 1024).toFixed(1)} KB
                                {att.entropy && ` • Entropy: ${att.entropy.toFixed(2)}`}
                              </p>
                            </div>
                          </div>
                          
                          {/* Threat Score */}
                          <div className="flex items-center space-x-3">
                            {threatScore > 0 && (
                              <div className={`flex items-center gap-2 px-3 py-1 rounded-full ${threatStyles.bg} border ${threatStyles.border}`}>
                                <Shield className={`w-4 h-4 ${threatStyles.text}`} />
                                <span className={`text-sm font-bold ${threatStyles.text}`}>{threatScore}/100</span>
                              </div>
                            )}
                            {threatLevel === 'clean' && threatScore === 0 && (
                              <span className="px-3 py-1 rounded-full bg-green-900/50 text-green-400 text-sm font-medium border border-green-700">
                                ✓ Clean
                              </span>
                            )}
                          </div>
                        </div>
                        
                        {/* Body */}
                        <div className="p-4 space-y-3">
                          {/* Warning Badges */}
                          <div className="flex flex-wrap gap-2">
                            {att.is_executable && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> Executable
                              </span>
                            )}
                            {(att.has_macros || att.is_office_with_macros) && (
                              <span className="px-2 py-1 rounded text-xs bg-orange-900/50 text-orange-400 border border-orange-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> VBA Macros
                              </span>
                            )}
                            {att.has_auto_exec_macros && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <XCircle className="w-3 h-3" /> Auto-Execute Macros
                              </span>
                            )}
                            {att.has_dde && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> DDE Links
                              </span>
                            )}
                            {att.has_ole_objects && (
                              <span className="px-2 py-1 rounded text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> OLE Objects
                              </span>
                            )}
                            {att.has_javascript && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> JavaScript
                              </span>
                            )}
                            {att.has_embedded_files && (
                              <span className="px-2 py-1 rounded text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700 flex items-center gap-1">
                                <FileText className="w-3 h-3" /> Embedded Files
                              </span>
                            )}
                            {att.is_packed && (
                              <span className="px-2 py-1 rounded text-xs bg-purple-900/50 text-purple-400 border border-purple-700 flex items-center gap-1">
                                <Lock className="w-3 h-3" /> Packed
                              </span>
                            )}
                            {att.has_suspicious_imports && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> Suspicious API Imports
                              </span>
                            )}
                            {att.type_mismatch && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <XCircle className="w-3 h-3" /> Type Mismatch
                              </span>
                            )}
                            {att.has_double_extension && (
                              <span className="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-700 flex items-center gap-1">
                                <XCircle className="w-3 h-3" /> Double Extension
                              </span>
                            )}
                            {att.is_archive && (
                              <span className="px-2 py-1 rounded text-xs bg-blue-900/50 text-blue-400 border border-blue-700">
                                Archive
                              </span>
                            )}
                            {att.is_script && (
                              <span className="px-2 py-1 rounded text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700">
                                Script
                              </span>
                            )}
                            {enriched?.virustotal_positives !== undefined && (
                              <span className={`px-2 py-1 rounded text-xs font-medium ${enriched.virustotal_positives > 0 ? 'bg-red-900/50 text-red-400 border border-red-700' : 'bg-green-900/50 text-green-400 border border-green-700'}`}>
                                VT: {enriched.virustotal_positives}/{enriched.virustotal_total}
                              </span>
                            )}
                          </div>
                          
                          {/* Threat Summary */}
                          {att.threat_summary && threatScore > 0 && (
                            <div className={`p-3 rounded-lg bg-gray-900/50 border ${threatStyles.border}`}>
                              <p className={`text-sm ${threatStyles.text}`}>{att.threat_summary}</p>
                            </div>
                          )}
                          
                          {/* Extracted IOCs from file */}
                          {((att.extracted_urls?.length > 0) || (att.extracted_ips?.length > 0) || (att.suspicious_strings?.length > 0)) && (
                            <div className="bg-gray-900/50 rounded-lg p-3 border border-gray-700">
                              <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">
                                Extracted from File Content
                              </h4>
                              <div className="space-y-2">
                                {att.extracted_urls?.length > 0 && (
                                  <div>
                                    <span className="text-xs text-gray-500 mr-2">URLs:</span>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {att.extracted_urls.slice(0, 5).map((url: string, i: number) => (
                                        <code key={i} className="text-xs bg-purple-900/30 text-purple-400 px-2 py-0.5 rounded border border-purple-700/50 max-w-xs truncate">
                                          {url}
                                        </code>
                                      ))}
                                      {att.extracted_urls.length > 5 && (
                                        <span className="text-xs text-gray-500">+{att.extracted_urls.length - 5} more</span>
                                      )}
                                    </div>
                                  </div>
                                )}
                                {att.extracted_ips?.length > 0 && (
                                  <div>
                                    <span className="text-xs text-gray-500 mr-2">IPs:</span>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {att.extracted_ips.slice(0, 5).map((ip: string, i: number) => (
                                        <code key={i} className="text-xs bg-blue-900/30 text-blue-400 px-2 py-0.5 rounded border border-blue-700/50">
                                          {ip}
                                        </code>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {att.suspicious_strings?.length > 0 && (
                                  <div>
                                    <span className="text-xs text-gray-500 mr-2">Suspicious Strings:</span>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {att.suspicious_strings.slice(0, 5).map((s: string, i: number) => (
                                        <code key={i} className="text-xs bg-red-900/30 text-red-400 px-2 py-0.5 rounded border border-red-700/50 max-w-[200px] truncate">
                                          {s}
                                        </code>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                          
                          {/* Hash info */}
                          {(att.sha256 || att.md5) && (
                            <div className="bg-gray-800 rounded p-3">
                              <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">File Hashes</h4>
                              <div className="space-y-1">
                                {att.sha256 && (
                                  <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500">SHA256:</span>
                                    <div className="flex items-center">
                                      <code className="font-mono text-gray-400">{att.sha256}</code>
                                      <button
                                        onClick={() => copyToClipboard(att.sha256, `sha256-${idx}`)}
                                        className="ml-2 text-gray-500 hover:text-white"
                                      >
                                        <Copy className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                )}
                                {att.sha1 && (
                                  <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500">SHA1:</span>
                                    <div className="flex items-center">
                                      <code className="font-mono text-gray-400">{att.sha1}</code>
                                      <button
                                        onClick={() => copyToClipboard(att.sha1, `sha1-${idx}`)}
                                        className="ml-2 text-gray-500 hover:text-white"
                                      >
                                        <Copy className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                )}
                                {att.md5 && (
                                  <div className="flex items-center justify-between text-xs">
                                    <span className="text-gray-500">MD5:</span>
                                    <div className="flex items-center">
                                      <code className="font-mono text-gray-400">{att.md5}</code>
                                      <button
                                        onClick={() => copyToClipboard(att.md5, `md5-${idx}`)}
                                        className="ml-2 text-gray-500 hover:text-white"
                                      >
                                        <Copy className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>
                              
                              {/* VirusTotal Link */}
                              {att.sha256 && (
                                <a
                                  href={`https://www.virustotal.com/gui/file/${att.sha256}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 mt-2 text-xs text-blue-400 hover:text-blue-300"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                  Check on VirusTotal
                                </a>
                              )}
                            </div>
                          )}
                          
                          {/* Threat names from VirusTotal */}
                          {enriched?.virustotal_threat_names?.length > 0 && (
                            <div className="bg-gray-800 rounded p-3">
                              <h4 className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wide">VirusTotal Detections</h4>
                              <div className="flex flex-wrap gap-1">
                                {enriched.virustotal_threat_names.slice(0, 10).map((name: string, i: number) => (
                                  <span key={i} className="text-xs px-2 py-0.5 bg-red-900/50 text-red-400 rounded border border-red-700">
                                    {name}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* External Lookup Links */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <ExternalLink className="w-5 h-5 mr-2 text-cyan-400" />
                External Lookup Resources
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {result.email?.sender?.domain && (
                  <>
                    <a
                      href={`https://www.virustotal.com/gui/domain/${result.email.sender.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-3 py-2 bg-gray-900 hover:bg-gray-700 rounded-lg border border-gray-700 text-sm text-gray-300 transition-colors"
                    >
                      <Globe className="w-4 h-4 text-blue-400" />
                      VirusTotal
                    </a>
                    <a
                      href={`https://urlhaus.abuse.ch/browse.php?search=${result.email.sender.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-3 py-2 bg-gray-900 hover:bg-gray-700 rounded-lg border border-gray-700 text-sm text-gray-300 transition-colors"
                    >
                      <Database className="w-4 h-4 text-purple-400" />
                      URLhaus
                    </a>
                    <a
                      href={`https://www.whois.com/whois/${result.email.sender.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-3 py-2 bg-gray-900 hover:bg-gray-700 rounded-lg border border-gray-700 text-sm text-gray-300 transition-colors"
                    >
                      <Search className="w-4 h-4 text-green-400" />
                      WHOIS
                    </a>
                    <a
                      href={`https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${result.email.sender.domain}&run=toolpage`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-3 py-2 bg-gray-900 hover:bg-gray-700 rounded-lg border border-gray-700 text-sm text-gray-300 transition-colors"
                    >
                      <Mail className="w-4 h-4 text-orange-400" />
                      MX Lookup
                    </a>
                  </>
                )}
              </div>
            </div>

            {/* No Data State */}
            {!result.email?.urls?.length && !result.email?.attachments?.length && !senderDomain && !tiResults && (
              <div className="bg-gray-800 rounded-lg p-8 border border-gray-700 text-center">
                <Database className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                <h3 className="text-xl font-semibold text-gray-400 mb-2">Limited Threat Intel Data</h3>
                <p className="text-gray-500 max-w-md mx-auto">
                  This email has no URLs or attachments to analyze. Configure API keys in Settings 
                  to enable automatic threat intelligence enrichment for sender domains.
                </p>
              </div>
            )}
          </div>
        )}

        {/* IOCs Tab */}
        {activeTab === 'iocs' && (
          <div className="space-y-6">
            {/* Domains */}
            {result.iocs?.domains?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Globe className="w-5 h-5 mr-2 text-blue-400" />
                  Domains ({result.iocs.domains.length})
                </h2>
                <div className="space-y-2">
                  {result.iocs.domains.map((domain: string, idx: number) => (
                    <div key={idx} className="flex items-center justify-between bg-gray-900 rounded p-2">
                      <span className="font-mono text-sm text-yellow-400">{defang(domain)}</span>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => copyToClipboard(domain, `domain-${idx}`)}
                          className="p-1 text-gray-400 hover:text-white"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        {getOsintLinks('domain', domain).slice(0, 2).map(link => (
                          <a
                            key={link.name}
                            href={link.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded"
                          >
                            {link.name}
                          </a>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* URLs */}
            {result.iocs?.urls?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <LinkIcon className="w-5 h-5 mr-2 text-purple-400" />
                  URLs ({result.iocs.urls.length})
                </h2>
                <div className="space-y-2">
                  {result.iocs.urls.map((url: string, idx: number) => (
                    <div key={idx} className="bg-gray-900 rounded p-2">
                      <div className="flex items-start justify-between">
                        <span className="font-mono text-sm text-yellow-400 break-all">{defang(url)}</span>
                        <button
                          onClick={() => copyToClipboard(url, `ioc-url-${idx}`)}
                          className="p-1 text-gray-400 hover:text-white flex-shrink-0 ml-2"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* IPs */}
            {result.iocs?.ips?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Server className="w-5 h-5 mr-2 text-green-400" />
                  IP Addresses ({result.iocs.ips.length})
                </h2>
                <div className="space-y-2">
                  {result.iocs.ips.map((ip: string, idx: number) => (
                    <div key={idx} className="flex items-center justify-between bg-gray-900 rounded p-2">
                      <span className="font-mono text-sm">{defang(ip)}</span>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => copyToClipboard(ip, `ip-${idx}`)}
                          className="p-1 text-gray-400 hover:text-white"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        {getOsintLinks('ip', ip).slice(0, 2).map(link => (
                          <a
                            key={link.name}
                            href={link.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded"
                          >
                            {link.name}
                          </a>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* File Hashes */}
            {result.iocs?.file_hashes_sha256?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Hash className="w-5 h-5 mr-2 text-orange-400" />
                  File Hashes ({result.iocs.file_hashes_sha256.length})
                </h2>
                <div className="space-y-2">
                  {result.iocs.file_hashes_sha256.map((hash: string, idx: number) => (
                    <div key={idx} className="flex items-center justify-between bg-gray-900 rounded p-2">
                      <span className="font-mono text-xs text-gray-300">{hash}</span>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => copyToClipboard(hash, `hash-ioc-${idx}`)}
                          className="p-1 text-gray-400 hover:text-white"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        {getOsintLinks('hash', hash).slice(0, 2).map(link => (
                          <a
                            key={link.name}
                            href={link.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded"
                          >
                            {link.name}
                          </a>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Email Addresses */}
            {result.iocs?.email_addresses?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Mail className="w-5 h-5 mr-2 text-cyan-400" />
                  Email Addresses ({result.iocs.email_addresses.length})
                </h2>
                <div className="space-y-2">
                  {result.iocs.email_addresses.map((email: string, idx: number) => (
                    <div key={idx} className="flex items-center justify-between bg-gray-900 rounded p-2">
                      <span className="font-mono text-sm">{defang(email)}</span>
                      <button
                        onClick={() => copyToClipboard(email, `email-${idx}`)}
                        className="p-1 text-gray-400 hover:text-white"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Detection Rules Tab */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Shield className="w-5 h-5 mr-2 text-red-400" />
                Triggered Detection Rules ({result.detection?.rules_triggered?.length || 0})
              </h2>
              
              {result.detection?.rules_triggered?.length > 0 ? (
                <div className="space-y-2">
                  {result.detection.rules_triggered.map((rule: any, idx: number) => (
                    <div key={idx} className={`rounded p-3 border ${
                      rule.severity === 'critical' ? 'bg-red-900/20 border-red-700' :
                      rule.severity === 'high' ? 'bg-orange-900/20 border-orange-700' :
                      rule.severity === 'medium' ? 'bg-yellow-900/20 border-yellow-700' :
                      'bg-blue-900/20 border-blue-700'
                    }`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <span className={`px-2 py-0.5 text-xs font-bold uppercase rounded ${
                            rule.severity === 'critical' ? 'bg-red-600 text-white' :
                            rule.severity === 'high' ? 'bg-orange-600 text-white' :
                            rule.severity === 'medium' ? 'bg-yellow-600 text-black' :
                            'bg-blue-600 text-white'
                          }`}>
                            {rule.severity}
                          </span>
                          <span className="font-medium">{rule.rule_name || rule.name}</span>
                        </div>
                        <span className="text-sm text-gray-400">{rule.category}</span>
                      </div>
                      {rule.description && (
                        <p className="text-sm text-gray-400 mt-2">{rule.description}</p>
                      )}
                      {rule.evidence && (
                        <p className="text-xs font-mono text-gray-500 mt-1 bg-gray-900 p-2 rounded">
                          Evidence: {rule.evidence}
                        </p>
                      )}
                      {rule.mitre_technique && (
                        <div className="flex items-center mt-2 space-x-2">
                          <Target className="w-4 h-4 text-purple-400" />
                          <a
                            href={`https://attack.mitre.org/techniques/${rule.mitre_technique.includes('.') ? rule.mitre_technique.replace('.', '/') : rule.mitre_technique}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs px-2 py-0.5 bg-purple-900/50 text-purple-400 rounded hover:bg-purple-900 flex items-center gap-1"
                          >
                            {rule.mitre_technique}
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <ShieldCheck className="w-12 h-12 mx-auto mb-4 text-green-500" />
                  <p className="text-green-400 font-medium">No Detection Rules Triggered</p>
                  <p className="text-gray-500 text-sm">This email did not match any of the 51 detection rules</p>
                </div>
              )}
            </div>

            {/* MITRE ATT&CK Mapping */}
            {result.ai_triage?.mitre_techniques?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Target className="w-5 h-5 mr-2 text-purple-400" />
                  MITRE ATT&CK Techniques
                </h2>
                <div className="grid grid-cols-2 gap-3">
                  {result.ai_triage.mitre_techniques.map((tech: any, idx: number) => {
                    // Handle both string format and object format
                    const techniqueId = typeof tech === 'string' ? tech : tech.technique_id;
                    const name = typeof tech === 'string' ? null : tech.name;
                    const tactic = typeof tech === 'string' ? null : tech.tactic;
                    
                    // Build MITRE URL with proper sub-technique handling
                    const mitreUrl = techniqueId 
                      ? `https://attack.mitre.org/techniques/${techniqueId.includes('.') ? techniqueId.replace('.', '/') : techniqueId}/`
                      : '#';
                    
                    return (
                      <a
                        key={idx}
                        href={mitreUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="bg-gray-900 rounded p-3 border border-gray-700 hover:border-purple-500 transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-purple-400 font-mono text-sm">{techniqueId || 'Unknown'}</span>
                          <ExternalLink className="w-4 h-4 text-gray-500" />
                        </div>
                        {name && <p className="text-white font-medium">{name}</p>}
                        {tactic && <p className="text-sm text-gray-400">{tactic}</p>}
                      </a>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* AI Analysis Tab */}
        {activeTab === 'ai' && (
          <div className="space-y-6">
            {result.ai_triage ? (
              <>
                {/* AI Summary */}
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <h2 className="text-lg font-semibold mb-4 flex items-center">
                    <Brain className="w-5 h-5 mr-2 text-cyan-400" />
                    AI Threat Assessment
                    {result.ai_triage.model_used && (
                      <span className="ml-2 text-xs bg-gray-700 px-2 py-0.5 rounded text-gray-400">
                        {result.ai_triage.model_used}
                      </span>
                    )}
                  </h2>
                  <div className="bg-gray-900 rounded p-4">
                    <p className="text-gray-300 leading-relaxed">{result.ai_triage.summary}</p>
                  </div>
                </div>

                {/* Detailed Analysis - NEW */}
                {result.ai_triage.detailed_analysis && (
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h2 className="text-lg font-semibold mb-4 flex items-center">
                      <FileText className="w-5 h-5 mr-2 text-blue-400" />
                      Analysis Description
                    </h2>
                    <div className="bg-gray-900 rounded p-4">
                      <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{result.ai_triage.detailed_analysis}</p>
                    </div>
                  </div>
                )}

                {/* Key Findings */}
                {result.ai_triage.key_findings?.length > 0 && (
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h2 className="text-lg font-semibold mb-4 flex items-center">
                      <AlertCircle className="w-5 h-5 mr-2 text-yellow-400" />
                      Key Findings
                    </h2>
                    <ul className="space-y-2">
                      {result.ai_triage.key_findings.map((finding: string, idx: number) => (
                        <li key={idx} className="flex items-start bg-gray-900 rounded p-3">
                          <AlertTriangle className="w-5 h-5 mr-3 text-yellow-400 flex-shrink-0 mt-0.5" />
                          <span className="text-gray-300">{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Recommended Actions */}
                {result.ai_triage.recommended_actions?.length > 0 && (
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h2 className="text-lg font-semibold mb-4 flex items-center">
                      <Zap className="w-5 h-5 mr-2 text-green-400" />
                      Recommended Actions
                    </h2>
                    <div className="space-y-3">
                      {result.ai_triage.recommended_actions.map((action: any, idx: number) => (
                        <div key={idx} className="bg-gray-900 rounded p-3 border-l-4 border-green-500">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold text-green-400">{action.action}</span>
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              action.priority === 'high' ? 'bg-red-900/50 text-red-400' :
                              action.priority === 'medium' ? 'bg-yellow-900/50 text-yellow-400' :
                              'bg-blue-900/50 text-blue-400'
                            }`}>
                              {action.priority} priority
                            </span>
                          </div>
                          <p className="text-sm text-gray-400">{action.details}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 text-center">
                <Brain className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                <h3 className="text-lg font-semibold text-gray-400 mb-2">AI Analysis Not Available</h3>
                <p className="text-gray-500">
                  Configure an AI provider (OpenAI or Anthropic) in Settings to enable AI-powered threat analysis.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Sandbox Analysis Tab */}
        {activeTab === 'sandbox' && (
          <div className="space-y-6">
            <SandboxResultsPanel sandboxAnalysis={result.sandbox_analysis} />
          </div>
        )}

        {/* Enhanced Analysis Tab */}
        {activeTab === 'enhanced' && (
          <div className="space-y-6">
            {/* Social Engineering Analysis */}
            {result.se_analysis && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Brain className="w-5 h-5 mr-2 text-purple-400" />
                  Social Engineering Analysis
                  <span className={`ml-2 px-2 py-0.5 text-xs rounded font-bold ${
                    result.se_analysis.se_level === 'critical' ? 'bg-red-600' :
                    result.se_analysis.se_level === 'high' ? 'bg-orange-600' :
                    result.se_analysis.se_level === 'medium' ? 'bg-yellow-600 text-black' :
                    'bg-green-600'
                  }`}>
                    {result.se_analysis.se_score}/100
                  </span>
                </h2>
                
                {/* SE Score Breakdown */}
                <div className="grid grid-cols-5 gap-2 mb-4">
                  {Object.entries(result.se_analysis.heuristic_breakdown || {}).map(([key, value]: [string, any]) => (
                    <div key={key} className="bg-gray-900 rounded p-2 text-center">
                      <div className="text-xs text-gray-400 uppercase">{key}</div>
                      <div className={`text-lg font-bold ${
                        value > 70 ? 'text-red-400' :
                        value > 40 ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>{value}</div>
                    </div>
                  ))}
                </div>

                {/* Techniques Detected */}
                {result.se_analysis.techniques?.length > 0 && (
                  <div className="mb-4">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Techniques Detected</h3>
                    <div className="flex flex-wrap gap-2">
                      {result.se_analysis.techniques.map((tech: string, idx: number) => (
                        <span key={idx} className="px-2 py-1 bg-purple-900/50 text-purple-400 text-xs rounded">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Key Indicators */}
                {result.se_analysis.key_indicators?.length > 0 && (
                  <div className="mb-4">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Key Indicators</h3>
                    <ul className="space-y-1">
                      {result.se_analysis.key_indicators.map((indicator: string, idx: number) => (
                        <li key={idx} className="flex items-start text-sm">
                          <AlertTriangle className="w-4 h-4 mr-2 text-yellow-400 flex-shrink-0 mt-0.5" />
                          <span className="text-gray-300">{indicator}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Explanation */}
                {result.se_analysis.explanation && (
                  <div className="bg-gray-900 rounded p-3">
                    <p className="text-sm text-gray-300">{result.se_analysis.explanation}</p>
                  </div>
                )}
              </div>
            )}

            {/* Content Deconstruction */}
            {result.content_analysis && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <FileText className="w-5 h-5 mr-2 text-blue-400" />
                  Content Deconstruction
                  <span className="ml-2 px-2 py-0.5 text-xs bg-blue-900/50 text-blue-400 rounded">
                    {result.content_analysis.intent?.replace(/_/g, ' ')}
                  </span>
                </h2>

                <div className="grid grid-cols-2 gap-4 mb-4">
                  {/* Requested Actions */}
                  {result.content_analysis.requested_actions?.length > 0 && (
                    <div className="bg-gray-900 rounded p-3">
                      <h3 className="text-sm font-semibold text-gray-400 mb-2">Requested Actions</h3>
                      <div className="flex flex-wrap gap-1">
                        {result.content_analysis.requested_actions.map((action: string, idx: number) => (
                          <span key={idx} className="px-2 py-0.5 bg-orange-900/50 text-orange-400 text-xs rounded">
                            {action.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Target Data */}
                  {result.content_analysis.target_data?.length > 0 && (
                    <div className="bg-gray-900 rounded p-3">
                      <h3 className="text-sm font-semibold text-gray-400 mb-2">Target Data</h3>
                      <div className="flex flex-wrap gap-1">
                        {result.content_analysis.target_data.map((data: string, idx: number) => (
                          <span key={idx} className="px-2 py-0.5 bg-red-900/50 text-red-400 text-xs rounded">
                            {data.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Business Process Abused */}
                {result.content_analysis.business_process_abused && result.content_analysis.business_process_abused !== 'none' && (
                  <div className="bg-gray-900 rounded p-3 mb-4">
                    <h3 className="text-sm font-semibold text-gray-400 mb-1">Business Process Abused</h3>
                    <span className="text-yellow-400">{result.content_analysis.business_process_abused.replace(/_/g, ' ')}</span>
                  </div>
                )}

                {/* Spoofed Brand */}
                {result.content_analysis.spoofed_brand && (
                  <div className="bg-red-900/20 border border-red-700 rounded p-3 mb-4">
                    <h3 className="text-sm font-semibold text-red-400 mb-1">Spoofed Brand Detected</h3>
                    <span className="text-white font-medium">{result.content_analysis.spoofed_brand}</span>
                    {result.content_analysis.spoofed_entity_type && (
                      <span className="ml-2 text-xs text-gray-400">({result.content_analysis.spoofed_entity_type})</span>
                    )}
                  </div>
                )}

                {/* Potential Impact */}
                {result.content_analysis.potential_impact?.length > 0 && (
                  <div className="bg-gray-900 rounded p-3">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Potential Impact</h3>
                    <div className="flex flex-wrap gap-1">
                      {result.content_analysis.potential_impact.map((impact: string, idx: number) => (
                        <span key={idx} className="px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded">
                          {impact.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Lookalike Domain Detection */}
            {result.lookalike_analysis && result.lookalike_analysis.has_lookalikes && (
              <div className="bg-gray-800 rounded-lg p-4 border border-red-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Globe className="w-5 h-5 mr-2 text-red-400" />
                  Lookalike Domain Detection
                  <span className="ml-2 px-2 py-0.5 text-xs bg-red-600 text-white rounded font-bold">
                    {result.lookalike_analysis.matches?.length || 0} found
                  </span>
                </h2>

                <div className="space-y-3">
                  {result.lookalike_analysis.matches?.map((match: any, idx: number) => (
                    <div key={idx} className="bg-red-900/20 border border-red-700 rounded p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-red-400">{match.suspicious_domain}</span>
                        <span className={`px-2 py-0.5 text-xs rounded ${
                          match.confidence > 0.8 ? 'bg-red-600' :
                          match.confidence > 0.5 ? 'bg-orange-600' :
                          'bg-yellow-600 text-black'
                        }`}>
                          {Math.round(match.confidence * 100)}% confidence
                        </span>
                      </div>
                      
                      {/* AI-generated description */}
                      {match.description && (
                        <p className="text-sm text-gray-300 mb-3 leading-relaxed">
                          {match.description}
                        </p>
                      )}
                      
                      <div className="text-sm text-gray-400">
                        <span className="mr-4">Impersonating: <span className="text-white font-medium capitalize">{match.target_brand}</span></span>
                        <span className="mr-4">Real domain: <span className="text-green-400">{match.legitimate_domain}</span></span>
                      </div>
                      {match.detection_methods?.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {match.detection_methods.map((method: string, mIdx: number) => {
                            // Make method names human readable
                            const readableMethod = method
                              .replace(/_/g, ' ')
                              .replace(/edit distance (\d+)/i, 'Edit distance: $1')
                              .replace(/^(\w)/, (c) => c.toUpperCase());
                            return (
                              <span key={mIdx} className="px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded">
                                {readableMethod}
                              </span>
                            );
                          })}
                        </div>
                      )}
                      {match.homoglyphs_found?.length > 0 && (
                        <div className="mt-2 text-xs text-gray-500">
                          Homoglyphs: {match.homoglyphs_found.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TI Fusion Results */}
            {result.ti_results && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <Database className="w-5 h-5 mr-2 text-cyan-400" />
                  Threat Intelligence Fusion
                  <span className={`ml-2 px-2 py-0.5 text-xs rounded font-bold ${
                    result.ti_results.fused_verdict === 'malicious' ? 'bg-red-600' :
                    result.ti_results.fused_verdict === 'suspicious' ? 'bg-orange-600' :
                    'bg-green-600'
                  }`}>
                    {result.ti_results.fused_score}/100
                  </span>
                </h2>

                {/* API Status */}
                {result.ti_results.api_status && Object.keys(result.ti_results.api_status).length > 0 && (
                  <div className="grid grid-cols-3 gap-2 mb-4">
                    {Object.entries(result.ti_results.api_status).map(([source, status]: [string, any]) => (
                      <div key={source} className="bg-gray-900 rounded p-2 flex items-center justify-between">
                        <span className="text-sm text-gray-400">{source}</span>
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          status.toLowerCase().includes('ok') ? 'bg-green-900/50 text-green-400' :
                          status.toLowerCase().includes('limit') ? 'bg-yellow-900/50 text-yellow-400' :
                          'bg-red-900/50 text-red-400'
                        }`}>
                          {status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Findings */}
                {result.ti_results.findings?.length > 0 && (
                  <div className="bg-gray-900 rounded p-3">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Findings</h3>
                    <ul className="space-y-1">
                      {result.ti_results.findings.map((finding: string, idx: number) => (
                        <li key={idx} className="flex items-start text-sm">
                          <Info className="w-4 h-4 mr-2 text-cyan-400 flex-shrink-0 mt-0.5" />
                          <span className="text-gray-300">{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Multi-Dimensional Risk Score */}
            {result.risk_score && result.risk_score.dimensions && (
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center">
                  <TrendingUp className="w-5 h-5 mr-2 text-green-400" />
                  Multi-Dimensional Risk Score
                  <span className={`ml-2 px-2 py-0.5 text-xs rounded font-bold ${
                    result.risk_score.overall_level === 'critical' ? 'bg-red-600' :
                    result.risk_score.overall_level === 'high' ? 'bg-orange-600' :
                    result.risk_score.overall_level === 'medium' ? 'bg-yellow-600 text-black' :
                    'bg-green-600'
                  }`}>
                    {result.risk_score.overall_score}/100
                  </span>
                </h2>

                {/* Dimension Bars */}
                <div className="space-y-3 mb-4">
                  {Object.entries(result.risk_score.dimensions).map(([dim, data]: [string, any]) => (
                    <div key={dim} className="bg-gray-900 rounded p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-gray-300">{dim.replace(/_/g, ' ')}</span>
                        <span className={`text-sm font-bold ${
                          data.level === 'critical' ? 'text-red-400' :
                          data.level === 'high' ? 'text-orange-400' :
                          data.level === 'medium' ? 'text-yellow-400' :
                          'text-green-400'
                        }`}>{data.score}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            data.level === 'critical' ? 'bg-red-500' :
                            data.level === 'high' ? 'bg-orange-500' :
                            data.level === 'medium' ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`}
                          style={{ width: `${data.score}%` }}
                        />
                      </div>
                      {data.indicators?.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {data.indicators.slice(0, 3).map((ind: string, idx: number) => (
                            <span key={idx} className="text-xs text-gray-500">{ind}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                {/* Top Indicators */}
                {result.risk_score.top_indicators?.length > 0 && (
                  <div className="bg-gray-900 rounded p-3">
                    <h3 className="text-sm font-semibold text-gray-400 mb-2">Top Indicators</h3>
                    <ol className="space-y-1">
                      {result.risk_score.top_indicators.slice(0, 5).map((indicator: string, idx: number) => (
                        <li key={idx} className="flex items-start text-sm">
                          <span className="text-yellow-400 font-bold mr-2">{idx + 1}.</span>
                          <span className="text-gray-300">{indicator}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            )}

            {/* No Enhanced Data Message */}
            {!result.se_analysis && !result.content_analysis && !result.lookalike_analysis && !result.ti_results && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 text-center">
                <Zap className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                <h3 className="text-lg font-semibold text-gray-400 mb-2">Enhanced Analysis Not Available</h3>
                <p className="text-gray-500">
                  Run analysis with Enhanced mode enabled to see social engineering scoring, content deconstruction, and lookalike domain detection.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
  } catch (err) {
    console.error('AdvancedAnalysisView render error:', err);
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-8">
        <div className="bg-red-900/50 border border-red-500 rounded-lg p-6 max-w-2xl">
          <h2 className="text-xl font-bold text-red-400 mb-2">Error Rendering Analysis View</h2>
          <p className="text-gray-300 mb-4">An error occurred while rendering the analysis:</p>
          <pre className="bg-black/50 p-4 rounded text-sm text-red-300 overflow-auto max-h-40">
            {String(err)}
          </pre>
          <button
            onClick={onBack}
            className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }
};

export default AdvancedAnalysisView;
