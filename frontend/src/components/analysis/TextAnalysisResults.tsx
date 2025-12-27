/**
 * SMS/URL Analysis Results Panel
 * 
 * Dedicated component for displaying SMS smishing and URL phishing analysis results.
 * Designed specifically for text/URL analysis, not email.
 */

import React from 'react';
import {
  Shield, AlertTriangle, CheckCircle, XCircle,
  Link, Phone, Globe, Target, Brain, 
  ExternalLink, Copy, ChevronDown, ChevronUp,
  MessageSquare, Smartphone, AlertCircle, Info
} from 'lucide-react';

interface ScamPattern {
  pattern_id: string;
  name: string;
  description: string;
  severity: string;
  matched_text?: string;
  mitre_technique?: string;
}

interface URLEnrichment {
  url: string;
  domain: string;
  is_malicious: boolean;
  threat_score: number;
  sources: string[];
  categories: string[];
}

interface URLSandbox {
  url: string;
  provider: string;
  status: string;
  is_malicious: boolean;
  threat_score: number;
  threat_level: string;
  categories: string[];
  indicators: string[];
  contacted_ips: string[];
  contacted_domains: string[];
  redirects: string[];
  final_url?: string;
  page_title?: string;
  screenshot_url?: string;
  report_url?: string;
  analysis_time_ms: number;
}

interface AIAnalysis {
  enabled: boolean;
  provider?: string;
  summary: string;
  threat_assessment?: string;
  key_findings: string[];
  social_engineering_tactics: string[];
  recommendations: string[];
  confidence: number;
}

interface MITRETechnique {
  id: string;
  name: string;
  tactic: string;
}

interface TextAnalysisResult {
  analysis_id: string;
  analyzed_at: string;
  analysis_type: string;
  source: string;
  original_text: string;
  message_length: number;
  overall_score: number;
  overall_level: string;
  classification: string;
  is_threat: boolean;
  confidence: number;
  urls_found: string[];
  domains_found: string[];
  ips_found: string[];
  phone_numbers_found: string[];
  url_enrichment: URLEnrichment[];
  url_sandbox: URLSandbox[];
  patterns_matched: ScamPattern[];
  threat_indicators: string[];
  ai_analysis: AIAnalysis;
  recommendations: string[];
  mitre_techniques: MITRETechnique[];
}

interface Props {
  result: TextAnalysisResult;
  onClose?: () => void;
}

const getRiskColor = (level: string | undefined | null) => {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'text-red-400 bg-red-500/20 border-red-500';
    case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500';
    case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500';
    case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500';
    default: return 'text-green-400 bg-green-500/20 border-green-500';
  }
};

const getSeverityColor = (severity: string | undefined | null) => {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    default: return 'bg-blue-500';
  }
};

const getSourceIcon = (source: string | undefined | null) => {
  switch ((source || '').toLowerCase()) {
    case 'sms': return <Smartphone className="w-5 h-5" />;
    case 'url': return <Link className="w-5 h-5" />;
    case 'whatsapp': return <MessageSquare className="w-5 h-5" />;
    case 'telegram': return <MessageSquare className="w-5 h-5" />;
    default: return <MessageSquare className="w-5 h-5" />;
  }
};

const TextAnalysisResults: React.FC<Props> = ({ result, onClose }) => {
  const [expandedSections, setExpandedSections] = React.useState<Record<string, boolean>>({
    indicators: true,
    patterns: true,
    ai: true,
    urls: true,
    recommendations: true,
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const isUrlMode = result.source === 'url';

  return (
    <div className="space-y-4 md:space-y-6">
      {/* Header with Risk Score */}
      <div className={`p-4 md:p-6 rounded-xl border-2 ${getRiskColor(result.overall_level)}`}>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 md:gap-4">
            <div className={`w-12 h-12 md:w-16 md:h-16 rounded-xl flex items-center justify-center ${
              result.is_threat ? 'bg-red-500/30' : 'bg-green-500/30'
            }`}>
              {result.is_threat ? (
                <AlertTriangle className="w-6 h-6 md:w-8 md:h-8 text-red-400" />
              ) : (
                <CheckCircle className="w-6 h-6 md:w-8 md:h-8 text-green-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                {getSourceIcon(result.source)}
                <h2 className="text-lg md:text-xl font-bold">
                  {isUrlMode ? 'URL Analysis' : `${result.source.toUpperCase()} Analysis`}
                </h2>
              </div>
              <p className="text-xs md:text-sm text-slate-400 mt-1">
                {result.classification.replace(/_/g, ' ').toUpperCase()}
              </p>
            </div>
          </div>
          
          {/* Risk Score Circle */}
          <div className="text-center self-end sm:self-auto">
            <div className={`w-16 h-16 md:w-20 md:h-20 rounded-full border-4 flex items-center justify-center ${
              result.overall_score >= 70 ? 'border-red-500' :
              result.overall_score >= 40 ? 'border-orange-500' :
              result.overall_score >= 20 ? 'border-yellow-500' : 'border-green-500'
            }`}>
              <span className="text-xl md:text-2xl font-bold">{result.overall_score}</span>
            </div>
            <p className="text-[10px] md:text-xs text-slate-400 mt-1">Risk Score</p>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-4 gap-2 md:gap-4 mt-4 md:mt-6">
          <div className="bg-slate-800/50 rounded-lg p-2 md:p-3 text-center">
            <p className="text-lg md:text-2xl font-bold text-blue-400">{result.urls_found.length}</p>
            <p className="text-[10px] md:text-xs text-slate-400">URLs</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-2 md:p-3 text-center">
            <p className="text-lg md:text-2xl font-bold text-purple-400">{result.patterns_matched.length}</p>
            <p className="text-[10px] md:text-xs text-slate-400">Patterns</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-2 md:p-3 text-center">
            <p className="text-lg md:text-2xl font-bold text-orange-400">{result.phone_numbers_found.length}</p>
            <p className="text-[10px] md:text-xs text-slate-400">Phones</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-2 md:p-3 text-center">
            <p className="text-lg md:text-2xl font-bold text-green-400">{Math.round(result.confidence * 100)}%</p>
            <p className="text-[10px] md:text-xs text-slate-400">Confidence</p>
          </div>
        </div>
      </div>

      {/* Original Content */}
      <div className="bg-slate-800 rounded-xl p-3 md:p-4 border border-slate-700">
        <h3 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
          <MessageSquare className="w-4 h-4" />
          Original Content
        </h3>
        <div className="bg-slate-900 rounded-lg p-3 md:p-4 font-mono text-xs md:text-sm text-slate-300 whitespace-pre-wrap break-all max-h-32 md:max-h-40 overflow-y-auto">
          {result.original_text}
        </div>
        <div className="flex items-center justify-between mt-2 text-[10px] md:text-xs text-slate-500">
          <span>{result.message_length} characters</span>
          <button
            onClick={() => copyToClipboard(result.original_text)}
            className="flex items-center gap-1 hover:text-slate-300"
          >
            <Copy className="w-3 h-3" /> Copy
          </button>
        </div>
      </div>

      {/* AI Analysis */}
      {result.ai_analysis.enabled && (
        <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
          <button
            onClick={() => toggleSection('ai')}
            className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50"
          >
            <div className="flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              <h3 className="font-semibold">AI Analysis</h3>
              {result.ai_analysis.provider && (
                <span className="text-xs bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded">
                  {result.ai_analysis.provider}
                </span>
              )}
            </div>
            {expandedSections.ai ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          
          {expandedSections.ai && (
            <div className="p-4 pt-0 space-y-4">
              {/* Summary */}
              <div className="bg-slate-900 rounded-lg p-4">
                <p className="text-slate-300">{result.ai_analysis.summary}</p>
              </div>

              {/* Threat Assessment */}
              {result.ai_analysis.threat_assessment && (
                <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full ${
                  result.ai_analysis.threat_assessment === 'MALICIOUS' ? 'bg-red-500/20 text-red-300' :
                  result.ai_analysis.threat_assessment === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-300' :
                  'bg-green-500/20 text-green-300'
                }`}>
                  <Shield className="w-4 h-4" />
                  {result.ai_analysis.threat_assessment}
                </div>
              )}

              {/* Key Findings */}
              {result.ai_analysis.key_findings.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-2">Key Findings</h4>
                  <ul className="space-y-1">
                    {result.ai_analysis.key_findings.map((finding, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                        {finding}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Social Engineering Tactics */}
              {result.ai_analysis.social_engineering_tactics.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-2">Social Engineering Tactics</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.ai_analysis.social_engineering_tactics.map((tactic, i) => (
                      <span key={i} className="px-2 py-1 bg-orange-500/20 text-orange-300 rounded text-xs">
                        {tactic}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Threat Indicators */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <button
          onClick={() => toggleSection('indicators')}
          className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <h3 className="font-semibold">Threat Indicators</h3>
            <span className="text-xs bg-slate-700 px-2 py-0.5 rounded">
              {result.threat_indicators.length}
            </span>
          </div>
          {expandedSections.indicators ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        
        {expandedSections.indicators && (
          <div className="p-4 pt-0">
            <ul className="space-y-2">
              {result.threat_indicators.map((indicator, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-300 bg-slate-900 rounded-lg p-2">
                  {indicator}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Detected Patterns */}
      {result.patterns_matched.length > 0 && (
        <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
          <button
            onClick={() => toggleSection('patterns')}
            className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50"
          >
            <div className="flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" />
              <h3 className="font-semibold">Detected Patterns</h3>
              <span className="text-xs bg-red-500/20 text-red-300 px-2 py-0.5 rounded">
                {result.patterns_matched.length}
              </span>
            </div>
            {expandedSections.patterns ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          
          {expandedSections.patterns && (
            <div className="p-4 pt-0 space-y-3">
              {result.patterns_matched.map((pattern, i) => (
                <div key={i} className="bg-slate-900 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`w-2 h-2 rounded-full ${getSeverityColor(pattern.severity)}`} />
                    <span className="font-medium text-slate-200">{pattern.name}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded ${
                      pattern.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                      pattern.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                      'bg-yellow-500/20 text-yellow-300'
                    }`}>
                      {pattern.severity}
                    </span>
                    {pattern.mitre_technique && (
                      <span className="text-xs bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded">
                        {pattern.mitre_technique}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-slate-400">{pattern.description}</p>
                  {pattern.matched_text && (
                    <p className="text-xs text-slate-500 mt-1 font-mono bg-slate-800 p-1 rounded">
                      Matched: "{pattern.matched_text}"
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* URLs & Enrichment */}
      {result.urls_found.length > 0 && (
        <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
          <button
            onClick={() => toggleSection('urls')}
            className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50"
          >
            <div className="flex items-center gap-2">
              <Link className="w-5 h-5 text-blue-400" />
              <h3 className="font-semibold">URLs & Threat Intel</h3>
              <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">
                {result.urls_found.length}
              </span>
            </div>
            {expandedSections.urls ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          
          {expandedSections.urls && (
            <div className="p-4 pt-0 space-y-3">
              {result.url_enrichment.length > 0 ? (
                result.url_enrichment.map((enrichment, i) => (
                  <div key={i} className={`rounded-lg p-3 border ${
                    enrichment.is_malicious ? 'bg-red-500/10 border-red-500/50' : 'bg-slate-900 border-slate-700'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        {enrichment.is_malicious ? (
                          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                        ) : (
                          <Globe className="w-4 h-4 text-slate-400 flex-shrink-0" />
                        )}
                        <span className="text-sm text-slate-300 truncate">{enrichment.url}</span>
                      </div>
                      <div className="flex items-center gap-2 ml-2">
                        {enrichment.threat_score > 0 && (
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            enrichment.threat_score >= 70 ? 'bg-red-500/20 text-red-300' :
                            enrichment.threat_score >= 40 ? 'bg-orange-500/20 text-orange-300' :
                            'bg-yellow-500/20 text-yellow-300'
                          }`}>
                            Score: {enrichment.threat_score}
                          </span>
                        )}
                        <a
                          href={`https://www.virustotal.com/gui/url/${btoa(enrichment.url)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      </div>
                    </div>
                    {enrichment.sources.length > 0 && (
                      <div className="flex items-center gap-1 mt-2">
                        <span className="text-xs text-slate-500">Sources:</span>
                        {enrichment.sources.map((src, j) => (
                          <span key={j} className="text-xs bg-slate-700 px-1.5 py-0.5 rounded">
                            {src}
                          </span>
                        ))}
                      </div>
                    )}
                    {enrichment.categories.length > 0 && (
                      <div className="flex items-center gap-1 mt-1">
                        <span className="text-xs text-slate-500">Categories:</span>
                        {enrichment.categories.map((cat, j) => (
                          <span key={j} className="text-xs bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded">
                            {cat}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                result.urls_found.map((url, i) => (
                  <div key={i} className="bg-slate-900 rounded-lg p-3 flex items-center justify-between">
                    <span className="text-sm text-slate-300 truncate">{url}</span>
                    <a
                      href={`https://www.virustotal.com/gui/url/${btoa(url)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 ml-2"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* URL Sandbox (Dynamic Analysis) */}
      {result.url_sandbox && result.url_sandbox.length > 0 && (
        <div className="bg-slate-800 rounded-xl border border-orange-600/50 overflow-hidden">
          <div className="p-4 bg-orange-500/10 border-b border-orange-600/30">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-orange-400" />
              <h3 className="font-semibold">URL Sandbox Analysis</h3>
              <span className="text-xs bg-orange-500/20 text-orange-300 px-2 py-0.5 rounded">
                Dynamic Analysis
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Real-time URL detonation and behavioral analysis</p>
          </div>
          
          <div className="p-4 space-y-4">
            {result.url_sandbox.map((sandbox, i) => (
              <div key={i} className={`rounded-lg p-4 border ${
                sandbox.is_malicious ? 'bg-red-500/10 border-red-500/50' : 'bg-slate-900 border-slate-700'
              }`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {sandbox.is_malicious ? (
                      <XCircle className="w-5 h-5 text-red-400" />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    )}
                    <span className="text-sm font-medium text-slate-200 truncate max-w-md">{sandbox.url}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      sandbox.threat_level === 'malicious' ? 'bg-red-500/20 text-red-300' :
                      sandbox.threat_level === 'suspicious' ? 'bg-orange-500/20 text-orange-300' :
                      sandbox.threat_level === 'low' ? 'bg-yellow-500/20 text-yellow-300' :
                      'bg-green-500/20 text-green-300'
                    }`}>
                      {sandbox.threat_level.toUpperCase()}
                    </span>
                    <span className="text-xs bg-slate-700 px-2 py-0.5 rounded">
                      Score: {sandbox.threat_score}
                    </span>
                    <span className="text-xs bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded">
                      {sandbox.provider}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm">
                  {/* Page Info */}
                  {sandbox.page_title && (
                    <div>
                      <span className="text-slate-500">Page Title:</span>
                      <span className="text-slate-300 ml-2">{sandbox.page_title}</span>
                    </div>
                  )}
                  {sandbox.final_url && sandbox.final_url !== sandbox.url && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Final URL:</span>
                      <span className="text-orange-300 ml-2 break-all">{sandbox.final_url}</span>
                    </div>
                  )}

                  {/* Network Behavior */}
                  {sandbox.contacted_domains.length > 0 && (
                    <div>
                      <span className="text-slate-500">Contacted Domains:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {sandbox.contacted_domains.slice(0, 5).map((domain, j) => (
                          <span key={j} className="text-xs bg-slate-700 px-1.5 py-0.5 rounded text-slate-300">
                            {domain}
                          </span>
                        ))}
                        {sandbox.contacted_domains.length > 5 && (
                          <span className="text-xs text-slate-500">+{sandbox.contacted_domains.length - 5} more</span>
                        )}
                      </div>
                    </div>
                  )}
                  {sandbox.contacted_ips.length > 0 && (
                    <div>
                      <span className="text-slate-500">Contacted IPs:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {sandbox.contacted_ips.slice(0, 5).map((ip, j) => (
                          <span key={j} className="text-xs bg-slate-700 px-1.5 py-0.5 rounded font-mono text-slate-300">
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Redirects */}
                  {sandbox.redirects.length > 0 && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Redirect Chain ({sandbox.redirects.length}):</span>
                      <div className="flex flex-wrap items-center gap-1 mt-1">
                        {sandbox.redirects.map((redirect, j) => (
                          <React.Fragment key={j}>
                            <span className="text-xs bg-slate-700 px-1.5 py-0.5 rounded text-slate-300 truncate max-w-[200px]">
                              {redirect}
                            </span>
                            {j < sandbox.redirects.length - 1 && <span className="text-slate-500">→</span>}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Indicators */}
                  {sandbox.indicators.length > 0 && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Behavioral Indicators:</span>
                      <ul className="mt-1 space-y-1">
                        {sandbox.indicators.slice(0, 5).map((indicator, j) => (
                          <li key={j} className="text-xs text-orange-300 flex items-start gap-1">
                            <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                            {indicator}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 mt-3 pt-3 border-t border-slate-700">
                  {sandbox.screenshot_url && (
                    <a
                      href={sandbox.screenshot_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs flex items-center gap-1 px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
                    >
                      📷 Screenshot
                    </a>
                  )}
                  {sandbox.report_url && (
                    <a
                      href={sandbox.report_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs flex items-center gap-1 px-2 py-1 bg-blue-500/20 hover:bg-blue-500/30 rounded text-blue-300"
                    >
                      <ExternalLink className="w-3 h-3" />
                      Full Report
                    </a>
                  )}
                  <span className="text-xs text-slate-500 ml-auto">
                    Analysis time: {sandbox.analysis_time_ms}ms
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK */}
      {result.mitre_techniques.length > 0 && (
        <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
          <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
            <Target className="w-4 h-4 text-purple-400" />
            MITRE ATT&CK Techniques
          </h3>
          <div className="flex flex-wrap gap-2">
            {result.mitre_techniques.map((technique, i) => (
              <a
                key={i}
                href={`https://attack.mitre.org/techniques/${technique.id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-3 py-1.5 bg-purple-500/20 text-purple-300 rounded-lg text-sm hover:bg-purple-500/30 transition"
              >
                <span className="font-mono">{technique.id}</span>
                <span className="text-slate-400">|</span>
                <span>{technique.name}</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <button
          onClick={() => toggleSection('recommendations')}
          className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50"
        >
          <div className="flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <h3 className="font-semibold">Recommendations</h3>
          </div>
          {expandedSections.recommendations ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
        
        {expandedSections.recommendations && (
          <div className="p-4 pt-0">
            <ul className="space-y-2">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="text-green-400 mt-0.5">→</span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Analysis Metadata */}
      <div className="text-xs text-slate-500 text-center">
        Analysis ID: {result.analysis_id} | Analyzed: {new Date(result.analyzed_at).toLocaleString()}
      </div>
    </div>
  );
};

export default TextAnalysisResults;
