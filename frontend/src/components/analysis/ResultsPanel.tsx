import React, { useState } from 'react';
import {
  Shield,
  Mail,
  Link,
  Paperclip,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Globe,
  Server,
  Key,
  Hash,
  Copy,
  Brain,
  Lightbulb,
  Target,
  Eye,
  FileText,
  Lock,
  Unlock,
  MinusCircle,
} from 'lucide-react';

interface ResultsPanelProps {
  result: any;
  onExport: (format: string) => void;
  onViewFullAnalysis: () => void;
}

const ResultsPanel: React.FC<ResultsPanelProps> = ({ result, onExport, onViewFullAnalysis }) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['ai', 'detection', 'auth'])
  );
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Early return if no result
  if (!result) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8 text-center">
        <Shield className="w-12 h-12 mx-auto mb-3 text-gray-600" />
        <div className="text-gray-400">No analysis result available</div>
      </div>
    );
  }

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Extract score from number or object
  const extractScore = (score: any): number => {
    if (typeof score === 'number') return score;
    if (score && typeof score === 'object' && 'overall_score' in score) return score.overall_score;
    return 0;
  };

  const riskScore = extractScore(result?.detection?.risk_score) || extractScore(result?.risk_score) || 0;
  const riskLevel = String(result?.detection?.risk_level || result?.risk_level || 'unknown').toLowerCase();
  
  // Compute verdict
  const computeVerdict = (level: string, score: number): string => {
    const l = level?.toLowerCase();
    if (l === 'critical' || l === 'high' || score >= 60) return 'malicious';
    if (l === 'medium' || score >= 30) return 'suspicious';
    if (l === 'low' || l === 'minimal' || score < 30) return 'clean';
    return 'unknown';
  };
  const verdict = computeVerdict(riskLevel, riskScore);
  
  const rulesTriggered = result?.detection?.rules_triggered || result?.rules_triggered || [];
  const email = result?.email || result?.parsed_email || {};
  const urls = email?.urls || result?.urls || result?.extracted_urls || [];
  const attachments = email?.attachments || result?.attachments || [];
  
  const authentication = {
    spf: email?.spf_result || email?.header_analysis?.spf_result,
    dkim: email?.dkim_result || email?.header_analysis?.dkim_result,
    dmarc: email?.dmarc_result || email?.header_analysis?.dmarc_result,
  };
  
  const aiAnalysis = result?.ai_triage || result?.ai_analysis || result?.ai_summary || null;
  const iocs = result?.iocs || { domains: [], ips: [], urls: [], hashes: [] };

  // Color helpers
  const getVerdictStyles = (v: string) => {
    switch (v) {
      case 'malicious':
        return { bg: 'bg-red-600', ring: 'ring-red-500/30', text: 'text-red-400' };
      case 'suspicious':
        return { bg: 'bg-orange-600', ring: 'ring-orange-500/30', text: 'text-orange-400' };
      case 'clean':
        return { bg: 'bg-green-600', ring: 'ring-green-500/30', text: 'text-green-400' };
      default:
        return { bg: 'bg-gray-600', ring: 'ring-gray-500/30', text: 'text-gray-400' };
    }
  };

  const getRiskRingColor = (score: number) => {
    if (score >= 70) return 'border-red-500';
    if (score >= 40) return 'border-orange-500';
    if (score >= 20) return 'border-yellow-500';
    return 'border-green-500';
  };

  const getSeverityStyles = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-900/50 text-red-400 border-red-700/50';
      case 'high':
        return 'bg-orange-900/50 text-orange-400 border-orange-700/50';
      case 'medium':
        return 'bg-yellow-900/50 text-yellow-400 border-yellow-700/50';
      case 'low':
        return 'bg-blue-900/50 text-blue-400 border-blue-700/50';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  // Extract auth result string from value (could be string or object)
  const getAuthResultString = (value: any): string => {
    if (!value) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'object') {
      return value.result || value.status || value.verdict || '';
    }
    return String(value);
  };

  const getAuthIcon = (value: any) => {
    const result = getAuthResultString(value).toLowerCase();
    switch (result) {
      case 'pass':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'fail':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'softfail':
        return <MinusCircle className="w-4 h-4 text-yellow-400" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getAuthColor = (value: any) => {
    const result = getAuthResultString(value).toLowerCase();
    switch (result) {
      case 'pass':
        return 'text-green-400';
      case 'fail':
        return 'text-red-400';
      case 'softfail':
        return 'text-yellow-400';
      default:
        return 'text-gray-500';
    }
  };

  const getAuthDisplayValue = (value: any): string => {
    const result = getAuthResultString(value);
    return result || 'N/A';
  };

  const verdictStyles = getVerdictStyles(verdict);

  // Collapsible Section Component
  const Section: React.FC<{
    id: string;
    title: string;
    icon: React.ReactNode;
    children: React.ReactNode;
    badge?: React.ReactNode;
  }> = ({ id, title, icon, children, badge }) => {
    const isExpanded = expandedSections.has(id);
    return (
      <div className="border border-gray-700 rounded-lg overflow-hidden bg-gray-800/50">
        <button
          onClick={() => toggleSection(id)}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-800 transition-colors"
        >
          <div className="flex items-center gap-2">
            {icon}
            <span className="font-medium text-gray-200 text-sm">{title}</span>
            {badge}
          </div>
          {isExpanded ? (
            <ChevronDown className="w-4 h-4 text-gray-500" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-500" />
          )}
        </button>
        {isExpanded && <div className="border-t border-gray-700 p-3">{children}</div>}
      </div>
    );
  };

  try {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 overflow-hidden">
        {/* Header with Risk Score */}
        <div className="p-4 border-b border-gray-700 bg-gray-800/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              {/* Risk Score Circle */}
              <div className={`relative w-16 h-16 rounded-full border-4 ${getRiskRingColor(riskScore)} flex items-center justify-center bg-gray-900`}>
                <div className="text-center">
                  <span className="text-2xl font-bold text-gray-100">{riskScore}</span>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">Risk</div>
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold text-white ${verdictStyles.bg}`}>
                    {(verdict || 'unknown').toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded border border-gray-700">
                    {riskLevel}
                  </span>
                </div>
                <h3 className="font-semibold text-gray-100 text-sm truncate max-w-[280px]">
                  {email.subject || '(No Subject)'}
                </h3>
                <p className="text-xs text-gray-500">
                  From: {email.sender?.email || email.sender || 'Unknown'}
                </p>
              </div>
            </div>

            <button
              onClick={onViewFullAnalysis}
              className="flex items-center gap-2 px-4 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium"
            >
              <Eye className="w-4 h-4" />
              Full Analysis
            </button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-4 gap-2 md:gap-3 p-3 md:p-4 bg-gray-900 border-b border-gray-700">
          <div className="text-center p-2 md:p-3 bg-gray-800 rounded-lg border border-gray-700">
            <div className="text-lg md:text-xl font-bold text-indigo-400">{rulesTriggered.length}</div>
            <div className="text-[10px] md:text-xs text-gray-500 uppercase tracking-wide">Rules</div>
          </div>
          <div className="text-center p-2 md:p-3 bg-gray-800 rounded-lg border border-gray-700">
            <div className="text-lg md:text-xl font-bold text-purple-400">{urls.length}</div>
            <div className="text-[10px] md:text-xs text-gray-500 uppercase tracking-wide">URLs</div>
          </div>
          <div className="text-center p-2 md:p-3 bg-gray-800 rounded-lg border border-gray-700">
            <div className="text-lg md:text-xl font-bold text-blue-400">{attachments.length}</div>
            <div className="text-[10px] md:text-xs text-gray-500 uppercase tracking-wide">Files</div>
          </div>
          <div className="text-center p-2 md:p-3 bg-gray-800 rounded-lg border border-gray-700">
            <div className="text-lg md:text-xl font-bold text-orange-400">
              {(iocs.domains?.length || 0) + (iocs.ips?.length || 0) + (iocs.hashes?.length || 0)}
            </div>
            <div className="text-[10px] md:text-xs text-gray-500 uppercase tracking-wide">IOCs</div>
          </div>
        </div>

        {/* Sections */}
        <div className="p-3 md:p-4 space-y-3 max-h-[400px] md:max-h-[500px] overflow-auto">
          {/* AI Analysis */}
          {aiAnalysis && (
            <Section
              id="ai"
              title="AI Analysis"
              icon={<Brain className="w-4 h-4 text-purple-400" />}
              badge={
                <span className="text-[10px] bg-purple-900/50 text-purple-400 px-2 py-0.5 rounded border border-purple-700/50">
                  {aiAnalysis.provider || 'AI'}
                </span>
              }
            >
              <div className="space-y-3">
                {/* Summary */}
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                  <p className="text-sm text-gray-300 leading-relaxed">
                    {aiAnalysis.summary || aiAnalysis.executive_summary || 'No summary available'}
                  </p>
                </div>

                {/* Key Findings */}
                {aiAnalysis.key_findings && aiAnalysis.key_findings.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-orange-400" />
                      Key Findings
                    </h5>
                    <ul className="space-y-1.5">
                      {aiAnalysis.key_findings.slice(0, 3).map((finding: string, idx: number) => (
                        <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                          <span className="text-orange-400 mt-0.5">•</span>
                          <span>{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Recommendations */}
                {aiAnalysis.recommendations && aiAnalysis.recommendations.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-1">
                      <Lightbulb className="w-3 h-3 text-yellow-400" />
                      Recommendations
                    </h5>
                    <ul className="space-y-1.5">
                      {aiAnalysis.recommendations.slice(0, 3).map((rec: string, idx: number) => (
                        <li key={idx} className="text-xs text-gray-400 flex items-start gap-2">
                          <CheckCircle className="w-3 h-3 text-green-400 mt-0.5 flex-shrink-0" />
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* MITRE */}
                {aiAnalysis.mitre_techniques && aiAnalysis.mitre_techniques.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {aiAnalysis.mitre_techniques.map((tech: any, idx: number) => (
                      <span
                        key={idx}
                        className="text-[10px] bg-red-900/50 text-red-400 px-2 py-0.5 rounded border border-red-700/50"
                      >
                        {tech.id || tech}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Detection Rules */}
          <Section
            id="detection"
            title="Detection Rules Triggered"
            icon={<Shield className="w-4 h-4 text-red-400" />}
            badge={
              rulesTriggered.length > 0 && (
                <span className="text-[10px] bg-red-900/50 text-red-400 px-2 py-0.5 rounded border border-red-700/50">
                  {rulesTriggered.length}
                </span>
              )
            }
          >
            {rulesTriggered.length === 0 ? (
              <div className="text-center py-4 text-gray-500 text-sm">
                <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-500 opacity-50" />
                No detection rules triggered
              </div>
            ) : (
              <div className="space-y-2">
                {rulesTriggered.slice(0, 5).map((rule: any, idx: number) => (
                  <div key={idx} className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 text-[10px] font-medium rounded border ${getSeverityStyles(rule.severity)}`}>
                            {(rule.severity || 'unknown').toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-300">{rule.description || rule.rule_name || rule.name}</p>
                      </div>
                    </div>
                  </div>
                ))}
                {rulesTriggered.length > 5 && (
                  <p className="text-xs text-gray-500 text-center">
                    +{rulesTriggered.length - 5} more rules
                  </p>
                )}
              </div>
            )}
          </Section>

          {/* Email Authentication */}
          <Section
            id="auth"
            title="Email Authentication"
            icon={<Key className="w-4 h-4 text-blue-400" />}
          >
            <div className="grid grid-cols-3 gap-3">
              {['spf', 'dkim', 'dmarc'].map((auth) => {
                const value = authentication[auth as keyof typeof authentication];
                return (
                  <div key={auth} className="bg-gray-900 rounded-lg p-3 border border-gray-700 text-center">
                    <div className="flex justify-center mb-2">
                      {getAuthIcon(value)}
                    </div>
                    <div className="text-xs font-bold text-gray-300 uppercase mb-1">{auth}</div>
                    <div className={`text-xs font-medium ${getAuthColor(value)}`}>
                      {getAuthDisplayValue(value)}
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>

          {/* URLs */}
          {urls.length > 0 && (
            <Section
              id="urls"
              title="URLs"
              icon={<Link className="w-4 h-4 text-purple-400" />}
              badge={
                <span className="text-[10px] bg-purple-900/50 text-purple-400 px-2 py-0.5 rounded border border-purple-700/50">
                  {urls.length}
                </span>
              }
            >
              <div className="space-y-2">
                {urls.slice(0, 5).map((url: any, idx: number) => {
                  const urlStr = typeof url === 'string' ? url : url?.url || '';
                  return (
                    <div key={idx} className="flex items-center justify-between bg-gray-900 rounded p-2 border border-gray-700">
                      <code className="text-xs text-gray-400 truncate flex-1 mr-2">{urlStr}</code>
                      <button
                        onClick={() => copyToClipboard(urlStr, `url-${idx}`)}
                        className="text-gray-500 hover:text-gray-300 flex-shrink-0"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  );
                })}
                {urls.length > 5 && (
                  <p className="text-xs text-gray-500 text-center">+{urls.length - 5} more URLs</p>
                )}
              </div>
            </Section>
          )}

          {/* Attachments with Static Analysis */}
          {attachments.length > 0 && (
            <Section
              id="attachments"
              title="Attachments"
              icon={<Paperclip className="w-4 h-4 text-blue-400" />}
              badge={
                <span className="text-[10px] bg-blue-900/50 text-blue-400 px-2 py-0.5 rounded border border-blue-700/50">
                  {attachments.length}
                </span>
              }
            >
              <div className="space-y-3">
                {attachments.map((att: any, idx: number) => {
                  const threatLevel = att.threat_level?.toLowerCase() || 'unknown';
                  const threatScore = att.threat_score || 0;
                  
                  const getThreatStyles = (level: string, score: number) => {
                    if (level === 'critical' || score >= 70) return { bg: 'bg-red-900/30', border: 'border-red-700/50', badge: 'bg-red-600', text: 'text-red-400' };
                    if (level === 'high' || score >= 50) return { bg: 'bg-orange-900/30', border: 'border-orange-700/50', badge: 'bg-orange-600', text: 'text-orange-400' };
                    if (level === 'medium' || score >= 25) return { bg: 'bg-yellow-900/30', border: 'border-yellow-700/50', badge: 'bg-yellow-600', text: 'text-yellow-400' };
                    if (level === 'low' || score > 0) return { bg: 'bg-blue-900/30', border: 'border-blue-700/50', badge: 'bg-blue-600', text: 'text-blue-400' };
                    return { bg: 'bg-gray-900', border: 'border-gray-700', badge: 'bg-green-600', text: 'text-green-400' };
                  };
                  
                  const threatStyles = getThreatStyles(threatLevel, threatScore);
                  
                  return (
                    <div key={idx} className={`${threatStyles.bg} rounded-lg p-3 border ${threatStyles.border}`}>
                      {/* Header Row */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          <FileText className="w-4 h-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-300 truncate">{att.filename || att.name}</span>
                        </div>
                        
                        {/* Threat Score Badge */}
                        {threatScore > 0 && (
                          <div className={`flex items-center gap-1 px-2 py-0.5 rounded ${threatStyles.badge}`}>
                            <Shield className="w-3 h-3 text-white" />
                            <span className="text-[10px] text-white font-bold">{threatScore}/100</span>
                          </div>
                        )}
                      </div>
                      
                      {/* File Info Row */}
                      <div className="text-xs text-gray-500 mt-1 flex items-center gap-2 flex-wrap">
                        <span>{att.content_type}</span>
                        <span>•</span>
                        <span>{((att.size_bytes || att.size || 0) / 1024).toFixed(1)} KB</span>
                        {att.entropy && (
                          <>
                            <span>•</span>
                            <span>Entropy: {att.entropy.toFixed(2)}</span>
                          </>
                        )}
                      </div>
                      
                      {/* Warning Badges */}
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {att.is_executable && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />EXECUTABLE
                          </span>
                        )}
                        {(att.has_macros || att.is_office_with_macros) && (
                          <span className="text-[10px] bg-orange-900/50 text-orange-400 px-1.5 py-0.5 rounded border border-orange-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />MACROS
                          </span>
                        )}
                        {att.has_auto_exec_macros && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <XCircle className="w-2.5 h-2.5" />AUTO-EXEC
                          </span>
                        )}
                        {att.has_dde && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />DDE
                          </span>
                        )}
                        {att.has_ole_objects && (
                          <span className="text-[10px] bg-yellow-900/50 text-yellow-400 px-1.5 py-0.5 rounded border border-yellow-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />OLE
                          </span>
                        )}
                        {att.has_javascript && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />JS
                          </span>
                        )}
                        {att.has_embedded_files && (
                          <span className="text-[10px] bg-yellow-900/50 text-yellow-400 px-1.5 py-0.5 rounded border border-yellow-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />EMBEDDED
                          </span>
                        )}
                        {att.is_packed && (
                          <span className="text-[10px] bg-purple-900/50 text-purple-400 px-1.5 py-0.5 rounded border border-purple-700/50 flex items-center gap-1">
                            <Lock className="w-2.5 h-2.5" />PACKED
                          </span>
                        )}
                        {att.has_suspicious_imports && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />SUS IMPORTS
                          </span>
                        )}
                        {att.type_mismatch && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <XCircle className="w-2.5 h-2.5" />TYPE MISMATCH
                          </span>
                        )}
                        {att.has_double_extension && (
                          <span className="text-[10px] bg-red-900/50 text-red-400 px-1.5 py-0.5 rounded border border-red-700/50 flex items-center gap-1">
                            <XCircle className="w-2.5 h-2.5" />DOUBLE EXT
                          </span>
                        )}
                        {att.is_archive && (
                          <span className="text-[10px] bg-blue-900/50 text-blue-400 px-1.5 py-0.5 rounded border border-blue-700/50">ARCHIVE</span>
                        )}
                        {att.is_script && (
                          <span className="text-[10px] bg-yellow-900/50 text-yellow-400 px-1.5 py-0.5 rounded border border-yellow-700/50">SCRIPT</span>
                        )}
                        {threatLevel === 'clean' && threatScore === 0 && (
                          <span className="text-[10px] bg-green-900/50 text-green-400 px-1.5 py-0.5 rounded border border-green-700/50 flex items-center gap-1">
                            <CheckCircle className="w-2.5 h-2.5" />CLEAN
                          </span>
                        )}
                      </div>
                      
                      {/* Threat Summary */}
                      {att.threat_summary && threatScore > 0 && (
                        <div className={`mt-2 text-xs ${threatStyles.text} bg-gray-900/50 rounded p-2`}>
                          {att.threat_summary}
                        </div>
                      )}
                      
                      {/* Extracted IOCs from attachment */}
                      {((att.extracted_urls?.length > 0) || (att.extracted_ips?.length > 0) || (att.suspicious_strings?.length > 0)) && (
                        <div className="mt-2 border-t border-gray-700/50 pt-2">
                          <div className="text-[10px] text-gray-500 mb-1 font-medium">EXTRACTED FROM FILE:</div>
                          <div className="flex flex-wrap gap-1">
                            {att.extracted_urls?.slice(0, 3).map((url: string, i: number) => (
                              <span key={`url-${i}`} className="text-[10px] bg-purple-900/30 text-purple-400 px-1.5 py-0.5 rounded border border-purple-700/30 max-w-[200px] truncate">
                                🔗 {url}
                              </span>
                            ))}
                            {att.extracted_ips?.slice(0, 3).map((ip: string, i: number) => (
                              <span key={`ip-${i}`} className="text-[10px] bg-blue-900/30 text-blue-400 px-1.5 py-0.5 rounded border border-blue-700/30">
                                🌐 {ip}
                              </span>
                            ))}
                            {att.suspicious_strings?.slice(0, 3).map((s: string, i: number) => (
                              <span key={`sus-${i}`} className="text-[10px] bg-red-900/30 text-red-400 px-1.5 py-0.5 rounded border border-red-700/30 max-w-[150px] truncate">
                                ⚠️ {s}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {/* Hash row */}
                      <div className="mt-2 flex items-center gap-2 text-[10px] text-gray-600">
                        <button
                          onClick={() => copyToClipboard(att.sha256 || '', `sha256-${idx}`)}
                          className="flex items-center gap-1 hover:text-gray-400 transition-colors"
                          title="Copy SHA256"
                        >
                          <Hash className="w-3 h-3" />
                          <span className="font-mono">{(att.sha256 || '').slice(0, 16)}...</span>
                          <Copy className="w-2.5 h-2.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Section>
          )}

          {/* IOCs */}
          {((iocs.domains?.length || 0) + (iocs.ips?.length || 0) + (iocs.hashes?.length || 0)) > 0 && (
            <Section
              id="iocs"
              title="Indicators of Compromise"
              icon={<Target className="w-4 h-4 text-orange-400" />}
            >
              <div className="grid grid-cols-2 gap-3">
                {/* Domains */}
                {iocs.domains && iocs.domains.length > 0 && (
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <div className="font-medium text-gray-300 mb-2 text-xs flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-blue-400" />
                      Domains ({iocs.domains.length})
                    </div>
                    <div className="space-y-1 max-h-24 overflow-auto">
                      {iocs.domains.slice(0, 5).map((domain: string, idx: number) => (
                        <div key={idx} className="flex items-center justify-between">
                          <code className="text-[11px] text-gray-400">{domain}</code>
                          <button
                            onClick={() => copyToClipboard(domain, `domain-${idx}`)}
                            className="text-gray-600 hover:text-gray-400"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* IPs */}
                {iocs.ips && iocs.ips.length > 0 && (
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <div className="font-medium text-gray-300 mb-2 text-xs flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-green-400" />
                      IPs ({iocs.ips.length})
                    </div>
                    <div className="space-y-1 max-h-24 overflow-auto">
                      {iocs.ips.slice(0, 5).map((ip: string, idx: number) => (
                        <div key={idx} className="flex items-center justify-between">
                          <code className="text-[11px] text-gray-400">{ip}</code>
                          <button
                            onClick={() => copyToClipboard(ip, `ip-${idx}`)}
                            className="text-gray-600 hover:text-gray-400"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Hashes */}
                {iocs.hashes && iocs.hashes.length > 0 && (
                  <div className="bg-gray-900 rounded-lg p-3 border border-gray-700 col-span-2">
                    <div className="font-medium text-gray-300 mb-2 text-xs flex items-center gap-1.5">
                      <Hash className="w-3.5 h-3.5 text-purple-400" />
                      File Hashes ({iocs.hashes.length})
                    </div>
                    <div className="space-y-1 max-h-24 overflow-auto">
                      {iocs.hashes.slice(0, 3).map((hash: any, idx: number) => (
                        <div key={idx} className="flex items-center justify-between">
                          <div>
                            <span className="text-[10px] text-gray-500">{hash.type || 'SHA256'}:</span>
                            <code className="text-[11px] text-gray-400 ml-1">
                              {(hash.value || hash).slice(0, 24)}...
                            </code>
                          </div>
                          <button
                            onClick={() => copyToClipboard(hash.value || hash, `hash-${idx}`)}
                            className="text-gray-600 hover:text-gray-400"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Section>
          )}
        </div>

        {/* Export Buttons */}
        <div className="p-4 border-t border-gray-700 bg-gray-800/50">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500">Export Analysis</span>
            <div className="flex gap-2">
              {['JSON', 'PDF', 'MARKDOWN', 'CSV', 'STIX'].map((format) => (
                <button
                  key={format}
                  onClick={() => onExport(format.toLowerCase())}
                  className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors font-medium border border-gray-600"
                >
                  {format}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Copy Toast */}
        {copiedText && (
          <div className="fixed bottom-4 right-4 bg-gray-800 text-gray-200 px-4 py-2 rounded-lg text-sm shadow-lg border border-gray-700 z-50">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-green-400" />
              Copied to clipboard!
            </div>
          </div>
        )}
      </div>
    );
  } catch (err) {
    console.error('ResultsPanel render error:', err);
    return (
      <div className="bg-red-900/30 border border-red-700 rounded-xl p-6">
        <h3 className="text-red-400 font-semibold mb-2">Error Rendering Results</h3>
        <p className="text-sm text-red-300">{String(err)}</p>
      </div>
    );
  }
};

export default ResultsPanel;
