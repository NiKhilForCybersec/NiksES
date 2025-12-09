import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Mail,
  User,
  Users,
  Calendar,
  Clock,
  Link,
  Paperclip,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  ChevronDown,
  ChevronRight,
  Globe,
  Server,
  Key,
  Hash,
  ExternalLink,
  Copy,
  Download,
  Brain,
  Lightbulb,
  Target,
  Activity,
  Search,
  Database,
  Zap,
  Eye,
  EyeOff,
  MessageSquare,
  Tag,
  Layers,
  Wrench,
} from 'lucide-react';
import { FullSOCToolsView } from '../soc-tools';

interface AnalysisResult {
  id: string;
  filename: string;
  analyzed_at: string;
  email: {
    message_id: string;
    subject: string;
    sender: {
      raw: string;
      display_name: string;
      email: string;
      domain: string;
    };
    recipients: {
      to: string[];
      cc: string[];
      bcc: string[];
    };
    reply_to: string | null;
    date: string;
    body_text: string;
    body_html: string;
    headers: Record<string, string>;
  };
  authentication: {
    spf?: { result: string; details?: string };
    dkim?: { result: string; details?: string };
    dmarc?: { result: string; details?: string };
  };
  urls: {
    url: string;
    domain: string;
    is_shortened: boolean;
    is_suspicious: boolean;
    threat_info?: { source: string; threat_type: string };
  }[];
  attachments: {
    filename: string;
    content_type: string;
    size: number;
    md5: string;
    sha256: string;
    is_executable: boolean;
    is_macro_enabled: boolean;
    has_double_extension: boolean;
    threat_info?: { source: string; detections: number };
  }[];
  enrichment: {
    geoip?: { country: string; city: string; isp: string; ip: string };
    whois?: { registrar: string; created_date: string; domain_age_days: number };
    dns?: { mx_records: string[]; spf_record: string; has_dmarc: boolean };
    virustotal?: { positives: number; total: number; permalink: string };
    abuseipdb?: { abuse_confidence: number; total_reports: number };
    urlhaus?: { threat_type: string; tags: string[] };
    phishtank?: { verified: boolean; phish_id: string };
  };
  detection: {
    rules_triggered: {
      rule_id: string;
      name: string;
      description: string;
      category: string;
      severity: string;
      mitre_technique?: string;
      is_custom: boolean;
    }[];
    risk_score: number;
    risk_level: string;
    verdict: string;
  };
  ai_analysis?: {
    enabled?: boolean;
    provider?: string;
    summary?: string;
    threat_assessment?: string;
    key_findings?: string[];
    recommendations?: (string | any)[];
    mitre_techniques?: ({ id: string; name: string; description?: string } | any)[];
    confidence?: number;
  } | null;
  iocs: {
    domains: string[];
    ips: string[];
    urls: string[];
    hashes: { type: string; value: string }[];
    emails: string[];
  };
  timeline: {
    timestamp: string;
    event: string;
    status: 'success' | 'warning' | 'error' | 'info';
    details?: string;
  }[];
}

interface AnalysisViewProps {
  analysis: AnalysisResult | null;
  onClose: () => void;
  onExport: (format: string) => void;
}

const AnalysisView: React.FC<AnalysisViewProps> = ({ analysis, onClose, onExport }) => {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['overview', 'detection', 'ai', 'iocs'])
  );
  const [activeTab, setActiveTab] = useState<'overview' | 'technical' | 'enrichment' | 'timeline'>('overview');
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [showSOCTools, setShowSOCTools] = useState(false);

  if (!analysis) {
    return null;
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

  const getVerdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return 'bg-red-500';
      case 'suspicious':
        return 'bg-orange-500';
      case 'clean':
        return 'bg-green-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getVerdictBgColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return 'bg-red-50 border-red-200';
      case 'suspicious':
        return 'bg-orange-50 border-orange-200';
      case 'clean':
        return 'bg-green-50 border-green-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getAuthStatusIcon = (result: string) => {
    switch (result.toLowerCase()) {
      case 'pass':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'fail':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'none':
        return <Info className="w-5 h-5 text-gray-400" />;
      default:
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
    }
  };

  const getRiskScoreGradient = (score: number) => {
    if (score >= 80) return 'from-red-500 to-red-600';
    if (score >= 60) return 'from-orange-500 to-red-500';
    if (score >= 40) return 'from-yellow-500 to-orange-500';
    if (score >= 20) return 'from-blue-500 to-yellow-500';
    return 'from-green-500 to-blue-500';
  };

  const Section: React.FC<{
    id: string;
    title: string;
    icon: React.ReactNode;
    children: React.ReactNode;
    badge?: React.ReactNode;
  }> = ({ id, title, icon, children, badge }) => {
    const isExpanded = expandedSections.has(id);
    return (
      <div className="border rounded-lg overflow-hidden bg-white">
        <button
          onClick={() => toggleSection(id)}
          className="w-full flex items-center justify-between p-4 hover:bg-gray-50 transition-colors"
        >
          <div className="flex items-center gap-3">
            {icon}
            <span className="font-semibold text-gray-900">{title}</span>
            {badge}
          </div>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </button>
        {isExpanded && <div className="border-t p-4">{children}</div>}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-100 rounded-xl shadow-2xl w-full max-w-6xl max-h-[95vh] overflow-hidden flex flex-col">
        {/* Header with Risk Score */}
        <div className={`relative overflow-hidden ${getVerdictBgColor(analysis.detection.verdict)} border-b`}>
          <div className="absolute inset-0 opacity-10">
            <div className={`absolute inset-0 bg-gradient-to-r ${getRiskScoreGradient(analysis.detection.risk_score)}`} />
          </div>
          <div className="relative p-6">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-6">
                {/* Risk Score Circle */}
                <div className={`relative w-24 h-24 rounded-full bg-gradient-to-br ${getRiskScoreGradient(analysis.detection.risk_score)} p-1`}>
                  <div className="w-full h-full rounded-full bg-white flex flex-col items-center justify-center">
                    <span className="text-3xl font-bold text-gray-900">{analysis.detection.risk_score}</span>
                    <span className="text-xs text-gray-500 uppercase">Risk Score</span>
                  </div>
                </div>

                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`px-3 py-1 rounded-full text-sm font-bold text-white ${getVerdictColor(analysis.detection.verdict)}`}>
                      {analysis.detection.verdict.toUpperCase()}
                    </span>
                    <span className="text-sm text-gray-600 bg-white/50 px-2 py-1 rounded">
                      {analysis.detection.risk_level}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-gray-900 mb-1">
                    {analysis.email.subject || '(No Subject)'}
                  </h2>
                  <div className="flex items-center gap-4 text-sm text-gray-600">
                    <span className="flex items-center gap-1">
                      <Mail className="w-4 h-4" />
                      {analysis.email.sender.email}
                    </span>
                    <span className="flex items-center gap-1">
                      <Calendar className="w-4 h-4" />
                      {new Date(analysis.analyzed_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {/* SOC Tools Button */}
                <button
                  onClick={() => setShowSOCTools(true)}
                  className="flex items-center gap-2 px-4 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors text-sm font-medium"
                >
                  <Wrench className="w-4 h-4" />
                  SOC Tools
                </button>
                
                <div className="flex gap-1">
                  {[
                    { format: 'executive-pdf', label: 'Executive PDF', primary: true },
                    { format: 'pdf', label: 'Technical PDF', primary: false },
                    { format: 'json', label: 'JSON', primary: false },
                    { format: 'markdown', label: 'MD', primary: false },
                    { format: 'stix', label: 'STIX', primary: false },
                  ].map(({ format, label, primary }) => (
                    <button
                      key={format}
                      onClick={() => onExport(format)}
                      className={`px-3 py-1.5 text-sm border rounded-lg transition-colors ${
                        primary 
                          ? 'bg-blue-600 hover:bg-blue-500 text-white border-blue-600' 
                          : 'bg-white/80 hover:bg-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <button
                  onClick={onClose}
                  className="p-2 hover:bg-white/50 rounded-lg transition-colors"
                >
                  <XCircle className="w-6 h-6 text-gray-600" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b bg-white">
          {[
            { id: 'overview', label: 'Overview', icon: <Eye className="w-4 h-4" /> },
            { id: 'technical', label: 'Technical Details', icon: <Server className="w-4 h-4" /> },
            { id: 'enrichment', label: 'Threat Intel', icon: <Database className="w-4 h-4" /> },
            { id: 'timeline', label: 'Analysis Timeline', icon: <Activity className="w-4 h-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-6 py-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'text-indigo-600 border-b-2 border-indigo-600 bg-indigo-50'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {activeTab === 'overview' && (
            <div className="space-y-4">
              {/* Quick Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-white rounded-lg p-4 border">
                  <div className="text-sm text-gray-500 mb-1">Rules Triggered</div>
                  <div className="text-2xl font-bold text-gray-900">
                    {analysis.detection.rules_triggered.length}
                  </div>
                </div>
                <div className="bg-white rounded-lg p-4 border">
                  <div className="text-sm text-gray-500 mb-1">URLs Found</div>
                  <div className="text-2xl font-bold text-gray-900">{analysis.urls.length}</div>
                </div>
                <div className="bg-white rounded-lg p-4 border">
                  <div className="text-sm text-gray-500 mb-1">Attachments</div>
                  <div className="text-2xl font-bold text-gray-900">{analysis.attachments.length}</div>
                </div>
                <div className="bg-white rounded-lg p-4 border">
                  <div className="text-sm text-gray-500 mb-1">IOCs Extracted</div>
                  <div className="text-2xl font-bold text-gray-900">
                    {analysis.iocs.domains.length +
                      analysis.iocs.ips.length +
                      analysis.iocs.urls.length +
                      analysis.iocs.hashes.length}
                  </div>
                </div>
              </div>

              {/* AI Analysis */}
              {analysis.ai_analysis?.enabled && (
                <Section
                  id="ai"
                  title="AI Analysis & Recommendations"
                  icon={<Brain className="w-5 h-5 text-purple-600" />}
                  badge={
                    <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">
                      {analysis.ai_analysis.provider}
                    </span>
                  }
                >
                  <div className="space-y-4">
                    {/* Summary */}
                    <div className="bg-purple-50 rounded-lg p-4 border border-purple-100">
                      <h4 className="font-semibold text-purple-900 mb-2 flex items-center gap-2">
                        <MessageSquare className="w-4 h-4" />
                        Executive Summary
                      </h4>
                      <p className="text-gray-700">{analysis.ai_analysis.summary}</p>
                    </div>

                    {/* Key Findings */}
                    {analysis.ai_analysis.key_findings && analysis.ai_analysis.key_findings.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                        <Search className="w-4 h-4" />
                        Key Findings
                      </h4>
                      <ul className="space-y-2">
                        {analysis.ai_analysis.key_findings.map((finding, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-gray-700">
                            <AlertTriangle className="w-4 h-4 text-orange-500 mt-0.5 flex-shrink-0" />
                            {finding}
                          </li>
                        ))}
                      </ul>
                    </div>
                    )}

                    {/* Recommendations */}
                    {analysis.ai_analysis.recommendations && analysis.ai_analysis.recommendations.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                        <Lightbulb className="w-4 h-4 text-yellow-500" />
                        Recommendations
                      </h4>
                      <ul className="space-y-2">
                        {analysis.ai_analysis.recommendations.map((rec, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-gray-700">
                            <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                            {typeof rec === 'string' ? rec : rec?.description || rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                    )}

                    {/* MITRE Techniques */}
                    {analysis.ai_analysis.mitre_techniques && analysis.ai_analysis.mitre_techniques.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                          <Target className="w-4 h-4 text-red-500" />
                          MITRE ATT&CK Techniques
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          {analysis.ai_analysis.mitre_techniques.map((tech, idx) => (
                            <span
                              key={idx}
                              className="px-3 py-1 bg-red-50 text-red-700 rounded-lg text-sm border border-red-200"
                              title={tech?.description || ''}
                            >
                              {tech?.id || tech}: {tech?.name || ''}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </Section>
              )}

              {/* Detection Rules */}
              <Section
                id="detection"
                title="Detection Rules Triggered"
                icon={<Shield className="w-5 h-5 text-red-600" />}
                badge={
                  <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">
                    {analysis.detection.rules_triggered.length} rules
                  </span>
                }
              >
                <div className="space-y-2">
                  {analysis.detection.rules_triggered.length === 0 ? (
                    <p className="text-gray-500">No detection rules triggered</p>
                  ) : (
                    analysis.detection.rules_triggered.map((rule, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg border"
                      >
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(
                            rule.severity
                          )}`}
                        >
                          {rule.severity.toUpperCase()}
                        </span>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-gray-500">{rule.rule_id}</span>
                            <span className="font-semibold text-gray-900">{rule.name}</span>
                            {rule.is_custom && (
                              <span className="text-xs bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded">
                                Custom
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 mt-1">{rule.description}</p>
                          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                            <span className="bg-gray-100 px-2 py-0.5 rounded">{rule.category}</span>
                            {rule.mitre_technique && (
                              <span className="bg-red-50 text-red-600 px-2 py-0.5 rounded">
                                {rule.mitre_technique}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </Section>

              {/* IOCs */}
              <Section
                id="iocs"
                title="Indicators of Compromise (IOCs)"
                icon={<Target className="w-5 h-5 text-orange-600" />}
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Domains */}
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                      <Globe className="w-4 h-4" />
                      Domains ({analysis.iocs.domains.length})
                    </h4>
                    <div className="space-y-1 max-h-40 overflow-auto">
                      {analysis.iocs.domains.map((domain, idx) => (
                        <div key={idx} className="flex items-center justify-between text-sm">
                          <code className="text-gray-700">{domain}</code>
                          <button
                            onClick={() => copyToClipboard(domain, `domain-${idx}`)}
                            className="text-gray-400 hover:text-gray-600"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* IPs */}
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                      <Server className="w-4 h-4" />
                      IP Addresses ({analysis.iocs.ips.length})
                    </h4>
                    <div className="space-y-1 max-h-40 overflow-auto">
                      {analysis.iocs.ips.map((ip, idx) => (
                        <div key={idx} className="flex items-center justify-between text-sm">
                          <code className="text-gray-700">{ip}</code>
                          <button
                            onClick={() => copyToClipboard(ip, `ip-${idx}`)}
                            className="text-gray-400 hover:text-gray-600"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* URLs */}
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                      <Link className="w-4 h-4" />
                      URLs ({analysis.iocs.urls.length})
                    </h4>
                    <div className="space-y-1 max-h-40 overflow-auto">
                      {analysis.iocs.urls.map((url, idx) => (
                        <div key={idx} className="flex items-center justify-between text-sm">
                          <code className="text-gray-700 truncate max-w-[250px]" title={url}>
                            {url}
                          </code>
                          <button
                            onClick={() => copyToClipboard(url, `url-${idx}`)}
                            className="text-gray-400 hover:text-gray-600"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Hashes */}
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-2">
                      <Hash className="w-4 h-4" />
                      File Hashes ({analysis.iocs.hashes.length})
                    </h4>
                    <div className="space-y-1 max-h-40 overflow-auto">
                      {analysis.iocs.hashes.map((hash, idx) => (
                        <div key={idx} className="flex items-center justify-between text-sm">
                          <div>
                            <span className="text-xs text-gray-500 mr-2">{hash.type}:</span>
                            <code className="text-gray-700 text-xs">{hash.value.slice(0, 32)}...</code>
                          </div>
                          <button
                            onClick={() => copyToClipboard(hash.value, `hash-${idx}`)}
                            className="text-gray-400 hover:text-gray-600"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </Section>

              {/* Email Authentication */}
              <Section
                id="auth"
                title="Email Authentication"
                icon={<Key className="w-5 h-5 text-blue-600" />}
              >
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {['spf', 'dkim', 'dmarc'].map((auth) => {
                    const authData = analysis.authentication?.[auth as keyof typeof analysis.authentication];
                    const result = authData?.result || 'none';
                    return (
                      <div key={auth} className="bg-gray-50 rounded-lg p-4 border">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-semibold text-gray-900 uppercase">{auth}</span>
                          {getAuthStatusIcon(result)}
                        </div>
                        <div
                          className={`text-sm font-medium ${
                            result === 'pass'
                              ? 'text-green-600'
                              : result === 'fail'
                              ? 'text-red-600'
                              : 'text-gray-500'
                          }`}
                        >
                          {result.toUpperCase()}
                        </div>
                        <p className="text-xs text-gray-500 mt-1">{authData?.details || 'No details'}</p>
                      </div>
                    );
                  })}
                </div>
              </Section>
            </div>
          )}

          {activeTab === 'technical' && (
            <div className="space-y-4">
              {/* Email Details */}
              <Section
                id="email-details"
                title="Email Details"
                icon={<Mail className="w-5 h-5 text-blue-600" />}
              >
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs text-gray-500 uppercase">From</label>
                      <div className="flex items-center gap-2 mt-1">
                        <User className="w-4 h-4 text-gray-400" />
                        <span className="font-medium">{analysis.email.sender.display_name}</span>
                        <code className="text-sm text-gray-600">&lt;{analysis.email.sender.email}&gt;</code>
                      </div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500 uppercase">Domain</label>
                      <div className="flex items-center gap-2 mt-1">
                        <Globe className="w-4 h-4 text-gray-400" />
                        <code className="font-medium">{analysis.email.sender.domain}</code>
                      </div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500 uppercase">To</label>
                      <div className="flex items-center gap-2 mt-1">
                        <Users className="w-4 h-4 text-gray-400" />
                        <span>{analysis.email.recipients.to.join(', ')}</span>
                      </div>
                    </div>
                    {analysis.email.reply_to && (
                      <div>
                        <label className="text-xs text-gray-500 uppercase">Reply-To</label>
                        <div className="flex items-center gap-2 mt-1 text-orange-600">
                          <AlertTriangle className="w-4 h-4" />
                          <span>{analysis.email.reply_to}</span>
                        </div>
                      </div>
                    )}
                    <div>
                      <label className="text-xs text-gray-500 uppercase">Date</label>
                      <div className="flex items-center gap-2 mt-1">
                        <Calendar className="w-4 h-4 text-gray-400" />
                        <span>{analysis.email.date}</span>
                      </div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500 uppercase">Message-ID</label>
                      <div className="flex items-center gap-2 mt-1">
                        <Hash className="w-4 h-4 text-gray-400" />
                        <code className="text-xs truncate">{analysis.email.message_id}</code>
                      </div>
                    </div>
                  </div>

                  {/* Body Preview */}
                  <div>
                    <label className="text-xs text-gray-500 uppercase">Body Preview</label>
                    <div className="mt-1 p-3 bg-gray-50 rounded-lg border max-h-40 overflow-auto">
                      <pre className="text-sm text-gray-700 whitespace-pre-wrap">
                        {analysis.email.body_text.slice(0, 1000)}
                        {analysis.email.body_text.length > 1000 && '...'}
                      </pre>
                    </div>
                  </div>
                </div>
              </Section>

              {/* URLs */}
              <Section
                id="urls"
                title="Extracted URLs"
                icon={<Link className="w-5 h-5 text-indigo-600" />}
                badge={
                  <span className="text-xs bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">
                    {analysis.urls.length}
                  </span>
                }
              >
                <div className="space-y-2">
                  {analysis.urls.map((url, idx) => (
                    <div key={idx} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg border">
                      {url.is_suspicious ? (
                        <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
                      ) : (
                        <Link className="w-5 h-5 text-gray-400 flex-shrink-0" />
                      )}
                      <div className="flex-1 min-w-0">
                        <code className="text-sm break-all">{url.url}</code>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-gray-500">Domain: {url.domain}</span>
                          {url.is_shortened && (
                            <span className="text-xs bg-yellow-100 text-yellow-700 px-1.5 py-0.5 rounded">
                              Shortened
                            </span>
                          )}
                          {url.is_suspicious && (
                            <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
                              Suspicious
                            </span>
                          )}
                          {url.threat_info && (
                            <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
                              {url.threat_info.source}: {url.threat_info.threat_type}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>

              {/* Attachments */}
              <Section
                id="attachments"
                title="Attachments"
                icon={<Paperclip className="w-5 h-5 text-green-600" />}
                badge={
                  <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">
                    {analysis.attachments.length}
                  </span>
                }
              >
                <div className="space-y-2">
                  {analysis.attachments.map((att, idx) => (
                    <div key={idx} className="p-3 bg-gray-50 rounded-lg border">
                      <div className="flex items-start gap-3">
                        <FileText className="w-5 h-5 text-gray-400" />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{att.filename}</span>
                            {att.is_executable && (
                              <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
                                Executable
                              </span>
                            )}
                            {att.is_macro_enabled && (
                              <span className="text-xs bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded">
                                Macro
                              </span>
                            )}
                            {att.has_double_extension && (
                              <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
                                Double Extension
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-gray-500 mt-1">
                            {att.content_type} • {(att.size / 1024).toFixed(1)} KB
                          </div>
                          <div className="mt-2 text-xs font-mono">
                            <div className="flex items-center gap-2">
                              <span className="text-gray-500">MD5:</span>
                              <code>{att.md5}</code>
                              <button
                                onClick={() => copyToClipboard(att.md5, 'md5')}
                                className="text-gray-400 hover:text-gray-600"
                              >
                                <Copy className="w-3 h-3" />
                              </button>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-gray-500">SHA256:</span>
                              <code className="truncate max-w-[200px]">{att.sha256}</code>
                              <button
                                onClick={() => copyToClipboard(att.sha256, 'sha256')}
                                className="text-gray-400 hover:text-gray-600"
                              >
                                <Copy className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>

              {/* Headers */}
              <Section
                id="headers"
                title="Email Headers"
                icon={<Layers className="w-5 h-5 text-gray-600" />}
              >
                <div>
                  <button
                    onClick={() => setShowRawHeaders(!showRawHeaders)}
                    className="flex items-center gap-2 text-sm text-indigo-600 mb-3"
                  >
                    {showRawHeaders ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    {showRawHeaders ? 'Hide Raw Headers' : 'Show Raw Headers'}
                  </button>
                  {showRawHeaders && (
                    <pre className="p-3 bg-gray-900 text-gray-100 rounded-lg text-xs overflow-auto max-h-80">
                      {Object.entries(analysis.email.headers)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join('\n')}
                    </pre>
                  )}
                </div>
              </Section>
            </div>
          )}

          {activeTab === 'enrichment' && (
            <div className="space-y-4">
              {/* GeoIP */}
              {analysis.enrichment.geoip && (
                <Section
                  id="geoip"
                  title="GeoIP Information"
                  icon={<Globe className="w-5 h-5 text-blue-600" />}
                >
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <label className="text-xs text-gray-500">IP Address</label>
                      <div className="font-mono">{analysis.enrichment.geoip.ip}</div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">Country</label>
                      <div>{analysis.enrichment.geoip.country}</div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">City</label>
                      <div>{analysis.enrichment.geoip.city}</div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">ISP</label>
                      <div>{analysis.enrichment.geoip.isp}</div>
                    </div>
                  </div>
                </Section>
              )}

              {/* WHOIS */}
              {analysis.enrichment.whois && (
                <Section
                  id="whois"
                  title="WHOIS Information"
                  icon={<Database className="w-5 h-5 text-green-600" />}
                >
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <label className="text-xs text-gray-500">Registrar</label>
                      <div>{analysis.enrichment.whois.registrar}</div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">Created Date</label>
                      <div>{analysis.enrichment.whois.created_date}</div>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">Domain Age</label>
                      <div
                        className={
                          analysis.enrichment.whois.domain_age_days < 30 ? 'text-red-600 font-bold' : ''
                        }
                      >
                        {analysis.enrichment.whois.domain_age_days} days
                        {analysis.enrichment.whois.domain_age_days < 30 && ' ⚠️ New Domain'}
                      </div>
                    </div>
                  </div>
                </Section>
              )}

              {/* VirusTotal */}
              {analysis.enrichment.virustotal && (
                <Section
                  id="virustotal"
                  title="VirusTotal Results"
                  icon={<Shield className="w-5 h-5 text-red-600" />}
                >
                  <div className="flex items-center gap-6">
                    <div
                      className={`text-3xl font-bold ${
                        analysis.enrichment.virustotal.positives > 0 ? 'text-red-600' : 'text-green-600'
                      }`}
                    >
                      {analysis.enrichment.virustotal.positives}/{analysis.enrichment.virustotal.total}
                    </div>
                    <div className="text-gray-600">
                      {analysis.enrichment.virustotal.positives} security vendors flagged this as malicious
                    </div>
                    <a
                      href={analysis.enrichment.virustotal.permalink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-indigo-600 hover:underline"
                    >
                      View on VirusTotal <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                </Section>
              )}

              {/* AbuseIPDB */}
              {analysis.enrichment.abuseipdb && (
                <Section
                  id="abuseipdb"
                  title="AbuseIPDB Results"
                  icon={<AlertTriangle className="w-5 h-5 text-orange-600" />}
                >
                  <div className="flex items-center gap-6">
                    <div
                      className={`text-3xl font-bold ${
                        analysis.enrichment.abuseipdb.abuse_confidence > 50
                          ? 'text-red-600'
                          : analysis.enrichment.abuseipdb.abuse_confidence > 0
                          ? 'text-orange-600'
                          : 'text-green-600'
                      }`}
                    >
                      {analysis.enrichment.abuseipdb.abuse_confidence}%
                    </div>
                    <div className="text-gray-600">
                      Abuse Confidence Score • {analysis.enrichment.abuseipdb.total_reports} total reports
                    </div>
                  </div>
                </Section>
              )}

              {/* URLhaus */}
              {analysis.enrichment.urlhaus && (
                <Section
                  id="urlhaus"
                  title="URLhaus Results"
                  icon={<Link className="w-5 h-5 text-red-600" />}
                >
                  <div className="flex items-center gap-4">
                    <span className="text-red-600 font-bold">⚠️ Known Malicious URL</span>
                    <span className="bg-red-100 text-red-700 px-2 py-1 rounded">
                      {analysis.enrichment.urlhaus.threat_type}
                    </span>
                    <div className="flex gap-1">
                      {analysis.enrichment.urlhaus.tags.map((tag, idx) => (
                        <span key={idx} className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-sm">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </Section>
              )}

              {/* PhishTank */}
              {analysis.enrichment.phishtank && (
                <Section
                  id="phishtank"
                  title="PhishTank Results"
                  icon={<ShieldX className="w-5 h-5 text-red-600" />}
                >
                  <div className="flex items-center gap-4">
                    <span className="text-red-600 font-bold">🎣 Confirmed Phishing URL</span>
                    <span className="bg-red-100 text-red-700 px-2 py-1 rounded">
                      Phish ID: {analysis.enrichment.phishtank.phish_id}
                    </span>
                    {analysis.enrichment.phishtank.verified && (
                      <span className="bg-red-600 text-white px-2 py-1 rounded">Verified</span>
                    )}
                  </div>
                </Section>
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <div className="bg-white rounded-lg border p-6">
                <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Analysis Timeline
                </h3>
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200" />
                  <div className="space-y-4">
                    {analysis.timeline.map((event, idx) => (
                      <div key={idx} className="relative flex items-start gap-4 pl-10">
                        <div
                          className={`absolute left-2 w-5 h-5 rounded-full flex items-center justify-center ${
                            event.status === 'success'
                              ? 'bg-green-100'
                              : event.status === 'warning'
                              ? 'bg-yellow-100'
                              : event.status === 'error'
                              ? 'bg-red-100'
                              : 'bg-blue-100'
                          }`}
                        >
                          {event.status === 'success' && <CheckCircle className="w-3 h-3 text-green-600" />}
                          {event.status === 'warning' && (
                            <AlertTriangle className="w-3 h-3 text-yellow-600" />
                          )}
                          {event.status === 'error' && <XCircle className="w-3 h-3 text-red-600" />}
                          {event.status === 'info' && <Info className="w-3 h-3 text-blue-600" />}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-gray-500">{event.timestamp}</span>
                          </div>
                          <div className="font-medium text-gray-900">{event.event}</div>
                          {event.details && <div className="text-sm text-gray-600">{event.details}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* SOC Tools Panel */}
      <FullSOCToolsView
        analysisResult={analysis}
        isOpen={showSOCTools}
        onClose={() => setShowSOCTools(false)}
      />
    </div>
  );
};

export default AnalysisView;
