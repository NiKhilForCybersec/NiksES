/**
 * Sandbox Analysis Results Panel
 * 
 * Displays dynamic malware analysis results from Hybrid Analysis sandbox.
 * Shows verdict, threat score, MITRE ATT&CK techniques, IOCs, and behaviors.
 */

import React, { useState } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileWarning,
  Globe,
  Server,
  Link2,
  Activity,
  Cpu,
  Database,
  AlertOctagon,
  HelpCircle,
  Loader2,
  FileX,
  Bug,
  Copy,
  Check
} from 'lucide-react';

// Types
interface SandboxResult {
  provider: string;
  submission_id: string;
  status: string;
  filename?: string;
  file_hash?: string;
  verdict?: string;
  threat_score?: number;
  threat_level?: string;
  malware_families?: string[];
  signatures?: Array<{
    name: string;
    description: string;
    severity?: string;
    category?: string;
  }>;
  mitre_attacks?: Array<{
    tactic: string;
    technique: string;
    attck_id: string;
  }>;
  network_iocs?: {
    domains: string[];
    ips: string[];
    urls: string[];
  };
  file_iocs?: Array<{
    filename: string;
    sha256: string;
    type: string;
    malicious: boolean;
  }>;
  processes?: Array<{
    name: string;
    command_line: string;
    pid: number;
  }>;
  registry_keys?: string[];
  report_url?: string;
  environment?: string;
  error?: string;
}

interface SandboxAnalysis {
  analyzed: boolean;
  reason: string;
  results: SandboxResult[];
  summary: {
    total: number;
    analyzed: number;
    malicious: number;
    suspicious: number;
    clean: number;
    skipped: number;
  };
}

interface SandboxResultsPanelProps {
  sandboxAnalysis?: SandboxAnalysis | null;
  isLoading?: boolean;
}

// Helper to copy text
const useCopyToClipboard = () => {
  const [copied, setCopied] = useState<string | null>(null);
  
  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };
  
  return { copied, copy };
};

// Verdict Badge Component
const VerdictBadge: React.FC<{ verdict?: string; score?: number }> = ({ verdict, score }) => {
  const getVerdictStyle = () => {
    switch (verdict) {
      case 'malicious':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'suspicious':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'clean':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getVerdictIcon = () => {
    switch (verdict) {
      case 'malicious':
        return <XCircle className="w-4 h-4" />;
      case 'suspicious':
        return <AlertTriangle className="w-4 h-4" />;
      case 'clean':
        return <CheckCircle className="w-4 h-4" />;
      default:
        return <HelpCircle className="w-4 h-4" />;
    }
  };

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${getVerdictStyle()}`}>
      {getVerdictIcon()}
      <span className="font-medium capitalize">{verdict || 'Unknown'}</span>
      {score !== undefined && score > 0 && (
        <span className="text-xs opacity-70">({score}/100)</span>
      )}
    </div>
  );
};

// Threat Score Bar Component
const ThreatScoreBar: React.FC<{ score: number }> = ({ score }) => {
  const getColor = () => {
    if (score >= 70) return 'bg-red-500';
    if (score >= 40) return 'bg-yellow-500';
    if (score >= 10) return 'bg-blue-500';
    return 'bg-green-500';
  };

  return (
    <div className="w-full">
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-400">Threat Score</span>
        <span className="font-mono font-medium text-white">{score}/100</span>
      </div>
      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${getColor()}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
};

// Expandable Section Component
const ExpandableSection: React.FC<{
  title: string;
  icon: React.ReactNode;
  count?: number;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}> = ({ title, icon, count, children, defaultExpanded = false }) => {
  const [expanded, setExpanded] = useState(defaultExpanded);

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 bg-gray-800/50 hover:bg-gray-700/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          {icon}
          <span className="font-medium text-gray-200">{title}</span>
          {count !== undefined && count > 0 && (
            <span className="px-2 py-0.5 text-xs bg-gray-700 rounded-full text-gray-300">
              {count}
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-gray-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-400" />
        )}
      </button>
      {expanded && <div className="p-3 bg-gray-900/50">{children}</div>}
    </div>
  );
};

// Single File Result Card
const FileResultCard: React.FC<{ result: SandboxResult }> = ({ result }) => {
  const [expanded, setExpanded] = useState(false);
  const { copied, copy } = useCopyToClipboard();

  // Skipped file
  if (result.status === 'skipped') {
    return (
      <div className="border border-gray-700 rounded-lg p-4 bg-gray-800/30">
        <div className="flex items-center gap-3">
          <FileX className="w-5 h-5 text-gray-500" />
          <div>
            <p className="font-medium text-gray-300">{result.filename || 'Unknown file'}</p>
            <p className="text-sm text-gray-500">{result.error || 'Skipped - not suitable for analysis'}</p>
          </div>
        </div>
      </div>
    );
  }

  // Pending/Running
  if (result.status === 'submitted' || result.status === 'pending' || result.status === 'running') {
    return (
      <div className="border border-blue-500/30 rounded-lg p-4 bg-blue-500/10">
        <div className="flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
          <div className="flex-1">
            <p className="font-medium text-gray-200">{result.filename || 'File'}</p>
            <p className="text-sm text-blue-400">Analysis in progress...</p>
          </div>
          {result.report_url && (
            <a
              href={result.report_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300"
            >
              View Progress <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      </div>
    );
  }

  // Error
  if (result.status === 'error' || result.status === 'not_configured') {
    return (
      <div className="border border-red-500/30 rounded-lg p-4 bg-red-500/10">
        <div className="flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 text-red-400" />
          <div>
            <p className="font-medium text-gray-200">{result.filename || 'File'}</p>
            <p className="text-sm text-red-400">{result.error || 'Analysis failed'}</p>
          </div>
        </div>
      </div>
    );
  }

  // Completed analysis
  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="p-4 bg-gray-800/50 cursor-pointer hover:bg-gray-700/50 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileWarning className={`w-5 h-5 ${
              result.verdict === 'malicious' ? 'text-red-400' :
              result.verdict === 'suspicious' ? 'text-yellow-400' :
              'text-green-400'
            }`} />
            <div>
              <p className="font-medium text-gray-200">{result.filename || 'Unknown file'}</p>
              {result.file_hash && (
                <div className="flex items-center gap-1">
                  <p className="text-xs text-gray-500 font-mono">{result.file_hash.substring(0, 16)}...</p>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copy(result.file_hash!, 'hash');
                    }}
                    className="text-gray-500 hover:text-gray-300"
                  >
                    {copied === 'hash' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <VerdictBadge verdict={result.verdict} score={result.threat_score} />
            {expanded ? (
              <ChevronUp className="w-4 h-4 text-gray-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-gray-400" />
            )}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="flex flex-wrap gap-4 mt-3 text-sm">
          {result.malware_families && result.malware_families.length > 0 && (
            <span className="text-red-400">
              <Bug className="w-3 h-3 inline mr-1" />
              {result.malware_families.join(', ')}
            </span>
          )}
          {result.mitre_attacks && result.mitre_attacks.length > 0 && (
            <span className="text-orange-400">
              <Shield className="w-3 h-3 inline mr-1" />
              {result.mitre_attacks.length} MITRE techniques
            </span>
          )}
          {result.network_iocs && (
            (result.network_iocs.domains?.length > 0 || result.network_iocs.ips?.length > 0) && (
              <span className="text-blue-400">
                <Globe className="w-3 h-3 inline mr-1" />
                {(result.network_iocs.domains?.length || 0) + (result.network_iocs.ips?.length || 0)} network IOCs
              </span>
            )
          )}
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="p-4 space-y-4 bg-gray-900/50">
          {/* Threat Score */}
          {result.threat_score !== undefined && (
            <ThreatScoreBar score={result.threat_score} />
          )}

          {/* Malware Families */}
          {result.malware_families && result.malware_families.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Malware Families</h4>
              <div className="flex flex-wrap gap-2">
                {result.malware_families.map((family, i) => (
                  <span key={i} className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm">
                    {family}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {result.mitre_attacks && result.mitre_attacks.length > 0 && (
            <ExpandableSection
              title="MITRE ATT&CK Techniques"
              icon={<Shield className="w-4 h-4 text-orange-400" />}
              count={result.mitre_attacks.length}
              defaultExpanded={true}
            >
              <div className="space-y-2">
                {result.mitre_attacks.map((attack, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <a
                      href={`https://attack.mitre.org/techniques/${attack.attck_id.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded font-mono text-xs hover:bg-orange-500/30"
                    >
                      {attack.attck_id}
                    </a>
                    <span className="text-gray-300">{attack.technique}</span>
                    <span className="text-gray-500">({attack.tactic})</span>
                  </div>
                ))}
              </div>
            </ExpandableSection>
          )}

          {/* Signatures */}
          {result.signatures && result.signatures.length > 0 && (
            <ExpandableSection
              title="Behavioral Signatures"
              icon={<Activity className="w-4 h-4 text-purple-400" />}
              count={result.signatures.length}
            >
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {result.signatures.map((sig, i) => (
                  <div key={i} className="p-2 bg-gray-800/50 rounded text-sm">
                    <p className="font-medium text-gray-200">{sig.name}</p>
                    {sig.description && (
                      <p className="text-gray-400 text-xs mt-1">{sig.description}</p>
                    )}
                  </div>
                ))}
              </div>
            </ExpandableSection>
          )}

          {/* Network IOCs */}
          {result.network_iocs && (
            (result.network_iocs.domains?.length > 0 || 
             result.network_iocs.ips?.length > 0 ||
             result.network_iocs.urls?.length > 0) && (
              <ExpandableSection
                title="Network IOCs"
                icon={<Globe className="w-4 h-4 text-blue-400" />}
                count={
                  (result.network_iocs.domains?.length || 0) +
                  (result.network_iocs.ips?.length || 0) +
                  (result.network_iocs.urls?.length || 0)
                }
              >
                <div className="space-y-3">
                  {result.network_iocs.domains && result.network_iocs.domains.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                        <Globe className="w-3 h-3" /> Domains
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {result.network_iocs.domains.map((domain, i) => (
                          <code key={i} className="px-2 py-0.5 bg-gray-800 rounded text-xs text-gray-300">
                            {domain}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.network_iocs.ips && result.network_iocs.ips.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                        <Server className="w-3 h-3" /> IP Addresses
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {result.network_iocs.ips.map((ip, i) => (
                          <code key={i} className="px-2 py-0.5 bg-gray-800 rounded text-xs text-gray-300">
                            {ip}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.network_iocs.urls && result.network_iocs.urls.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                        <Link2 className="w-3 h-3" /> URLs
                      </p>
                      <div className="space-y-1 max-h-32 overflow-y-auto">
                        {result.network_iocs.urls.slice(0, 10).map((url, i) => (
                          <code key={i} className="block px-2 py-0.5 bg-gray-800 rounded text-xs text-gray-300 truncate">
                            {url}
                          </code>
                        ))}
                        {result.network_iocs.urls.length > 10 && (
                          <p className="text-xs text-gray-500">
                            +{result.network_iocs.urls.length - 10} more
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </ExpandableSection>
            )
          )}

          {/* Dropped Files */}
          {result.file_iocs && result.file_iocs.length > 0 && (
            <ExpandableSection
              title="Dropped Files"
              icon={<FileWarning className="w-4 h-4 text-red-400" />}
              count={result.file_iocs.length}
            >
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {result.file_iocs.map((file, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 bg-gray-800/50 rounded">
                    <FileWarning className={`w-4 h-4 ${file.malicious ? 'text-red-400' : 'text-gray-400'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-gray-200 truncate">{file.filename}</p>
                      <p className="text-xs text-gray-500 font-mono truncate">{file.sha256}</p>
                    </div>
                    {file.malicious && (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                        Malicious
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </ExpandableSection>
          )}

          {/* Processes */}
          {result.processes && result.processes.length > 0 && (
            <ExpandableSection
              title="Process Activity"
              icon={<Cpu className="w-4 h-4 text-cyan-400" />}
              count={result.processes.length}
            >
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {result.processes.map((proc, i) => (
                  <div key={i} className="p-2 bg-gray-800/50 rounded">
                    <p className="text-sm text-gray-200">{proc.name} (PID: {proc.pid})</p>
                    {proc.command_line && (
                      <code className="block text-xs text-gray-400 mt-1 truncate">
                        {proc.command_line}
                      </code>
                    )}
                  </div>
                ))}
              </div>
            </ExpandableSection>
          )}

          {/* Registry Keys */}
          {result.registry_keys && result.registry_keys.length > 0 && (
            <ExpandableSection
              title="Registry Modifications"
              icon={<Database className="w-4 h-4 text-yellow-400" />}
              count={result.registry_keys.length}
            >
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {result.registry_keys.map((key, i) => (
                  <code key={i} className="block text-xs text-gray-400 p-1 bg-gray-800/50 rounded truncate">
                    {key}
                  </code>
                ))}
              </div>
            </ExpandableSection>
          )}

          {/* Report Link */}
          {result.report_url && (
            <div className="pt-2 border-t border-gray-700">
              <a
                href={result.report_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-blue-400 hover:text-blue-300 text-sm"
              >
                <ExternalLink className="w-4 h-4" />
                View Full Report on Hybrid Analysis
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Main Component
const SandboxResultsPanel: React.FC<SandboxResultsPanelProps> = ({
  sandboxAnalysis,
  isLoading = false
}) => {
  // Loading state
  if (isLoading) {
    return (
      <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-semibold text-gray-200">Sandbox Analysis</h3>
        </div>
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
          <span className="ml-2 text-gray-400">Running dynamic analysis...</span>
        </div>
      </div>
    );
  }

  // No sandbox data
  if (!sandboxAnalysis) {
    return null;
  }

  // Not configured
  if (!sandboxAnalysis.analyzed && sandboxAnalysis.reason === 'sandbox_not_configured') {
    return (
      <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-gray-500" />
          <h3 className="text-lg font-semibold text-gray-200">Sandbox Analysis</h3>
          <span className="px-2 py-0.5 bg-gray-700 text-gray-400 rounded text-xs">Not Configured</span>
        </div>
        <p className="text-gray-400 text-sm">
          Dynamic malware analysis is not configured. Add your Hybrid Analysis API key in Settings → Threat Intel to enable sandbox analysis of attachments.
        </p>
        <a 
          href="https://www.hybrid-analysis.com/apikeys/info" 
          target="_blank" 
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 mt-3 text-sm text-blue-400 hover:text-blue-300"
        >
          Get free API key <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    );
  }

  // No attachments
  if (!sandboxAnalysis.analyzed && sandboxAnalysis.reason === 'no_attachments') {
    return (
      <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-gray-500" />
          <h3 className="text-lg font-semibold text-gray-200">Sandbox Analysis</h3>
        </div>
        <p className="text-gray-400 text-sm">
          No attachments to analyze. Sandbox analysis is performed on email attachments like executables, documents, and archives.
        </p>
      </div>
    );
  }

  const { results, summary } = sandboxAnalysis;

  return (
    <div className="bg-gray-800/50 rounded-xl p-6 border border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-semibold text-gray-200">Sandbox Analysis</h3>
          <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">
            Hybrid Analysis
          </span>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-5 gap-3 mb-4">
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-gray-200">{summary.total}</p>
          <p className="text-xs text-gray-500">Total</p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-blue-400">{summary.analyzed}</p>
          <p className="text-xs text-gray-500">Analyzed</p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-red-400">{summary.malicious}</p>
          <p className="text-xs text-gray-500">Malicious</p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-yellow-400">{summary.suspicious}</p>
          <p className="text-xs text-gray-500">Suspicious</p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-green-400">{summary.clean}</p>
          <p className="text-xs text-gray-500">Clean</p>
        </div>
      </div>

      {/* Results List */}
      {results && results.length > 0 && (
        <div className="space-y-3">
          {results.map((result, index) => (
            <FileResultCard key={index} result={result} />
          ))}
        </div>
      )}
    </div>
  );
};

export default SandboxResultsPanel;
export { SandboxResultsPanel, VerdictBadge, ThreatScoreBar };
export type { SandboxResult, SandboxAnalysis };
