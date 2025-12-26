/**
 * NiksES Main Application Component
 * 
 * Root component with Dashboard, Analysis Progress, and Detailed Results.
 */

import { useState, useCallback, useEffect } from 'react';
import { Toaster, toast } from 'react-hot-toast';
import { 
  Upload, AlertTriangle, Shield, 
  Settings, RefreshCw,
  AlertCircle, CheckCircle, XCircle, Info,
  BookOpen, LayoutDashboard, Mail,
  Paperclip, Link, Key, Database,
  Target, Brain, Zap, Smartphone, MessageSquare
} from 'lucide-react';
import { apiClient } from './services/api';
import AdvancedRulesManager from './components/rules/AdvancedRulesManager';
import Dashboard from './components/dashboard/Dashboard';
import AdvancedAnalysisView from './components/analysis/AdvancedAnalysisView';
import AnalysisProgress, { 
  AnalysisStep, 
  createAnalysisSteps 
} from './components/analysis/AnalysisProgress';
import ResultsPanel from './components/analysis/ResultsPanel';
import { SettingsModal, APIStatusIndicator, APISetupBanner, SettingsState } from './components/settings';
import HistoryPanel from './components/history/HistoryPanel';
import { FullSOCToolsView } from './components/soc-tools';

// Types
interface AnalysisResult {
  analysis_id: string;
  analyzed_at: string;
  analysis_duration_ms: number;
  email: {
    message_id?: string;
    subject?: string;
    sender?: {
      raw?: string;
      email: string;
      display_name?: string;
      domain?: string;
    };
    recipients?: {
      to?: string[];
      cc?: string[];
      bcc?: string[];
    };
    reply_to?: string;
    date?: string;
    body_text?: string;
    body_html?: string;
    headers?: Record<string, string>;
    urls: any[];
    attachments: any[];
  };
  authentication?: {
    spf?: { result: string; details?: string };
    dkim?: { result: string; details?: string };
    dmarc?: { result: string; details?: string };
  };
  detection: {
    risk_score: number;
    risk_level: string;
    verdict?: string;
    primary_classification: string;
    confidence: number;
    rules_triggered: any[];
  };
  enrichment?: {
    geoip?: any;
    whois?: any;
    virustotal?: any;
    abuseipdb?: any;
    urlhaus?: any;
    phishtank?: any;
    dns?: any;
  };
  ai_triage?: {
    enabled?: boolean;
    provider?: string;
    summary: string;
    key_findings?: string[];
    recommendations?: string[];
    recommended_actions: any[];
    mitre_techniques?: any[];
  };
  ai_analysis?: {
    enabled?: boolean;
    provider?: string;
    summary?: string;
    key_findings?: string[];
    recommendations?: string[];
    mitre_techniques?: any[];
  } | null;
  iocs: {
    domains: string[];
    urls: string[];
    ips: string[];
    email_addresses: string[];
    file_hashes_sha256: string[];
    hashes?: { type: string; value: string }[];
  };
  timeline?: any[];
  // Top-level convenience fields (may be populated by API)
  risk_level?: string;
  risk_score?: number;
  classification?: string;
  verdict?: string;
  critical_findings?: number;
  // Orchestrator unified scores (these are the authoritative scores)
  overall_score?: number;
  overall_level?: string;
}

// Extract numeric score from risk_score (can be number or MultiDimensionalRiskScore object)
const extractScore = (score: any): number => {
  if (typeof score === 'number') return score;
  if (score && typeof score === 'object' && 'overall_score' in score) return score.overall_score;
  return 0;
};

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [enhancedResult, setEnhancedResult] = useState<any | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [dashboardOpen, setDashboardOpen] = useState(false);
  const [fullAnalysisOpen, setFullAnalysisOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [socToolsOpen, setSocToolsOpen] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [debugMode, setDebugMode] = useState(false);
  const [globalSettings, setGlobalSettings] = useState<SettingsState | null>(null);

  // SMS/Text analysis state
  const [inputType, setInputType] = useState<'email' | 'sms'>('email');
  const [textMessage, setTextMessage] = useState('');
  const [textSource, setTextSource] = useState<'sms' | 'whatsapp' | 'telegram' | 'other'>('sms');

  // Load initial settings
  useEffect(() => {
    const loadInitialSettings = async () => {
      try {
        const response = await apiClient.get('/settings');
        setGlobalSettings(response.data);
      } catch (error) {
        console.error('Failed to load initial settings:', error);
      }
    };
    loadInitialSettings();
  }, []);

  // Debug logging
  console.log('App render - result:', result ? 'present' : 'null');
  console.log('App render - enhancedResult:', enhancedResult ? 'present' : 'null');

  
  // Analysis progress state
  const [analysisSteps, setAnalysisSteps] = useState<AnalysisStep[]>(createAnalysisSteps());
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [showProgress, setShowProgress] = useState(false);

  // Handle file drop
  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.name.endsWith('.eml') || droppedFile.name.endsWith('.msg')) {
        setFile(droppedFile);
        setResult(null);
        setAnalysisComplete(false);
        setAnalysisSteps(createAnalysisSteps());
      } else {
        toast.error('Please upload a .eml or .msg file');
      }
    }
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setAnalysisComplete(false);
      setAnalysisSteps(createAnalysisSteps());
    }
  }, []);

  // Simulate analysis progress
  const simulateProgress = () => {
    const stepUpdates = [
      { id: 'parse', delay: 300 },
      { id: 'urls', delay: 400 },
      { id: 'attachments', delay: 350 },
      { id: 'auth', delay: 300 },
      { id: 'enrichment', delay: 800 },
      { id: 'geoip', delay: 250 },
      { id: 'detection', delay: 500 },
      { id: 'scoring', delay: 200 },
      { id: 'ai', delay: 1000 },
      { id: 'report', delay: 200 },
    ];

    let totalDelay = 0;
    stepUpdates.forEach((update) => {
      setTimeout(() => {
        setAnalysisSteps((prev) =>
          prev.map((step) =>
            step.id === update.id ? { ...step, status: 'running' as const } : step
          )
        );
      }, totalDelay);

      totalDelay += update.delay;

      setTimeout(() => {
        setAnalysisSteps((prev) =>
          prev.map((step) =>
            step.id === update.id
              ? { ...step, status: 'success' as const, duration: update.delay }
              : step
          )
        );
      }, totalDelay);
    });

    return totalDelay;
  };

  // Analyze email
  const analyzeEmail = async () => {
    if (!file) {
      toast.error('Please select a file first');
      return;
    }

    setLoading(true);
    setShowProgress(true);
    setResult(null);
    setEnhancedResult(null);
    setAnalysisComplete(false);
    setAnalysisSteps(createAnalysisSteps());

    const progressDuration = simulateProgress();

    const formData = new FormData();
    formData.append('file', file);
    formData.append('enable_enrichment', 'true');
    formData.append('enable_ai', 'true');

    try {
      // Always use the unified analysis endpoint
      const response = await apiClient.post('/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      const data = response.data;
      
      // Log response for debugging
      console.log('=== ANALYSIS RESPONSE DEBUG ===');
      console.log('Full response:', JSON.stringify(data, null, 2).slice(0, 1000));
      console.log('Response keys:', Object.keys(data));
      console.log('email:', data.email ? 'present' : 'MISSING');
      console.log('email keys:', data.email ? Object.keys(data.email) : 'N/A');
      console.log('detection:', data.detection ? 'present' : 'MISSING');
      console.log('detection keys:', data.detection ? Object.keys(data.detection) : 'N/A');
      console.log('iocs:', data.iocs ? 'present' : 'MISSING');
      console.log('iocs keys:', data.iocs ? Object.keys(data.iocs) : 'N/A');
      console.log('ai_triage:', data.ai_triage ? 'present' : 'not present');
      console.log('=== END DEBUG ===');
      
      setTimeout(() => {
        try {
          // Validate required fields exist
          if (!data) {
            throw new Error('Empty response from server');
          }
          
          // Unified analysis returns all data in one response
          setEnhancedResult(data);
          
          // Build detection object with proper fallbacks
          // IMPORTANT: Use orchestrator's overall_score as primary (it applies false positive suppression)
          // Detection engine's risk_score is just one component, not the final verdict
          const detectionData = data.detection || data.detection_results || {};
          const detection = {
            ...detectionData,
            // Priority: orchestrator overall_score > risk_score object > detection risk_score
            risk_score: data.overall_score ?? extractScore(data.risk_score) ?? detectionData.risk_score ?? 0,
            risk_level: data.overall_level ?? detectionData.risk_level ?? 'unknown',
            primary_classification: data.classification ?? detectionData.primary_classification ?? 'unknown',
            confidence: detectionData.confidence ?? 0.5,
            rules_triggered: detectionData.rules_triggered || [],
          };
          
          // Ensure email object exists
          const email = data.email || data.parsed_email || {};
          
          // Ensure iocs object exists
          const iocs = data.iocs || {
            domains: [],
            urls: [],
            ips: [],
            email_addresses: [],
            file_hashes_sha256: [],
          };
          
          // Set result for compatibility with existing UI components
          const processedResult = {
            ...data,
            email,
            detection,
            iocs,
          };
          
          console.log('=== PROCESSED RESULT DEBUG ===');
          console.log('Processed result keys:', Object.keys(processedResult));
          console.log('Processed email:', processedResult.email ? Object.keys(processedResult.email) : 'N/A');
          console.log('Processed detection:', processedResult.detection);
          console.log('Processed iocs:', processedResult.iocs);
          console.log('=== END PROCESSED DEBUG ===');
          
          setResult(processedResult);
          
          setAnalysisComplete(true);
          toast.success('Analysis complete!');
        } catch (err) {
          console.error('Error processing analysis result:', err);
          toast.error('Error displaying results: ' + (err instanceof Error ? err.message : 'Unknown error'));
        }
      }, Math.max(0, progressDuration - 500));

    } catch (error: any) {
      setAnalysisSteps((prev) =>
        prev.map((step) =>
          step.status === 'running' || step.status === 'pending'
            ? { ...step, status: 'error' as const }
            : step
        )
      );
      toast.error(error.message || 'Failed to analyze email');
      console.error('Analysis error:', error);
    } finally {
      setTimeout(() => {
        setLoading(false);
      }, progressDuration);
    }
  };

  // Analyze text/SMS message
  const analyzeText = async () => {
    if (!textMessage.trim()) {
      toast.error('Please enter a message to analyze');
      return;
    }

    setLoading(true);
    setResult(null);
    setEnhancedResult(null);
    setAnalysisComplete(false);
    setShowProgress(true);

    // Simplified progress for text analysis (faster)
    const textSteps = [
      { id: 'parse', delay: 100 },
      { id: 'urls', delay: 150 },
      { id: 'detection', delay: 200 },
      { id: 'scoring', delay: 100 },
    ];

    let totalDelay = 0;
    textSteps.forEach((update) => {
      setTimeout(() => {
        setAnalysisSteps((prev) =>
          prev.map((step) =>
            step.id === update.id ? { ...step, status: 'running' as const } : step
          )
        );
      }, totalDelay);
      totalDelay += update.delay;
      setTimeout(() => {
        setAnalysisSteps((prev) =>
          prev.map((step) =>
            step.id === update.id ? { ...step, status: 'success' as const, duration: update.delay } : step
          )
        );
      }, totalDelay);
    });

    try {
      console.log('=== SENDING TEXT ANALYSIS REQUEST ===');
      const response = await apiClient.post('/analyze/text', {
        text: textMessage,
        sender: '',
        source: textSource,
      });

      console.log('=== TEXT ANALYSIS RESPONSE ===');
      console.log(JSON.stringify(response.data, null, 2));

      // Convert text analysis result to email-like structure for display
      const textResult = response.data;
      const pseudoEmailResult: AnalysisResult = {
        analysis_id: textResult.analysis_id,
        analyzed_at: textResult.analyzed_at,
        analysis_duration_ms: 500,
        email: {
          subject: `${textSource.toUpperCase()} Message Analysis`,
          sender: { email: 'unknown@sms', display_name: 'SMS Sender', domain: 'sms' },
          recipients: { to: ['recipient@unknown'] },
          body_text: textMessage,
          urls: textResult.urls_found?.map((url: string) => ({ url, display_text: url })) || [],
          attachments: [],
        },
        authentication: {},
        detection: {
          risk_score: textResult.overall_score,
          risk_level: textResult.overall_level,
          verdict: textResult.is_likely_scam ? 'malicious' : 'clean',
          primary_classification: textResult.classification,
          confidence: textResult.confidence,
          rules_triggered: textResult.scam_patterns_matched?.map((p: any) => ({
            rule_id: p.pattern_id,
            name: p.name,
            description: p.description,
            severity: p.severity,
            category: 'smishing',
          })) || [],
        },
        iocs: {
          domains: [],
          urls: textResult.urls_found || [],
          ips: [],
          email_addresses: [],
          file_hashes_sha256: [],
        },
        ai_triage: {
          enabled: true,
          provider: 'pattern-matching',
          summary: textResult.is_likely_scam 
            ? `This ${textSource.toUpperCase()} message shows signs of a ${textResult.classification.replace('smishing_', '').replace('_', ' ')} scam.`
            : 'This message appears to be legitimate.',
          key_findings: textResult.indicators || [],
          recommendations: textResult.recommendations || [],
          recommended_actions: [],
        },
      };

      setResult(pseudoEmailResult);
      setEnhancedResult(pseudoEmailResult);
      setAnalysisComplete(true);
      toast.success('Text analysis complete!');

    } catch (error: any) {
      console.error('Text analysis error:', error);
      toast.error(error.response?.data?.detail || 'Failed to analyze text');
    } finally {
      setLoading(false);
    }
  };

  // Export results
  const exportResults = async (format: string) => {
    if (!result) return;

    try {
      const response = await apiClient.get(
        `/export/${result.analysis_id}/${format}`,
        { responseType: 'blob' }
      );
      
      const blob = response.data;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      // Determine file extension based on format
      const extensionMap: Record<string, string> = {
        'json': 'json',
        'markdown': 'md',
        'pdf': 'pdf',
        'executive-pdf': 'pdf',
        'summary-pdf': 'pdf',
        'stix': 'json',
        'iocs': 'txt',
        'rules': 'json',
      };
      const extension = extensionMap[format] || format;
      const prefix = format.includes('pdf') ? format.replace('-pdf', '_report') : format;
      a.download = `analysis_${result.analysis_id}_${prefix}.${extension}`;
      
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Export failed');
    }
  };

  // View analysis from dashboard
  const handleViewAnalysis = (analysisId: string) => {
    setDashboardOpen(false);
    setFullAnalysisOpen(true);
  };

  // Transform result for components
  const getTransformedResult = () => {
    if (!result) return null;
    
    try {
      // Defensive checks for nested objects
      const email = result.email || {};
      const detection = result.detection || {};
      const iocs = result.iocs || {};
      
      // Extract numeric score from risk_score (can be number or MultiDimensionalRiskScore object)
      const extractScore = (score: any): number => {
        if (typeof score === 'number') return score;
        if (score && typeof score === 'object' && 'overall_score' in score) return score.overall_score;
        return 0;
      };
      
      // Normalize risk_level to lowercase for comparison
      // Priority: orchestrator overall_level > detection risk_level
      const riskLevel = String(result.overall_level || detection.risk_level || 'unknown').toLowerCase();
      
      // Safe array extraction
      const safeArray = (val: any) => Array.isArray(val) ? val : [];
      
      const transformed = {
        ...result,
        analysis_id: result.analysis_id || 'unknown',
        analyzed_at: result.analyzed_at || new Date().toISOString(),
        analysis_duration_ms: result.analysis_duration_ms || 0,
        email: {
          ...email,
          subject: email.subject || '(No Subject)',
          sender: email.sender || { email: 'unknown' },
          urls: safeArray(email.urls),
          attachments: safeArray(email.attachments),
        },
        detection: {
          ...detection,
          // Use orchestrator's overall_score as primary source of truth
          risk_score: extractScore(result.overall_score) || extractScore(result.risk_score) || extractScore(detection.risk_score) || 0,
          risk_level: riskLevel,
          verdict: riskLevel === 'critical' || riskLevel === 'high' 
            ? 'malicious' 
            : riskLevel === 'medium' 
              ? 'suspicious' 
              : 'clean',
          rules_triggered: safeArray(detection.rules_triggered),
        },
        urls: safeArray(email.urls),
        attachments: safeArray(email.attachments),
        authentication: result.authentication || {
          spf: { result: 'none', details: 'Not checked' },
          dkim: { result: 'none', details: 'Not checked' },
          dmarc: { result: 'none', details: 'Not checked' },
        },
        ai_analysis: result.ai_triage ? {
          enabled: true,
          provider: 'Claude',
          summary: result.ai_triage.summary || '',
          key_findings: safeArray(result.ai_triage.key_findings),
          recommendations: safeArray(result.ai_triage.recommendations) ||
            safeArray(result.ai_triage.recommended_actions).map((a: any) => 
              typeof a === 'string' ? a : (a?.description || a?.action || '')
            ),
          mitre_techniques: safeArray(result.ai_triage.mitre_techniques),
        } : null,
        iocs: {
          domains: safeArray(iocs.domains),
          ips: safeArray(iocs.ips),
          urls: safeArray(iocs.urls),
          hashes: safeArray(iocs.file_hashes_sha256).map((h: string) => ({ type: 'SHA256', value: h })).concat(
            safeArray(iocs.hashes)
          ),
          emails: safeArray(iocs.email_addresses),
        },
      };
      
      console.log('getTransformedResult success:', transformed);
      return transformed;
    } catch (err) {
      console.error('getTransformedResult error:', err);
      // Return a safe fallback
      return {
        ...result,
        email: result?.email || {},
        detection: result?.detection || { risk_score: 0, risk_level: 'unknown', verdict: 'unknown', rules_triggered: [] },
        iocs: { domains: [], ips: [], urls: [], hashes: [], emails: [] },
      };
    }
  };

  // Create full analysis for view
  const getFullAnalysis = () => {
    const transformed = getTransformedResult();
    if (!transformed) return null;

    return {
      id: result?.analysis_id || '',
      filename: file?.name || 'unknown.eml',
      analyzed_at: result?.analyzed_at || new Date().toISOString(),
      email: {
        message_id: result?.email.message_id || '',
        subject: result?.email.subject || '',
        sender: {
          raw: result?.email.sender?.raw || '',
          display_name: result?.email.sender?.display_name || '',
          email: result?.email.sender?.email || '',
          domain: result?.email.sender?.domain || '',
        },
        recipients: {
          to: result?.email.recipients?.to || [],
          cc: result?.email.recipients?.cc || [],
          bcc: result?.email.recipients?.bcc || [],
        },
        reply_to: result?.email.reply_to || null,
        date: result?.email.date || '',
        body_text: result?.email.body_text || '',
        body_html: result?.email.body_html || '',
        headers: result?.email.headers || {},
      },
      authentication: transformed.authentication,
      urls: (result?.email.urls || []).map((url: any) => ({
        url: typeof url === 'string' ? url : url.url,
        domain: typeof url === 'string' ? '' : url.domain,
        is_shortened: url.is_shortened || false,
        is_suspicious: url.is_suspicious || url.suspicious || false,
        threat_info: url.threat_info,
      })),
      attachments: (result?.email.attachments || []).map((att: any) => ({
        filename: att.filename || att.name,
        content_type: att.content_type || att.mime_type,
        size: att.size || 0,
        md5: att.md5 || att.hashes?.md5 || '',
        sha256: att.sha256 || att.hashes?.sha256 || '',
        is_executable: att.is_executable || false,
        is_macro_enabled: att.is_macro_enabled || att.has_macros || false,
        has_double_extension: att.has_double_extension || false,
        threat_info: att.threat_info,
      })),
      enrichment: result?.enrichment || {},
      detection: {
        rules_triggered: (transformed?.detection?.rules_triggered || []).map((rule: any) => ({
          rule_id: rule.rule_id,
          name: rule.rule_name || rule.name,
          description: rule.description || '',
          category: rule.category || 'unknown',
          severity: rule.severity || 'medium',
          mitre_technique: rule.mitre_technique,
          is_custom: rule.rule_id?.startsWith('CUSTOM') || false,
        })),
        // Use transformed values which have correct orchestrator scores
        risk_score: transformed?.detection?.risk_score || 0,
        risk_level: String(transformed?.detection?.risk_level || 'UNKNOWN'),
        verdict: transformed?.detection?.verdict || 'unknown',
      },
      ai_analysis: transformed.ai_analysis,
      iocs: transformed.iocs,
      timeline: [
        { timestamp: '0ms', event: 'Email parsed', status: 'success' as const },
        { timestamp: '100ms', event: 'URLs extracted', status: 'success' as const, details: `Found ${result?.email?.urls?.length || 0} URLs` },
        { timestamp: '200ms', event: 'Attachments processed', status: 'success' as const, details: `Found ${result?.email?.attachments?.length || 0} attachments` },
        { timestamp: '350ms', event: 'Authentication checked', status: 'success' as const },
        { timestamp: '500ms', event: 'Threat intelligence queries', status: 'success' as const },
        { timestamp: '800ms', event: 'Detection rules evaluated', status: 'success' as const, details: `${transformed?.detection?.rules_triggered?.length || 0} rules triggered` },
        { timestamp: '1000ms', event: 'Risk score calculated', status: 'success' as const, details: `Score: ${transformed?.detection?.risk_score || 0}/100` },
        { timestamp: '2000ms', event: 'AI analysis completed', status: result?.ai_triage ? 'success' as const : 'info' as const },
        { timestamp: `${result?.analysis_duration_ms || 0}ms`, event: 'Analysis complete', status: 'success' as const },
      ],
    };
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      <Toaster position="top-right" />

      {/* Header */}
      <header className="h-16 bg-slate-800 border-b border-slate-700 flex items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold">NiksES</h1>
            <p className="text-xs text-slate-400">Email & SMS Security Analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* API Status Indicator */}
          <APIStatusIndicator
            settings={globalSettings}
            onOpenSettings={() => setSettingsOpen(true)}
          />
          
          <div className="w-px h-8 bg-slate-700 mx-1" />
          
          <button
            onClick={() => setDashboardOpen(true)}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg transition flex items-center gap-2"
          >
            <LayoutDashboard className="w-4 h-4" />
            <span className="text-sm">Dashboard</span>
          </button>
          <button
            onClick={() => setHistoryOpen(true)}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition flex items-center gap-2"
          >
            <Database className="w-4 h-4 text-green-400" />
            <span className="text-sm">History</span>
          </button>
          {result && (
            <button
              onClick={() => setSocToolsOpen(true)}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg transition flex items-center gap-2 animate-pulse"
            >
              <Target className="w-4 h-4" />
              <span className="text-sm">SOC Tools</span>
            </button>
          )}
          <button
            onClick={() => setRulesOpen(true)}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition flex items-center gap-2"
          >
            <BookOpen className="w-4 h-4 text-blue-400" />
            <span className="text-sm">Custom Rules</span>
          </button>
          <button
            onClick={() => setSettingsOpen(true)}
            className="p-2 hover:bg-slate-700 rounded-lg transition"
            title="Settings"
          >
            <Settings className="w-5 h-5 text-slate-400" />
          </button>
          <button
            onClick={() => setDebugMode(!debugMode)}
            className={`p-2 rounded-lg transition text-xs ${debugMode ? 'bg-yellow-600' : 'hover:bg-slate-700'}`}
            title="Toggle Debug Mode"
          >
            🐛
          </button>
        </div>
      </header>

      {/* Debug Panel */}
      {debugMode && (
        <div className="bg-yellow-900/50 border-b border-yellow-600 px-6 py-2 text-xs font-mono">
          <div className="max-w-7xl mx-auto flex flex-wrap gap-4 text-yellow-200">
            <span>result: {result ? '✓' : '✗'}</span>
            <span>enhancedResult: {enhancedResult ? '✓' : '✗'}</span>
            <span>loading: {loading ? 'yes' : 'no'}</span>
            <span>analysisComplete: {analysisComplete ? 'yes' : 'no'}</span>
            {result && (
              <>
                <span>email: {result.email ? '✓' : '✗'}</span>
                <span>detection: {result.detection ? '✓' : '✗'}</span>
                <span>iocs: {result.iocs ? '✓' : '✗'}</span>
              </>
            )}
          </div>
          {result && (
            <details className="mt-2">
              <summary className="cursor-pointer text-yellow-300">Show Raw Result</summary>
              <pre className="mt-1 max-h-40 overflow-auto text-yellow-100 bg-black/30 p-2 rounded">
                {JSON.stringify(result, null, 2).slice(0, 2000)}
              </pre>
            </details>
          )}
        </div>
      )}

      {/* API Setup Banner */}
      {globalSettings && (
        <APISetupBanner
          configuredCount={Object.values(globalSettings.api_keys_configured).filter(Boolean).length}
          totalCount={6}
          onOpenSettings={() => setSettingsOpen(true)}
        />
      )}

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Panel - Upload & Progress */}
          <div className="space-y-6">
            {/* Input Area with Tabs */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              {/* Input Type Tabs */}
              <div className="flex gap-2 mb-4">
                <button
                  onClick={() => setInputType('email')}
                  className={`flex-1 py-2 px-4 rounded-lg font-medium transition flex items-center justify-center gap-2 ${
                    inputType === 'email'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Mail className="w-4 h-4" />
                  <span className="font-medium">Email</span>
                </button>
                <button
                  onClick={() => setInputType('sms')}
                  className={`flex-1 py-2 px-4 rounded-lg font-medium transition flex items-center justify-center gap-2 ${
                    inputType === 'sms'
                      ? 'bg-green-600 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Smartphone className="w-4 h-4" />
                  <span className="font-medium">SMS / Message</span>
                </button>
              </div>

              {inputType === 'email' ? (
                <>
                  {/* Email Upload Mode */}
                  <div
                    className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
                      dragActive 
                        ? 'border-blue-500 bg-blue-500/10' 
                        : 'border-slate-600 hover:border-slate-500'
                    }`}
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                  >
                    <input
                      type="file"
                      accept=".eml,.msg"
                      onChange={handleFileSelect}
                      className="hidden"
                      id="file-upload"
                    />
                    <label htmlFor="file-upload" className="cursor-pointer">
                      <div className="flex flex-col items-center gap-3">
                        {file ? (
                          <>
                            <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center">
                              <Mail className="w-8 h-8 text-green-400" />
                            </div>
                            <div>
                              <p className="text-lg font-medium text-green-400">{file.name}</p>
                              <p className="text-sm text-slate-400">
                                {(file.size / 1024).toFixed(1)} KB
                              </p>
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="w-16 h-16 bg-slate-700 rounded-full flex items-center justify-center">
                              <Upload className="w-8 h-8 text-slate-400" />
                            </div>
                            <div>
                              <p className="text-slate-300">
                                Drop your email file here
                              </p>
                              <p className="text-sm text-slate-500">
                                or click to browse (.eml, .msg)
                              </p>
                            </div>
                          </>
                        )}
                      </div>
                    </label>
                  </div>

                  {/* Analysis Info */}
                  <div className="mt-4 p-3 bg-slate-700/50 rounded-lg border border-slate-600">
                    <div className="flex items-center gap-2">
                      <Zap className="w-4 h-4 text-yellow-400" />
                      <span className="text-sm font-medium text-slate-200">Full Email Analysis</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 ml-6">
                      Detection rules, SE analysis, content deconstruction, lookalike detection, TI fusion
                    </p>
                  </div>

                  <button
                    onClick={analyzeEmail}
                    disabled={!file || loading}
                    className={`w-full mt-4 py-3 rounded-lg font-semibold transition flex items-center justify-center gap-2 ${
                      file && !loading
                        ? 'bg-blue-600 hover:bg-blue-700 text-white'
                        : 'bg-slate-700 text-slate-400 cursor-not-allowed'
                    }`}
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        Analyze Email
                      </>
                    )}
                  </button>
                </>
              ) : (
                <>
                  {/* SMS/Text Message Mode */}
                  <div className="space-y-4">
                    {/* Source selector */}
                    <div className="flex gap-2">
                      {[
                        { value: 'sms', label: 'SMS', icon: Smartphone },
                        { value: 'whatsapp', label: 'WhatsApp', icon: MessageSquare },
                        { value: 'telegram', label: 'Telegram', icon: MessageSquare },
                        { value: 'other', label: 'Other', icon: MessageSquare },
                      ].map(({ value, label, icon: Icon }) => (
                        <button
                          key={value}
                          onClick={() => setTextSource(value as any)}
                          className={`flex-1 py-1.5 px-2 rounded-lg text-xs font-medium transition flex items-center justify-center gap-1 ${
                            textSource === value
                              ? 'bg-green-600 text-white'
                              : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                          }`}
                        >
                          <Icon className="w-3 h-3" />
                          {label}
                        </button>
                      ))}
                    </div>

                    {/* Message input */}
                    <textarea
                      value={textMessage}
                      onChange={(e) => setTextMessage(e.target.value)}
                      placeholder="Paste the suspicious SMS or message text here..."
                      className="w-full h-40 p-4 bg-slate-900 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:ring-2 focus:ring-green-500 focus:border-green-500 resize-none"
                    />

                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>{textMessage.length} characters</span>
                      <span>Max 5000 characters</span>
                    </div>
                  </div>

                  {/* SMS Analysis Info */}
                  <div className="mt-4 p-3 bg-slate-700/50 rounded-lg border border-slate-600">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-orange-400" />
                      <span className="text-sm font-medium text-slate-200">Smishing Analysis</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 ml-6">
                      Detects package scams, banking phishing, prize fraud, government impersonation
                    </p>
                  </div>

                  <button
                    onClick={analyzeText}
                    disabled={!textMessage.trim() || loading}
                    className={`w-full mt-4 py-3 rounded-lg font-semibold transition flex items-center justify-center gap-2 ${
                      textMessage.trim() && !loading
                        ? 'bg-green-600 hover:bg-green-700 text-white'
                        : 'bg-slate-700 text-slate-400 cursor-not-allowed'
                    }`}
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        Analyze Message
                      </>
                    )}
                  </button>
                </>
              )}
            </div>

            {/* Analysis Progress */}
            {showProgress && (
              <AnalysisProgress
                steps={analysisSteps}
                isComplete={analysisComplete}
                currentStep={analysisSteps.find(s => s.status === 'running')?.id || ''}
              />
            )}
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-6">
            {result ? (
              (() => {
                try {
                  const transformed = getTransformedResult();
                  console.log('Rendering ResultsPanel with:', transformed);
                  return (
                    <ResultsPanel
                      result={transformed}
                      onExport={exportResults}
                      onViewFullAnalysis={() => setFullAnalysisOpen(true)}
                    />
                  );
                } catch (err) {
                  console.error('Error rendering ResultsPanel:', err);
                  return (
                    <div className="bg-red-900/30 border border-red-500 rounded-xl p-6">
                      <h3 className="text-red-400 font-semibold">Error Rendering Results</h3>
                      <p className="text-sm text-red-300 mt-2">{String(err)}</p>
                      <pre className="mt-2 text-xs text-red-200 overflow-auto max-h-40">
                        {JSON.stringify(result, null, 2).slice(0, 500)}
                      </pre>
                    </div>
                  );
                }
              })()
            ) : (
              <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  Analysis Results
                </h2>
                <div className="text-center py-16">
                  <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                  <p className="text-slate-400">No analysis results yet</p>
                  <p className="text-sm text-slate-500 mt-1">
                    Upload an email file to get started
                  </p>
                </div>
              </div>
            )}

            {/* Quick Stats Card */}
            {result && (
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <h3 className="text-sm font-medium text-slate-400 mb-3">Analysis Summary</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-center gap-2">
                    <Mail className="w-4 h-4 text-blue-400" />
                    <span className="text-slate-300">Email Parsed</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Link className="w-4 h-4 text-indigo-400" />
                    <span className="text-slate-300">{result.email?.urls?.length || 0} URLs</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Paperclip className="w-4 h-4 text-green-400" />
                    <span className="text-slate-300">{result.email?.attachments?.length || 0} Files</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Key className="w-4 h-4 text-yellow-400" />
                    <span className="text-slate-300">Auth Checked</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-purple-400" />
                    <span className="text-slate-300">Threat Intel</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-red-400" />
                    <span className="text-slate-300">{result.detection?.rules_triggered?.length || 0} Rules</span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Target className="w-4 h-4 text-orange-400" />
                    <span className="text-slate-300">
                      {(result.iocs?.domains?.length || 0) + 
                       (result.iocs?.urls?.length || 0) + 
                       (result.iocs?.ips?.length || 0)} IOCs
                    </span>
                    <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                  </div>
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-purple-400" />
                    <span className="text-slate-300">AI Analysis</span>
                    {result.ai_triage ? (
                      <CheckCircle className="w-4 h-4 text-green-500 ml-auto" />
                    ) : (
                      <Info className="w-4 h-4 text-slate-500 ml-auto" />
                    )}
                  </div>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-700">
                  <p className="text-xs text-slate-500 text-center">
                    Analysis completed in {result.analysis_duration_ms || 0}ms • ID: {result.analysis_id || 'N/A'}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-8 text-center text-sm text-slate-500">
          <p>NiksES v1.0 • 51 Detection Rules + Custom Rules • AI-Powered Analysis</p>
        </footer>
      </main>

      {/* Dashboard Modal */}
      {dashboardOpen && (
        <Dashboard
          onViewAnalysis={handleViewAnalysis}
          onClose={() => setDashboardOpen(false)}
        />
      )}

      {/* Full Analysis View Modal */}
      {fullAnalysisOpen && result && (
        <div className="fixed inset-0 z-50 overflow-auto">
          <AdvancedAnalysisView
            result={{
              ...result,
              // Merge enhanced analysis data if available
              ...(enhancedResult ? {
                se_analysis: enhancedResult.se_analysis,
                content_analysis: enhancedResult.content_analysis,
                lookalike_analysis: enhancedResult.lookalike_analysis,
                ti_results: enhancedResult.ti_results,
                risk_score: enhancedResult.risk_score,
              } : {})
            }}
            onExport={exportResults}
            onBack={() => setFullAnalysisOpen(false)}
          />
        </div>
      )}

      {/* Settings Modal */}
      <SettingsModal 
        isOpen={settingsOpen} 
        onClose={() => setSettingsOpen(false)}
        onSettingsChange={(newSettings) => setGlobalSettings(newSettings)}
      />

      {/* Rules Manager Modal */}
      <AdvancedRulesManager isOpen={rulesOpen} onClose={() => setRulesOpen(false)} />

      {/* History Panel */}
      <HistoryPanel
        isOpen={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onViewAnalysis={async (analysisId: string) => {
          try {
            const response = await apiClient.get(`/analyses/${analysisId}`);
            setResult(response.data);
            setHistoryOpen(false);
            setFullAnalysisOpen(true);
          } catch (error) {
            toast.error('Failed to load analysis');
          }
        }}
        onExportAnalysis={async (analysisId: string, format: string) => {
          try {
            const response = await apiClient.get(`/export/${analysisId}/${format}`, {
              responseType: 'blob'
            });
            const blob = response.data;
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `analysis-${analysisId.slice(0, 8)}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            toast.success(`Exported as ${format.toUpperCase()}`);
          } catch (error) {
            toast.error('Export failed');
          }
        }}
      />

      {/* SOC Tools Panel */}
      <FullSOCToolsView
        analysisResult={enhancedResult || result}
        isOpen={socToolsOpen}
        onClose={() => setSocToolsOpen(false)}
      />
    </div>
  );
}

export default App;
