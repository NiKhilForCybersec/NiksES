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
  Target, Brain, Zap, Smartphone, MessageSquare,
  Menu, X, Home, History, FileText
} from 'lucide-react';
import { apiClient } from './services/api';
import AdvancedRulesManager from './components/rules/AdvancedRulesManager';
import Dashboard from './components/dashboard/Dashboard';
import AdvancedAnalysisView from './components/analysis/AdvancedAnalysisView';
import TextAnalysisResults from './components/analysis/TextAnalysisResults';
import AnalysisProgress, { 
  AnalysisStep, 
  AnalysisType,
  createAnalysisSteps,
  createUrlSmsAnalysisSteps
} from './components/analysis/AnalysisProgress';
import ResultsPanel from './components/analysis/ResultsPanel';
import { SettingsModal, APIStatusIndicator, APISetupBanner, SettingsState } from './components/settings';
import HistoryPanel from './components/history/HistoryPanel';
import { FullSOCToolsView } from './components/soc-tools';
import { DetectionEngineViz } from './components/detection-viz';
import QuotaWarningModal from './components/QuotaWarningModal';

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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [detectionVizOpen, setDetectionVizOpen] = useState(false);

  // SMS/Text analysis state
  const [inputType, setInputType] = useState<'email' | 'sms'>('email');
  const [textMessage, setTextMessage] = useState('');
  const [textSource, setTextSource] = useState<'sms' | 'whatsapp' | 'telegram' | 'other' | 'url'>('sms');
  const [textAnalysisResult, setTextAnalysisResult] = useState<any>(null); // Raw SMS/URL analysis result

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

  
  // Analysis progress state
  const [analysisSteps, setAnalysisSteps] = useState<AnalysisStep[]>(createAnalysisSteps());
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [showProgress, setShowProgress] = useState(false);
  const [currentAnalysisType, setCurrentAnalysisType] = useState<AnalysisType>('email');

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
    setCurrentAnalysisType('email');
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
      toast.error(textSource === 'url' ? 'Please enter URL(s) to analyze' : 'Please enter a message to analyze');
      return;
    }

    const isUrlMode = textSource === 'url';
    const analysisTypeToUse: AnalysisType = isUrlMode ? 'url' : 'sms';

    setLoading(true);
    setResult(null);
    setEnhancedResult(null);
    setTextAnalysisResult(null);
    setAnalysisComplete(false);
    setShowProgress(true);
    setCurrentAnalysisType(analysisTypeToUse);
    
    // Reset to URL/SMS specific steps
    setAnalysisSteps(createUrlSmsAnalysisSteps(analysisTypeToUse));

    // Progress steps for text/URL analysis (matching createUrlSmsAnalysisSteps ids)
    const textSteps = [
      { id: 'parse', delay: 100 },
      { id: 'patterns', delay: 200 },
      { id: 'enrichment', delay: 400 },
      { id: 'sandbox', delay: 500 },
      { id: 'scoring', delay: 150 },
      { id: 'ai', delay: 500 },
      { id: 'report', delay: 100 },
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
      console.log('Starting text analysis...', { textSource, isUrlMode });
      
      const response = await apiClient.post('/analyze/text', {
        text: textMessage,
        sender: '',
        source: textSource,
        enable_url_enrichment: true,
        enable_ai_analysis: true,
        enable_url_sandbox: isUrlMode, // Enable sandbox for URL mode
      });

      console.log('API Response received:', response.status, response.data);

      const textResult = response.data;
      
      if (!textResult || !textResult.analysis_id) {
        throw new Error('Invalid response: missing analysis_id');
      }
      
      // Store raw result for TextAnalysisResults component
      setTextAnalysisResult(textResult);
      
      // Also create email-like structure for compatibility with existing views
      const analysisType = isUrlMode ? 'URL' : (textSource || 'text').toUpperCase();
      const urlCount = textResult.urls_found?.length || 0;
      
      // Build pseudoEmailResult with defensive checks
      let pseudoEmailResult: AnalysisResult;
      try {
        pseudoEmailResult = {
          analysis_id: textResult.analysis_id || 'unknown',
          analyzed_at: textResult.analyzed_at || new Date().toISOString(),
          analysis_duration_ms: 500,
          email: {
            subject: isUrlMode 
              ? `URL Analysis: ${urlCount} URL(s) analyzed`
              : `${analysisType} Message Analysis`,
            sender: { 
              email: isUrlMode ? 'url@analysis' : 'unknown@sms', 
              display_name: isUrlMode ? 'URL Scanner' : `${analysisType} Sender`, 
              domain: isUrlMode ? 'analysis' : 'sms' 
            },
            recipients: { to: ['security@analysis'] },
            body_text: textResult.original_text || textMessage || '',
            urls: (textResult.urls_found || []).map((url: string) => ({ url, display_text: url })),
            attachments: [],
          },
          authentication: {},
          detection: {
            risk_score: textResult.overall_score || 0,
            risk_level: textResult.overall_level || 'unknown',
            verdict: textResult.is_threat ? 'malicious' : 'clean',
            primary_classification: textResult.classification || 'unknown',
            confidence: textResult.confidence || 0,
            rules_triggered: (textResult.patterns_matched || []).map((p: any) => ({
              rule_id: p.pattern_id || 'unknown',
              name: p.name || 'Unknown Pattern',
              description: p.description || '',
              severity: p.severity || 'low',
              category: isUrlMode ? 'url_threat' : 'smishing',
              mitre_technique: p.mitre_technique || '',
            })),
          },
          iocs: {
            domains: textResult.domains_found || [],
            urls: textResult.urls_found || [],
            ips: textResult.ips_found || [],
            email_addresses: [],
            file_hashes_sha256: [],
          },
          ai_triage: {
            enabled: textResult.ai_analysis?.enabled || false,
            provider: textResult.ai_analysis?.provider || 'pattern-matching',
            summary: textResult.ai_analysis?.summary || (
              textResult.is_threat 
                ? `⚠️ ${(textResult.classification || 'threat').replace(/_/g, ' ').toUpperCase()} detected with ${textResult.overall_score || 0}% threat score.`
                : '✅ No significant threats detected.'
            ),
            key_findings: textResult.ai_analysis?.key_findings || textResult.threat_indicators || [],
            recommendations: textResult.ai_analysis?.recommendations || textResult.recommendations || [],
            recommended_actions: isUrlMode 
              ? [
                  { action: 'block_url', label: 'Block URL(s)', priority: 'high' },
                  { action: 'report_phishing', label: 'Report to PhishTank', priority: 'medium' },
                ]
              : [],
          },
        };
        console.log('PseudoEmailResult constructed:', pseudoEmailResult.analysis_id);
      } catch (buildError) {
        console.error('Error building pseudoEmailResult:', buildError);
        throw new Error(`Failed to process analysis result: ${buildError}`);
      }

      setResult(pseudoEmailResult);
      setEnhancedResult(pseudoEmailResult);
      setAnalysisComplete(true);
      
      console.log('Analysis complete, result set:', pseudoEmailResult.analysis_id);
      
      const threatLabel = textResult.is_threat ? '⚠️ Threats detected!' : '✅ No threats';
      toast.success(isUrlMode ? `${urlCount} URL(s) analyzed - ${threatLabel}` : `Analysis complete - ${threatLabel}`);

    } catch (error: any) {
      console.error('Analysis error:', error);
      console.error('Error response:', error.response?.data);
      
      // Reset progress on error
      setShowProgress(false);
      setAnalysisSteps(createUrlSmsAnalysisSteps(analysisTypeToUse));
      
      const errorMessage = error.response?.data?.detail || error.message || 'Failed to analyze';
      toast.error(errorMessage);
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
    <div className="min-h-screen bg-slate-900 text-white has-bottom-nav">
      <Toaster position="top-right" />
      
      {/* API Quota Warning Modal - shows once per session */}
      <QuotaWarningModal />

      {/* Header - Mobile Responsive */}
      <header className="mobile-header h-14 md:h-16 bg-slate-800 border-b border-slate-700 flex items-center justify-between px-3 md:px-6">
        {/* Logo */}
        <div className="flex items-center gap-2 md:gap-3">
          <div className="w-8 h-8 md:w-10 md:h-10 bg-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 md:w-6 md:h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg md:text-xl font-bold">NiksES</h1>
            <p className="text-[10px] md:text-xs text-slate-400 hidden sm:block">Email & SMS Security</p>
          </div>
        </div>

        {/* Desktop Navigation */}
        <div className="hidden md:flex items-center gap-2">
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
            onClick={() => setDetectionVizOpen(true)}
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-lg transition flex items-center gap-2 group"
            title="View Detection Engine Architecture"
          >
            <Zap className="w-4 h-4 group-hover:animate-pulse" />
            <span className="text-sm">DIDA Engine</span>
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

        {/* Mobile Header Actions */}
        <div className="flex md:hidden items-center gap-2">
          {result && (
            <button
              onClick={() => setSocToolsOpen(true)}
              className="p-2 bg-purple-600 rounded-lg animate-pulse"
            >
              <Target className="w-5 h-5" />
            </button>
          )}
          <button
            onClick={() => setSettingsOpen(true)}
            className="p-2 hover:bg-slate-700 rounded-lg transition"
          >
            <Settings className="w-5 h-5 text-slate-400" />
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 hover:bg-slate-700 rounded-lg transition"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* Mobile Dropdown Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-slate-800 border-b border-slate-700 animate-fade-in">
          <div className="p-3 space-y-2">
            <button
              onClick={() => { setDashboardOpen(true); setMobileMenuOpen(false); }}
              className="w-full px-4 py-3 bg-indigo-600 hover:bg-indigo-700 rounded-lg transition flex items-center gap-3"
            >
              <LayoutDashboard className="w-5 h-5" />
              <span>Dashboard</span>
            </button>
            <button
              onClick={() => { setHistoryOpen(true); setMobileMenuOpen(false); }}
              className="w-full px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg transition flex items-center gap-3"
            >
              <Database className="w-5 h-5 text-green-400" />
              <span>History</span>
            </button>
            <button
              onClick={() => { setRulesOpen(true); setMobileMenuOpen(false); }}
              className="w-full px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg transition flex items-center gap-3"
            >
              <BookOpen className="w-5 h-5 text-blue-400" />
              <span>Custom Rules</span>
            </button>
            {globalSettings && (
              <div className="px-4 py-2 bg-slate-700/50 rounded-lg">
                <div className="text-xs text-slate-400 mb-1">API Status</div>
                <div className="flex items-center gap-2 text-sm">
                  <span className={`w-2 h-2 rounded-full ${
                    Object.values(globalSettings.api_keys_configured).filter(Boolean).length > 0 
                      ? 'bg-green-500' 
                      : 'bg-yellow-500'
                  }`} />
                  <span>
                    {Object.values(globalSettings.api_keys_configured).filter(Boolean).length}/{Object.keys(globalSettings.api_keys_configured).length} APIs
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mobile Bottom Navigation */}
      <nav className="mobile-bottom-nav">
        <div className="flex items-center justify-around">
          <button
            onClick={() => { setDashboardOpen(false); setHistoryOpen(false); setFullAnalysisOpen(false); }}
            className={`mobile-nav-item ${!dashboardOpen && !historyOpen && !fullAnalysisOpen ? 'active' : ''}`}
          >
            <Home className="w-5 h-5" />
            <span>Analyze</span>
          </button>
          <button
            onClick={() => setDashboardOpen(true)}
            className={`mobile-nav-item ${dashboardOpen ? 'active' : ''}`}
          >
            <LayoutDashboard className="w-5 h-5" />
            <span>Dashboard</span>
          </button>
          <button
            onClick={() => setHistoryOpen(true)}
            className={`mobile-nav-item ${historyOpen ? 'active' : ''}`}
          >
            <History className="w-5 h-5" />
            <span>History</span>
          </button>
          {result && (
            <button
              onClick={() => setFullAnalysisOpen(true)}
              className={`mobile-nav-item ${fullAnalysisOpen ? 'active' : ''}`}
            >
              <FileText className="w-5 h-5" />
              <span>Results</span>
            </button>
          )}
        </div>
      </nav>

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
      <main className="max-w-7xl mx-auto px-3 md:px-6 py-4 md:py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
          {/* Left Panel - Upload & Progress */}
          <div className="space-y-4 md:space-y-6">
            {/* Input Area with Tabs */}
            <div className="bg-slate-800 rounded-xl p-4 md:p-6 border border-slate-700">
              {/* Input Type Tabs */}
              <div className="flex gap-2 mb-4">
                <button
                  onClick={() => setInputType('email')}
                  className={`flex-1 py-2.5 md:py-2 px-3 md:px-4 rounded-lg font-medium transition flex items-center justify-center gap-2 ${
                    inputType === 'email'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Mail className="w-4 h-4" />
                  <span className="font-medium text-sm md:text-base">Email</span>
                </button>
                <button
                  onClick={() => setInputType('sms')}
                  className={`flex-1 py-2.5 md:py-2 px-3 md:px-4 rounded-lg font-medium transition flex items-center justify-center gap-2 ${
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
                  {/* SMS/Text/URL Analysis Mode */}
                  <div className="space-y-4">
                    {/* Analysis Type Selector */}
                    <div className="flex gap-2 p-1 bg-slate-900 rounded-lg">
                      <button
                        onClick={() => setTextSource('sms')}
                        className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition flex items-center justify-center gap-2 ${
                          textSource !== 'url'
                            ? 'bg-green-600 text-white'
                            : 'text-slate-400 hover:text-white hover:bg-slate-700'
                        }`}
                      >
                        <MessageSquare className="w-4 h-4" />
                        SMS / Message
                      </button>
                      <button
                        onClick={() => setTextSource('url')}
                        className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition flex items-center justify-center gap-2 ${
                          textSource === 'url'
                            ? 'bg-purple-600 text-white'
                            : 'text-slate-400 hover:text-white hover:bg-slate-700'
                        }`}
                      >
                        <Link className="w-4 h-4" />
                        URL Analysis
                      </button>
                    </div>

                    {textSource !== 'url' ? (
                      <>
                        {/* SMS Source selector */}
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
                          placeholder="Paste the suspicious SMS or message text here...&#10;&#10;Example: USPS: Your package is held due to unpaid customs fees. Pay $3.99 now: https://usps-delivery.tk/pay"
                          className="w-full h-40 p-4 bg-slate-900 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:ring-2 focus:ring-green-500 focus:border-green-500 resize-none"
                        />

                        <div className="flex items-center justify-between text-xs text-slate-500">
                          <span>{textMessage.length} characters</span>
                          <span>URLs will be auto-detected and analyzed</span>
                        </div>

                        {/* SMS Analysis Info */}
                        <div className="p-3 bg-slate-700/50 rounded-lg border border-slate-600">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-orange-400" />
                            <span className="text-sm font-medium text-slate-200">Smishing Detection</span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1 ml-6">
                            Detects package scams, banking phishing, prize fraud, government impersonation + URL threat intel
                          </p>
                        </div>
                      </>
                    ) : (
                      <>
                        {/* URL Input Mode */}
                        <div className="space-y-3">
                          <label className="text-sm text-slate-300 font-medium">Paste suspicious URL(s)</label>
                          <textarea
                            value={textMessage}
                            onChange={(e) => setTextMessage(e.target.value)}
                            placeholder="https://suspicious-site.com/login&#10;https://bit.ly/abc123&#10;&#10;One URL per line, or paste multiple URLs"
                            className="w-full h-32 p-4 bg-slate-900 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:ring-2 focus:ring-purple-500 focus:border-purple-500 resize-none font-mono text-sm"
                          />
                        </div>

                        <div className="flex items-center justify-between text-xs text-slate-500">
                          <span>{(textMessage.match(/https?:\/\/[^\s]+/gi) || []).length} URL(s) detected</span>
                          <span>Supports shortened URLs</span>
                        </div>

                        {/* URL Analysis Info */}
                        <div className="p-3 bg-slate-700/50 rounded-lg border border-purple-600/50">
                          <div className="flex items-center gap-2">
                            <Link className="w-4 h-4 text-purple-400" />
                            <span className="text-sm font-medium text-slate-200">URL Threat Analysis</span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1 ml-6">
                            VirusTotal, PhishTank, URLhaus, domain reputation, redirect chain analysis
                          </p>
                        </div>
                      </>
                    )}
                  </div>

                  <button
                    onClick={analyzeText}
                    disabled={!textMessage.trim() || loading}
                    className={`w-full mt-4 py-3 rounded-lg font-semibold transition flex items-center justify-center gap-2 ${
                      textMessage.trim() && !loading
                        ? textSource === 'url' 
                          ? 'bg-purple-600 hover:bg-purple-700 text-white'
                          : 'bg-green-600 hover:bg-green-700 text-white'
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
                        {textSource === 'url' ? 'Analyze URL(s)' : 'Analyze Message'}
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
                analysisType={currentAnalysisType}
              />
            )}
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-6">
            {result ? (
              (() => {
                try {
                  const transformed = getTransformedResult();
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

      {/* Detection Engine Visualization Modal */}
      <DetectionEngineViz
        isOpen={detectionVizOpen}
        onClose={() => setDetectionVizOpen(false)}
        analysisData={result ? {
          score: result.detection?.risk_score,
          level: result.detection?.risk_level,
          confidence: result.detection?.confidence,
          evidenceCount: result.detection?.rules_triggered?.length,
          rules_triggered: result.detection?.rules_triggered,
          attackChains: enhancedResult?.attack_chains || (result.detection as any)?.attack_chains,
          breakdown: enhancedResult?.breakdown || (result.detection as any)?.breakdown,
          ti_results: enhancedResult?.ti_results || result.enrichment,
        } : (textAnalysisResult ? {
          score: textAnalysisResult.risk_score,
          level: textAnalysisResult.risk_level,
          confidence: textAnalysisResult.confidence,
          rules_triggered: textAnalysisResult.indicators?.map((ind: any, i: number) => ({
            rule_id: `indicator_${i}`,
            description: ind,
            category: 'content',
            score: 50,
          })),
          attackChains: textAnalysisResult.attack_chains,
          breakdown: textAnalysisResult.breakdown,
        } : undefined)}
      />

      {/* Full Analysis View Modal */}
      {/* Full Analysis View - Email or URL/SMS from history */}
      {(fullAnalysisOpen && result) || textAnalysisResult ? (
        <div className="fixed inset-0 z-50 overflow-auto">
          {/* SMS/URL analysis - TextAnalysisResults has its own header */}
          {textAnalysisResult ? (
            <div className="min-h-screen bg-slate-900 p-6">
              <div className="max-w-4xl mx-auto">
                <TextAnalysisResults 
                  result={textAnalysisResult}
                  onClose={() => {
                    setFullAnalysisOpen(false);
                    setTextAnalysisResult(null);
                  }}
                  onSOCTools={() => setSocToolsOpen(true)}
                />
              </div>
            </div>
          ) : result ? (
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
          ) : null}
        </div>
      ) : null}

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
        onViewAnalysis={async (analysisId: string, analysisType: 'email' | 'url' | 'sms') => {
          try {
            const response = await apiClient.get(`/analyses/${analysisId}`);
            const data = response.data;
            
            console.log('[History View] Loading analysis:', analysisId, 'type:', analysisType);
            
            setHistoryOpen(false);
            
            if (analysisType === 'url' || analysisType === 'sms') {
              // URL/SMS: Show in dedicated TextAnalysisResults view
              setFullAnalysisOpen(false);
              setResult(null);
              
              // Create TextAnalysisResult format with safe defaults
              const textResult = {
                analysis_id: data.analysis_id || analysisId,
                analyzed_at: data.analyzed_at || new Date().toISOString(),
                analysis_type: analysisType,
                source: analysisType,
                original_text: data.email?.body_text || data.email?.body_html || '',
                message_length: (data.email?.body_text || '').length,
                overall_score: data.overall_score ?? data.detection?.risk_score ?? 0,
                overall_level: data.overall_level || data.detection?.risk_level || 'low',
                classification: data.classification || 'unknown',
                is_threat: (data.overall_score ?? 0) >= 50,
                confidence: data.detection?.confidence ?? 0.5,
                urls_found: (data.email?.urls || []).map((u: any) => typeof u === 'string' ? u : u.url || ''),
                domains_found: data.iocs?.domains || [],
                ips_found: data.iocs?.ips || [],
                phone_numbers_found: data.iocs?.phone_numbers || [],
                // Transform URLEnrichment model to TextAnalysisResults format
                url_enrichment: (data.enrichment?.urls || []).map((u: any) => ({
                  url: u.url || '',
                  domain: u.domain || '',
                  is_malicious: (u.virustotal_positives && u.virustotal_positives > 0) || 
                               u.phishtank_in_database || 
                               (u.ipqs_risk_score && u.ipqs_risk_score >= 85) ||
                               u.ipqs_is_phishing || u.ipqs_is_malware,
                  threat_score: u.ipqs_risk_score || (u.virustotal_positives ? u.virustotal_positives * 10 : 0),
                  sources: [
                    u.virustotal_positives !== null ? 'VirusTotal' : null,
                    u.phishtank_verified ? 'PhishTank' : null,
                    u.urlhaus_status ? 'URLhaus' : null,
                    u.ipqs_risk_score !== null ? 'IPQualityScore' : null,
                  ].filter(Boolean),
                  categories: u.virustotal_categories || [],
                  ipqs_score: u.ipqs_risk_score,
                  ipqs_phishing: u.ipqs_is_phishing,
                  ipqs_malware: u.ipqs_is_malware,
                  vt_malicious: u.virustotal_positives,
                })),
                url_sandbox: data.sandbox_results || [],
                patterns_matched: (data.detection?.rules_triggered || []).map((r: any) => ({
                  pattern_id: r.rule_id || 'unknown',
                  name: r.rule_name || r.name || 'Unknown Rule',
                  description: r.description || '',
                  severity: r.severity || 'medium',
                  matched_text: Array.isArray(r.evidence) ? r.evidence[0] : '',
                  mitre_technique: r.mitre_technique || '',
                })),
                threat_indicators: (data.detection?.rules_triggered || []).map((r: any) => r.rule_name || r.name || ''),
                ai_analysis: {
                  enabled: !!data.ai_triage,
                  provider: data.ai_triage?.model_used || data.ai_triage?.provider || 'ai',
                  summary: data.ai_triage?.summary || data.ai_triage?.detailed_analysis || '',
                  threat_assessment: data.ai_triage?.classification_reasoning || data.ai_triage?.threat_assessment || '',
                  key_findings: data.ai_triage?.key_findings || [],
                  social_engineering_tactics: data.ai_triage?.mitre_tactics || data.ai_triage?.social_engineering_tactics || [],
                  recommendations: (data.ai_triage?.recommended_actions || []).map((a: any) => 
                    typeof a === 'string' ? a : (a.description || a.action || '')
                  ),
                  confidence: data.ai_triage?.confidence ?? parseFloat(data.ai_triage?.risk_reasoning?.match(/(\d+)/)?.[1] || '0') / 100,
                },
                recommendations: (data.ai_triage?.recommended_actions || []).map((a: any) => 
                  typeof a === 'string' ? a : (a.description || a.action || '')
                ) || data.recommendations || [],
                mitre_techniques: data.ai_triage?.mitre_techniques || data.detection?.mitre_techniques || [],
              };
              
              setTextAnalysisResult(textResult);
              window.scrollTo({ top: 0, behavior: 'smooth' });
            } else {
              // Email: Show in AdvancedAnalysisView
              setTextAnalysisResult(null);
              setResult(data);
              setFullAnalysisOpen(true);
            }
            
          } catch (error) {
            console.error('[History View] Error:', error);
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
