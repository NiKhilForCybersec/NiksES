import React, { useState, useEffect } from 'react';
import {
  CheckCircle,
  XCircle,
  Loader,
  Mail,
  Search,
  Shield,
  Brain,
  FileText,
  Globe,
  Database,
  Link,
  Paperclip,
  Key,
  Target,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  MessageSquare,
} from 'lucide-react';

export type AnalysisType = 'email' | 'url' | 'sms';

export interface AnalysisStep {
  id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'success' | 'warning' | 'error';
  icon: React.ReactNode;
  details?: string;
  findings?: string[];
  duration?: number;
}

interface AnalysisProgressProps {
  steps: AnalysisStep[];
  isComplete: boolean;
  currentStep: string;
  analysisType?: AnalysisType;
}

const AnalysisProgress: React.FC<AnalysisProgressProps> = ({ 
  steps, 
  isComplete, 
  currentStep,
  analysisType = 'email'
}) => {
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const getAnalysisLabel = () => {
    switch (analysisType) {
      case 'url':
        return isComplete ? 'URL analysis complete' : 'Analyzing URL...';
      case 'sms':
        return isComplete ? 'SMS analysis complete' : 'Analyzing SMS/Message...';
      default:
        return isComplete ? 'Email analysis complete' : 'Analyzing email...';
    }
  };

  const toggleStep = (stepId: string) => {
    const newExpanded = new Set(expandedSteps);
    if (newExpanded.has(stepId)) {
      newExpanded.delete(stepId);
    } else {
      newExpanded.add(stepId);
    }
    setExpandedSteps(newExpanded);
  };

  const getStatusIcon = (status: AnalysisStep['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'running':
        return <Loader className="w-5 h-5 text-indigo-500 animate-spin" />;
      default:
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300" />;
    }
  };

  const getStatusColor = (status: AnalysisStep['status']) => {
    switch (status) {
      case 'success':
        return 'border-green-200 bg-green-50';
      case 'error':
        return 'border-red-200 bg-red-50';
      case 'warning':
        return 'border-yellow-200 bg-yellow-50';
      case 'running':
        return 'border-indigo-200 bg-indigo-50';
      default:
        return 'border-gray-200 bg-gray-50';
    }
  };

  return (
    <div className="bg-white rounded-lg border shadow-sm">
      <div className="p-4 border-b bg-gray-50">
        <h3 className="font-semibold text-gray-900 flex items-center gap-2">
          <Search className="w-5 h-5 text-indigo-600" />
          Analysis Progress
        </h3>
        <p className="text-sm text-gray-600 mt-1">
          {getAnalysisLabel()}
        </p>
      </div>

      <div className="p-4 space-y-2">
        {steps.map((step, index) => (
          <div
            key={step.id}
            className={`rounded-lg border transition-all ${getStatusColor(step.status)}`}
          >
            <div
              className="flex items-center gap-3 p-3 cursor-pointer"
              onClick={() => step.findings && step.findings.length > 0 && toggleStep(step.id)}
            >
              {/* Status Icon */}
              {getStatusIcon(step.status)}

              {/* Step Icon */}
              <div className="text-gray-600">{step.icon}</div>

              {/* Step Info */}
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-gray-900">{step.name}</span>
                  {step.status === 'running' && (
                    <span className="text-xs text-indigo-600 animate-pulse">Processing...</span>
                  )}
                </div>
                <p className="text-xs text-gray-500">{step.description}</p>
              </div>

              {/* Duration */}
              {step.duration !== undefined && (
                <span className="text-xs text-gray-400 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {step.duration}ms
                </span>
              )}

              {/* Expand Arrow */}
              {step.findings && step.findings.length > 0 && (
                <div className="text-gray-400">
                  {expandedSteps.has(step.id) ? (
                    <ChevronDown className="w-4 h-4" />
                  ) : (
                    <ChevronRight className="w-4 h-4" />
                  )}
                </div>
              )}
            </div>

            {/* Findings */}
            {expandedSteps.has(step.id) && step.findings && (
              <div className="px-3 pb-3">
                <div className="ml-8 p-2 bg-white rounded border text-sm">
                  <ul className="space-y-1">
                    {step.findings.map((finding, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-gray-700">
                        <span className="text-gray-400">•</span>
                        {finding}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Progress Bar */}
      <div className="p-4 border-t">
        <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
          <span>Overall Progress</span>
          <span>
            {steps.filter((s) => s.status === 'success' || s.status === 'warning').length}/{steps.length} steps
          </span>
        </div>
        <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-500"
            style={{
              width: `${
                (steps.filter((s) => s.status === 'success' || s.status === 'warning' || s.status === 'error')
                  .length /
                  steps.length) *
                100
              }%`,
            }}
          />
        </div>
      </div>
    </div>
  );
};

// Helper function to generate default analysis steps for EMAIL
export const createAnalysisSteps = (): AnalysisStep[] => [
  {
    id: 'parse',
    name: 'Parse Email',
    description: 'Extract headers, body, and metadata',
    status: 'pending',
    icon: <Mail className="w-4 h-4" />,
  },
  {
    id: 'urls',
    name: 'Extract URLs',
    description: 'Find and analyze embedded links',
    status: 'pending',
    icon: <Link className="w-4 h-4" />,
  },
  {
    id: 'attachments',
    name: 'Process Attachments',
    description: 'Analyze file types and calculate hashes',
    status: 'pending',
    icon: <Paperclip className="w-4 h-4" />,
  },
  {
    id: 'auth',
    name: 'Check Authentication',
    description: 'Verify SPF, DKIM, and DMARC',
    status: 'pending',
    icon: <Key className="w-4 h-4" />,
  },
  {
    id: 'enrichment',
    name: 'Threat Intelligence',
    description: 'Query external threat feeds',
    status: 'pending',
    icon: <Database className="w-4 h-4" />,
  },
  {
    id: 'geoip',
    name: 'GeoIP Lookup',
    description: 'Determine sender location',
    status: 'pending',
    icon: <Globe className="w-4 h-4" />,
  },
  {
    id: 'detection',
    name: 'Run Detection Rules',
    description: 'Check against 51+ detection rules',
    status: 'pending',
    icon: <Shield className="w-4 h-4" />,
  },
  {
    id: 'scoring',
    name: 'Calculate Risk Score',
    description: 'Compute overall threat level',
    status: 'pending',
    icon: <Target className="w-4 h-4" />,
  },
  {
    id: 'ai',
    name: 'AI Analysis',
    description: 'Generate insights and recommendations',
    status: 'pending',
    icon: <Brain className="w-4 h-4" />,
  },
  {
    id: 'report',
    name: 'Generate Report',
    description: 'Compile final analysis results',
    status: 'pending',
    icon: <FileText className="w-4 h-4" />,
  },
];

// Helper function to generate analysis steps for URL/SMS
export const createUrlSmsAnalysisSteps = (type: 'url' | 'sms' = 'url'): AnalysisStep[] => [
  {
    id: 'parse',
    name: type === 'url' ? 'Parse URL' : 'Parse Message',
    description: type === 'url' ? 'Extract URL components and domain' : 'Extract URLs and text patterns',
    status: 'pending',
    icon: type === 'url' ? <Link className="w-4 h-4" /> : <MessageSquare className="w-4 h-4" />,
  },
  {
    id: 'patterns',
    name: 'Pattern Detection',
    description: 'Detect smishing, phishing, and scam patterns',
    status: 'pending',
    icon: <Shield className="w-4 h-4" />,
  },
  {
    id: 'enrichment',
    name: 'URL Threat Intelligence',
    description: 'Check URLhaus, PhishTank, VirusTotal',
    status: 'pending',
    icon: <Database className="w-4 h-4" />,
  },
  {
    id: 'sandbox',
    name: 'URL Sandbox Analysis',
    description: 'Dynamic analysis via URLScan.io',
    status: 'pending',
    icon: <Globe className="w-4 h-4" />,
  },
  {
    id: 'scoring',
    name: 'Calculate Risk Score',
    description: 'Compute overall threat level',
    status: 'pending',
    icon: <Target className="w-4 h-4" />,
  },
  {
    id: 'ai',
    name: 'AI Analysis',
    description: 'Generate threat assessment',
    status: 'pending',
    icon: <Brain className="w-4 h-4" />,
  },
  {
    id: 'report',
    name: 'Generate Report',
    description: 'Compile analysis results',
    status: 'pending',
    icon: <FileText className="w-4 h-4" />,
  },
];

// Simulated step updates for demo purposes
export const simulateAnalysis = (
  setSteps: React.Dispatch<React.SetStateAction<AnalysisStep[]>>,
  onComplete: () => void
) => {
  const stepUpdates = [
    { id: 'parse', delay: 500, findings: ['Parsed email headers', 'Extracted subject and body', 'Identified sender domain'] },
    { id: 'urls', delay: 800, findings: ['Found 3 URLs in body', '1 URL uses URL shortener', 'Extracted domains for analysis'] },
    { id: 'attachments', delay: 600, findings: ['1 attachment found', 'Type: PDF document', 'Calculated MD5 and SHA256 hashes'] },
    { id: 'auth', delay: 700, findings: ['SPF: Pass', 'DKIM: Fail', 'DMARC: None'] },
    { id: 'enrichment', delay: 1500, findings: ['VirusTotal: 0/72 detections', 'URLhaus: Not found', 'PhishTank: Not found'] },
    { id: 'geoip', delay: 400, findings: ['Country: United States', 'City: San Francisco', 'ISP: Amazon AWS'] },
    { id: 'detection', delay: 1000, findings: ['3 rules triggered', 'DKIM-FAIL (Medium)', 'URL-SHORTENER (Low)', 'SUSPICIOUS-DOMAIN (Medium)'] },
    { id: 'scoring', delay: 300, findings: ['Risk Score: 45/100', 'Risk Level: MEDIUM', 'Verdict: Suspicious'] },
    { id: 'ai', delay: 2000, findings: ['Summary generated', '3 recommendations', 'MITRE techniques identified'] },
    { id: 'report', delay: 400, findings: ['Report compiled', 'IOCs extracted', 'Ready for export'] },
  ];

  let totalDelay = 0;

  stepUpdates.forEach((update, index) => {
    // Set running state
    setTimeout(() => {
      setSteps((prev) =>
        prev.map((step) =>
          step.id === update.id ? { ...step, status: 'running' as const } : step
        )
      );
    }, totalDelay);

    totalDelay += update.delay;

    // Set complete state
    setTimeout(() => {
      setSteps((prev) =>
        prev.map((step) =>
          step.id === update.id
            ? {
                ...step,
                status: 'success' as const,
                findings: update.findings,
                duration: update.delay,
              }
            : step
        )
      );

      if (index === stepUpdates.length - 1) {
        onComplete();
      }
    }, totalDelay);
  });
};

export default AnalysisProgress;
