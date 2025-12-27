/**
 * NiksES Enhanced Risk Score Panel
 * 
 * Displays multi-dimensional risk assessment with:
 * - Overall score gauge
 * - Dimension breakdown bars
 * - Top indicators
 * - Recommended actions
 * - API status indicators
 */

import React, { useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  AlertTriangle, AlertCircle, CheckCircle, Info,
  ChevronDown, ChevronRight, Target, Brain,
  Users, Mail, Globe, Server, Activity, Zap,
  ExternalLink, Copy, TrendingUp, TrendingDown,
} from 'lucide-react';

interface DimensionScore {
  dimension: string;
  score: number;
  level: string;
  weight: number;
  indicators: string[];
  details: Record<string, any>;
}

interface RecommendedAction {
  action: string;
  priority: number;
  category: string;
  description: string;
  automated: boolean;
}

interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

interface UnifiedRiskScore {
  overall_score: number;
  overall_level: string;
  confidence: number;
  primary_classification: string;
  secondary_classifications: string[];
  dimensions: Record<string, DimensionScore>;
  top_indicators: string[];
  summary: string;
  detailed_explanation: string;
  recommended_actions: RecommendedAction[];
  mitre_techniques: MitreTechnique[];
  rules_triggered: number;
  data_sources_available: number;
}

interface APIStatus {
  [key: string]: string;
}

interface RiskScorePanelProps {
  riskScore: UnifiedRiskScore;
  apiStatus?: APIStatus;
  onExportReport?: () => void;
}

// Score level colors
const getLevelColor = (level: string): string => {
  switch (level) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    case 'low': return 'text-green-500';
    default: return 'text-gray-500';
  }
};

const getLevelBgColor = (level: string): string => {
  switch (level) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    case 'low': return 'bg-green-500';
    default: return 'bg-gray-500';
  }
};

const getLevelBgLight = (level: string): string => {
  switch (level) {
    case 'critical': return 'bg-red-500/20';
    case 'high': return 'bg-orange-500/20';
    case 'medium': return 'bg-yellow-500/20';
    case 'low': return 'bg-green-500/20';
    default: return 'bg-gray-500/20';
  }
};

const getDimensionIcon = (dimension: string) => {
  switch (dimension) {
    case 'social_engineering': return <Brain className="w-4 h-4" />;
    case 'brand_impersonation': return <Users className="w-4 h-4" />;
    case 'content': return <Mail className="w-4 h-4" />;
    case 'threat_intel': return <Globe className="w-4 h-4" />;
    case 'technical': return <Server className="w-4 h-4" />;
    default: return <Activity className="w-4 h-4" />;
  }
};

const formatDimensionName = (name: string): string => {
  return name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
};

const RiskScorePanel: React.FC<RiskScorePanelProps> = ({
  riskScore,
  apiStatus,
  onExportReport,
}) => {
  const [expandedDimensions, setExpandedDimensions] = useState<Set<string>>(new Set());
  const [showActions, setShowActions] = useState(true);

  const toggleDimension = (dim: string) => {
    const newExpanded = new Set(expandedDimensions);
    if (newExpanded.has(dim)) {
      newExpanded.delete(dim);
    } else {
      newExpanded.add(dim);
    }
    setExpandedDimensions(newExpanded);
  };

  // Sort dimensions by score
  const sortedDimensions = Object.entries(riskScore.dimensions)
    .sort(([, a], [, b]) => b.score - a.score);

  return (
    <div className="space-y-6">
      {/* Overall Score Card */}
      <div className={`rounded-xl p-6 border ${getLevelBgLight(riskScore.overall_level)} border-gray-700`}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className={`w-6 h-6 ${getLevelColor(riskScore.overall_level)}`} />
            Risk Assessment
          </h2>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getLevelBgColor(riskScore.overall_level)} text-white uppercase`}>
            {riskScore.overall_level}
          </span>
        </div>

        <div className="flex items-center gap-8">
          {/* Score Gauge */}
          <div className="relative w-32 h-32">
            <svg className="w-full h-full transform -rotate-90">
              {/* Background circle */}
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="12"
                className="text-gray-700"
              />
              {/* Progress circle */}
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={`${(riskScore.overall_score / 100) * 352} 352`}
                className={getLevelColor(riskScore.overall_level)}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center flex-col">
              <span className={`text-3xl font-bold ${getLevelColor(riskScore.overall_level)}`}>
                {riskScore.overall_score}
              </span>
              <span className="text-xs text-gray-400">/ 100</span>
            </div>
          </div>

          {/* Score Details */}
          <div className="flex-1">
            <div className="mb-3">
              <span className="text-sm text-gray-400">Classification</span>
              <p className="text-lg font-medium text-white">
                {(riskScore.primary_classification || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </p>
            </div>
            
            <div className="flex gap-4 text-sm">
              <div>
                <span className="text-gray-400">Confidence</span>
                <p className="text-white font-medium">{Math.round(riskScore.confidence * 100)}%</p>
              </div>
              <div>
                <span className="text-gray-400">Rules Triggered</span>
                <p className="text-white font-medium">{riskScore.rules_triggered}</p>
              </div>
              <div>
                <span className="text-gray-400">Data Sources</span>
                <p className="text-white font-medium">{riskScore.data_sources_available}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Summary */}
        <p className="mt-4 text-gray-300 text-sm">{riskScore.summary}</p>
      </div>

      {/* Dimension Breakdown */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          Risk Dimensions
        </h3>

        <div className="space-y-3">
          {sortedDimensions.map(([dimName, dim]) => (
            <div key={dimName} className="bg-gray-900 rounded-lg p-3">
              <div 
                className="flex items-center justify-between cursor-pointer"
                onClick={() => toggleDimension(dimName)}
              >
                <div className="flex items-center gap-3">
                  <span className={getLevelColor(dim.level)}>
                    {getDimensionIcon(dimName)}
                  </span>
                  <span className="text-white font-medium">
                    {formatDimensionName(dimName)}
                  </span>
                  {dim.indicators.length > 0 && (
                    <span className="text-xs text-gray-500">
                      ({dim.indicators.length} indicators)
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <span className={`font-bold ${getLevelColor(dim.level)}`}>
                    {dim.score}
                  </span>
                  {expandedDimensions.has(dimName) ? (
                    <ChevronDown className="w-4 h-4 text-gray-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-400" />
                  )}
                </div>
              </div>

              {/* Progress bar */}
              <div className="mt-2 h-2 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={`h-full ${getLevelBgColor(dim.level)} transition-all duration-300`}
                  style={{ width: `${dim.score}%` }}
                />
              </div>

              {/* Expanded content */}
              {expandedDimensions.has(dimName) && dim.indicators.length > 0 && (
                <div className="mt-3 pl-7 border-l border-gray-700 space-y-1">
                  {dim.indicators.map((indicator, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-sm">
                      <AlertCircle className="w-3 h-3 text-gray-500 mt-1 flex-shrink-0" />
                      <span className="text-gray-400">{indicator}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Top Indicators */}
      {riskScore.top_indicators.length > 0 && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            Key Findings
          </h3>
          <div className="space-y-2">
            {riskScore.top_indicators.map((indicator, idx) => (
              <div 
                key={idx}
                className="flex items-center gap-3 p-2 bg-gray-900 rounded-lg"
              >
                <span className="w-6 h-6 rounded-full bg-yellow-500/20 text-yellow-400 flex items-center justify-center text-xs font-bold">
                  {idx + 1}
                </span>
                <span className="text-gray-300">{indicator}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Techniques */}
      {riskScore.mitre_techniques.length > 0 && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-purple-400" />
            MITRE ATT&CK Techniques
          </h3>
          <div className="grid grid-cols-2 gap-3">
            {riskScore.mitre_techniques.map((tech, idx) => (
              <a
                key={idx}
                href={`https://attack.mitre.org/techniques/${tech.technique_id.includes('.') ? tech.technique_id.replace('.', '/') : tech.technique_id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700 hover:border-purple-500 transition-colors group"
              >
                <div>
                  <span className="text-purple-400 font-mono text-sm">{tech.technique_id}</span>
                  <p className="text-white text-sm font-medium">{tech.name}</p>
                  <p className="text-xs text-gray-500">{tech.tactic}</p>
                </div>
                <ExternalLink className="w-4 h-4 text-gray-500 group-hover:text-purple-400" />
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Actions */}
      {riskScore.recommended_actions.length > 0 && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div 
            className="flex items-center justify-between cursor-pointer"
            onClick={() => setShowActions(!showActions)}
          >
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              Recommended Actions
            </h3>
            {showActions ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </div>

          {showActions && (
            <div className="mt-4 space-y-2">
              {riskScore.recommended_actions.map((action, idx) => (
                <div 
                  key={idx}
                  className="flex items-start gap-3 p-3 bg-gray-900 rounded-lg"
                >
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    action.priority === 1 ? 'bg-red-500/20 text-red-400' :
                    action.priority === 2 ? 'bg-orange-500/20 text-orange-400' :
                    action.priority === 3 ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-gray-500/20 text-gray-400'
                  }`}>
                    P{action.priority}
                  </span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-medium">{action.action}</span>
                      {action.automated && (
                        <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">
                          Auto
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{action.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* API Status */}
      {apiStatus && Object.keys(apiStatus).length > 0 && (
        <div className="bg-gray-800 rounded-xl p-4 border border-gray-700">
          <h4 className="text-sm font-medium text-gray-400 mb-3">Threat Intel API Status</h4>
          <div className="flex flex-wrap gap-2">
            {Object.entries(apiStatus).map(([api, status]) => (
              <div 
                key={api}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs ${
                  status === 'OK' 
                    ? 'bg-green-500/10 text-green-400' 
                    : status.includes('limited') 
                    ? 'bg-yellow-500/10 text-yellow-400'
                    : 'bg-red-500/10 text-red-400'
                }`}
              >
                {status === 'OK' ? (
                  <CheckCircle className="w-3 h-3" />
                ) : (
                  <AlertCircle className="w-3 h-3" />
                )}
                <span className="font-medium">{api}</span>
                {status !== 'OK' && (
                  <span className="text-gray-500">({status})</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default RiskScorePanel;
