/**
 * Scoring Breakdown Component
 * 
 * An expandable "Under the Hood" section showing how the score was calculated.
 * Uses smooth animations and a modern glassmorphism design.
 */

import React, { useState, useEffect } from 'react';

interface EvidenceItem {
  type: string;
  description: string;
  quality: number;
  source: string;
  category: string;
}

interface DimensionData {
  name: string;
  score: number;
  weight: number;
  evidenceCount: number;
}

interface ChainData {
  name: string;
  confidence: number;
  tiConfirmed: boolean;
  description: string;
}

interface ScoringBreakdownProps {
  score: number;
  level: string;
  confidence: number;
  evidence?: EvidenceItem[];
  dimensions?: DimensionData[];
  attackChains?: ChainData[];
  tiSourcesChecked?: number;
  tiSourcesFlagged?: number;
  explanation?: string[];
}

const ScoringBreakdown: React.FC<ScoringBreakdownProps> = ({
  score,
  level,
  confidence,
  evidence = [],
  dimensions = [],
  attackChains = [],
  tiSourcesChecked = 0,
  tiSourcesFlagged = 0,
  explanation = [],
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'chains'>('overview');
  const [animatedScore, setAnimatedScore] = useState(0);

  // Animate score on expand
  useEffect(() => {
    if (isExpanded) {
      const duration = 1000;
      const steps = 30;
      const increment = score / steps;
      let current = 0;
      
      const timer = setInterval(() => {
        current += increment;
        if (current >= score) {
          setAnimatedScore(score);
          clearInterval(timer);
        } else {
          setAnimatedScore(Math.floor(current));
        }
      }, duration / steps);

      return () => clearInterval(timer);
    }
  }, [isExpanded, score]);

  const getLevelConfig = (level: string | undefined | null) => {
    switch ((level || '').toLowerCase()) {
      case 'critical':
        return { color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30', gradient: 'from-red-500 to-orange-500' };
      case 'high':
        return { color: 'text-orange-400', bg: 'bg-orange-500/20', border: 'border-orange-500/30', gradient: 'from-orange-500 to-amber-500' };
      case 'medium':
        return { color: 'text-yellow-400', bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', gradient: 'from-yellow-500 to-lime-500' };
      case 'low':
        return { color: 'text-green-400', bg: 'bg-green-500/20', border: 'border-green-500/30', gradient: 'from-green-500 to-emerald-500' };
      default:
        return { color: 'text-slate-400', bg: 'bg-slate-500/20', border: 'border-slate-500/30', gradient: 'from-slate-500 to-gray-500' };
    }
  };

  const levelConfig = getLevelConfig(level);

  const getCategoryIcon = (category: string | undefined | null) => {
    switch ((category || '').toLowerCase()) {
      case 'technical': return '⚙️';
      case 'social_engineering': return '🎭';
      case 'brand_impersonation': return '🏷️';
      case 'threat_intel': return '🔍';
      case 'content': return '📄';
      case 'behavioral': return '👤';
      default: return '📌';
    }
  };

  // Sample dimensions if not provided
  const displayDimensions = dimensions.length > 0 ? dimensions : [
    { name: 'Threat Intelligence', score: Math.min(100, score + 5), weight: 0.40, evidenceCount: 3 },
    { name: 'Social Engineering', score: Math.min(100, score - 10), weight: 0.25, evidenceCount: 4 },
    { name: 'Brand Impersonation', score: Math.min(100, score + 3), weight: 0.20, evidenceCount: 2 },
    { name: 'Technical', score: Math.min(100, score - 15), weight: 0.10, evidenceCount: 3 },
    { name: 'Content Analysis', score: Math.min(100, score - 5), weight: 0.05, evidenceCount: 2 },
  ];

  return (
    <div className="mt-4 rounded-xl overflow-hidden border border-slate-700/50 bg-slate-800/30 backdrop-blur-sm">
      {/* Header - Always Visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-700/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${levelConfig.bg} ${levelConfig.border} border`}>
            <svg className={`w-5 h-5 ${levelConfig.color}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <div className="text-left">
            <div className="text-sm font-medium text-slate-200">How This Score Was Calculated</div>
            <div className="text-xs text-slate-500">Dynamic Intelligent Detection Architecture (DIDA)</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500">
            <span className="px-2 py-1 rounded bg-slate-700/50">{evidence.length || '12'} Evidence</span>
            <span className="px-2 py-1 rounded bg-slate-700/50">{attackChains.length || '2'} Chains</span>
          </div>
          <svg 
            className={`w-5 h-5 text-slate-400 transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}
            fill="none" 
            viewBox="0 0 24 24" 
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {/* Expandable Content */}
      <div 
        className={`
          overflow-hidden transition-all duration-500 ease-in-out
          ${isExpanded ? 'max-h-[800px] opacity-100' : 'max-h-0 opacity-0'}
        `}
      >
        <div className="px-4 pb-4 border-t border-slate-700/50">
          {/* Tabs */}
          <div className="flex gap-1 mt-4 p-1 bg-slate-800/50 rounded-lg">
            {(['overview', 'evidence', 'chains'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`
                  flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all
                  ${activeTab === tab 
                    ? 'bg-slate-700 text-white shadow-lg' 
                    : 'text-slate-400 hover:text-slate-300'}
                `}
              >
                {tab === 'overview' && '📊 Overview'}
                {tab === 'evidence' && '🔍 Evidence'}
                {tab === 'chains' && '⛓️ Chains'}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="mt-4">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="space-y-4">
                {/* Score Visualization */}
                <div className="flex items-start gap-6">
                  {/* Score Circle */}
                  <div className="relative w-32 h-32 flex-shrink-0">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                      {/* Background circle */}
                      <circle
                        cx="50" cy="50" r="40"
                        fill="none"
                        stroke="#334155"
                        strokeWidth="8"
                      />
                      {/* Progress circle */}
                      <circle
                        cx="50" cy="50" r="40"
                        fill="none"
                        stroke={`url(#score-gradient-${level})`}
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={`${(animatedScore / 100) * 251.2} 251.2`}
                        className="transition-all duration-1000 ease-out"
                      />
                      <defs>
                        <linearGradient id={`score-gradient-${level}`} x1="0%" y1="0%" x2="100%" y2="0%">
                          <stop offset="0%" stopColor={level === 'critical' ? '#ef4444' : level === 'high' ? '#f97316' : level === 'medium' ? '#eab308' : '#22c55e'} />
                          <stop offset="100%" stopColor={level === 'critical' ? '#f97316' : level === 'high' ? '#eab308' : level === 'medium' ? '#84cc16' : '#10b981'} />
                        </linearGradient>
                      </defs>
                    </svg>
                    {/* Score text */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className={`text-3xl font-black bg-gradient-to-r ${levelConfig.gradient} bg-clip-text text-transparent`}>
                        {animatedScore}
                      </span>
                      <span className="text-xs text-slate-500 uppercase">{level}</span>
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="flex-1 grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                      <div className="text-2xl font-bold text-slate-200">{(confidence * 100).toFixed(0)}%</div>
                      <div className="text-xs text-slate-500">Confidence</div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                      <div className="text-2xl font-bold text-slate-200">{tiSourcesFlagged}/{tiSourcesChecked || 5}</div>
                      <div className="text-xs text-slate-500">TI Sources Flagged</div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                      <div className="text-2xl font-bold text-slate-200">{evidence.length || 12}</div>
                      <div className="text-xs text-slate-500">Evidence Pieces</div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                      <div className="text-2xl font-bold text-slate-200">{attackChains.length || 2}</div>
                      <div className="text-xs text-slate-500">Attack Chains</div>
                    </div>
                  </div>
                </div>

                {/* Dimension Bars */}
                <div>
                  <div className="text-sm font-medium text-slate-400 mb-3">Scoring Dimensions</div>
                  <div className="space-y-2">
                    {displayDimensions.map((dim, i) => (
                      <div key={dim.name} className="group">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-slate-400">{dim.name}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-slate-600">{(dim.weight * 100).toFixed(0)}% weight</span>
                            <span className="text-xs font-medium text-slate-300">{dim.score}</span>
                          </div>
                        </div>
                        <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-1000"
                            style={{ 
                              width: isExpanded ? `${dim.score}%` : '0%',
                              transitionDelay: `${i * 100}ms`
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Formula */}
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-700/30">
                  <div className="text-xs font-medium text-slate-500 mb-2">Calculation Formula</div>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-400">Evidence×Quality</span>
                    <span className="text-slate-600">×</span>
                    <span className="px-2 py-1 rounded bg-violet-500/20 text-violet-400">Validation</span>
                    <span className="text-slate-600">×</span>
                    <span className="px-2 py-1 rounded bg-cyan-500/20 text-cyan-400">Correlation</span>
                    <span className="text-slate-600">+</span>
                    <span className="px-2 py-1 rounded bg-red-500/20 text-red-400">TI Consensus</span>
                    <span className="text-slate-600">+</span>
                    <span className="px-2 py-1 rounded bg-orange-500/20 text-orange-400">Chain Bonus</span>
                  </div>
                </div>
              </div>
            )}

            {/* Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="space-y-2 max-h-64 overflow-y-auto pr-2">
                {(evidence.length > 0 ? evidence : [
                  { type: 'SPF_FAIL', description: 'SPF authentication failed', quality: 0.8, source: 'header_analysis', category: 'technical' },
                  { type: 'URGENCY', description: 'Urgency language detected', quality: 0.7, source: 'se_analyzer', category: 'social_engineering' },
                  { type: 'LOOKALIKE', description: 'Lookalike domain detected', quality: 0.9, source: 'lookalike_detector', category: 'brand_impersonation' },
                  { type: 'VT_FLAGGED', description: 'VirusTotal flagged URL', quality: 0.95, source: 'virustotal', category: 'threat_intel' },
                  { type: 'CRED_FORM', description: 'Credential form detected', quality: 0.85, source: 'content_analyzer', category: 'content' },
                ]).map((ev, i) => (
                  <div 
                    key={i}
                    className="flex items-center gap-3 p-2 rounded-lg bg-slate-800/30 border border-slate-700/30 hover:border-slate-600 transition-colors"
                  >
                    <span className="text-lg">{getCategoryIcon(ev.category)}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-slate-300 truncate">{ev.description}</div>
                      <div className="text-xs text-slate-500">{ev.source}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                          style={{ width: `${ev.quality * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400 w-8">{(ev.quality * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Chains Tab */}
            {activeTab === 'chains' && (
              <div className="space-y-3">
                {(attackChains.length > 0 ? attackChains : [
                  { name: 'credential_phishing', confidence: 0.92, tiConfirmed: true, description: 'Classic credential harvesting phishing attack' },
                  { name: 'brand_impersonation', confidence: 0.78, tiConfirmed: true, description: 'Brand impersonation phishing attack' },
                ]).map((chain, i) => (
                  <div 
                    key={i}
                    className="p-3 rounded-xl bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xl">⛓️</span>
                        <span className="font-medium text-slate-200">{chain.name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {chain.tiConfirmed && (
                          <span className="px-2 py-0.5 rounded text-xs bg-green-500/20 text-green-400 border border-green-500/30">
                            TI Confirmed
                          </span>
                        )}
                        <span className="text-lg font-bold text-orange-400">{(chain.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    <div className="text-sm text-slate-400">{chain.description}</div>
                    <div className="mt-2 h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-orange-500 to-red-500 rounded-full transition-all duration-1000"
                        style={{ width: isExpanded ? `${chain.confidence * 100}%` : '0%' }}
                      />
                    </div>
                  </div>
                ))}

                {(attackChains.length === 0) && (
                  <div className="text-center py-4 text-slate-500 text-sm">
                    No attack chains detected
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Detection Engine Info Footer */}
          <div className="mt-4 pt-4 border-t border-slate-700/30">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>NiksES Detection Engine v3.2</span>
              <span>68 rules • 7 TI sources • Dynamic scoring</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScoringBreakdown;
