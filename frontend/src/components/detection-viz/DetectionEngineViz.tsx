/**
 * Detection Engine Visualization
 * 
 * A stunning visual representation of the Dynamic Intelligent Detection Architecture (DIDA)
 * Shows how evidence flows through the system and combines into a final score.
 * 
 * USES REAL ANALYSIS DATA - no hardcoded values!
 */

import React, { useState, useEffect } from 'react';

// Types
interface EvidenceNode {
  id: string;
  label: string;
  category: 'technical' | 'social' | 'brand' | 'ti' | 'content';
  quality: number;
  active?: boolean;
}

interface DimensionScore {
  name: string;
  score: number;
  weight: number;
  color: string;
  gradient: string;
}

interface AttackChain {
  name: string;
  confidence: number;
  icon: string;
}

interface DetectionVizProps {
  isOpen: boolean;
  onClose: () => void;
  // Real analysis data from API
  analysisData?: {
    score?: number;
    level?: string;
    confidence?: number;
    evidenceCount?: number;
    attackChains?: any[];
    dimensions?: any;
    rules_triggered?: any[];
    ti_results?: any;
    breakdown?: any;
  };
}

// Map category to display info
const CATEGORY_CONFIG: Record<string, { color: string; icon: string }> = {
  technical: { color: '#3b82f6', icon: '⚙️' },
  authentication: { color: '#3b82f6', icon: '🔐' },
  social_engineering: { color: '#f59e0b', icon: '🎭' },
  brand_impersonation: { color: '#8b5cf6', icon: '🏷️' },
  threat_intel: { color: '#ef4444', icon: '🔍' },
  content: { color: '#10b981', icon: '📄' },
  infrastructure: { color: '#06b6d4', icon: '🌐' },
  behavioral: { color: '#ec4899', icon: '👤' },
};

const DetectionEngineViz: React.FC<DetectionVizProps> = ({ 
  isOpen, 
  onClose,
  analysisData 
}) => {
  const [animationPhase, setAnimationPhase] = useState(0);
  const [activeEvidence, setActiveEvidence] = useState<Set<string>>(new Set());
  const [showScore, setShowScore] = useState(false);
  const [particles, setParticles] = useState<Array<{ id: number; x: number; y: number; color: string }>>([]);

  // Extract real data or use defaults for demo mode
  const hasRealData = analysisData && (analysisData.score !== undefined || analysisData.rules_triggered?.length);
  
  const finalScore = analysisData?.score ?? 0;
  const confidence = analysisData?.confidence ?? 0;
  const level = analysisData?.level || 'informational';
  
  // Build evidence from real rules_triggered
  const evidence: EvidenceNode[] = React.useMemo(() => {
    if (analysisData?.rules_triggered && analysisData.rules_triggered.length > 0) {
      return analysisData.rules_triggered.slice(0, 10).map((rule: any, i: number) => ({
        id: `e${i}`,
        label: rule.description || rule.rule_id || `Rule ${i + 1}`,
        category: rule.category?.toLowerCase() || 'content',
        quality: (rule.score || rule.weight || 50) / 100,
      }));
    }
    // No data - show empty state
    return [];
  }, [analysisData?.rules_triggered]);

  // Build dimensions from breakdown or estimate from score
  const dimensions: DimensionScore[] = React.useMemo(() => {
    if (analysisData?.breakdown) {
      const b = analysisData.breakdown;
      return [
        { name: 'Threat Intel', score: Math.round(b.ti_score || 0), weight: b.ti_weight || 0.40, color: '#ef4444', gradient: 'from-red-500 to-orange-500' },
        { name: 'Evidence', score: Math.round(b.evidence_score || 0), weight: b.evidence_weight || 0.35, color: '#3b82f6', gradient: 'from-blue-500 to-cyan-500' },
        { name: 'Attack Chains', score: Math.round(b.chain_score || 0), weight: b.chain_weight || 0.18, color: '#f59e0b', gradient: 'from-amber-500 to-yellow-500' },
        { name: 'AI Analysis', score: Math.round(b.ai_score || 0), weight: b.ai_weight || 0.12, color: '#8b5cf6', gradient: 'from-violet-500 to-purple-500' },
      ].filter(d => d.score > 0 || d.weight > 0);
    }
    // Estimate from final score
    if (finalScore > 0) {
      return [
        { name: 'Detection Score', score: finalScore, weight: 1.0, color: '#ef4444', gradient: 'from-red-500 to-orange-500' },
      ];
    }
    return [];
  }, [analysisData?.breakdown, finalScore]);

  // Build attack chains from real data
  const attackChains: AttackChain[] = React.useMemo(() => {
    if (analysisData?.attackChains && analysisData.attackChains.length > 0) {
      return analysisData.attackChains.map((chain: any) => ({
        name: chain.name?.replace(/_/g, ' ') || 'Unknown Chain',
        confidence: chain.confidence || 0,
        icon: chain.ti_confirmation ? '⛓️' : '🔗',
      }));
    }
    return [];
  }, [analysisData?.attackChains]);

  // Animation sequence
  useEffect(() => {
    if (!isOpen) {
      setAnimationPhase(0);
      setActiveEvidence(new Set());
      setShowScore(false);
      return;
    }

    // Phase 1: Evidence flows in
    const timer1 = setTimeout(() => {
      setAnimationPhase(1);
      evidence.forEach((e, i) => {
        setTimeout(() => {
          setActiveEvidence(prev => new Set([...prev, e.id]));
        }, i * 150);
      });
    }, 300);

    // Phase 2: Processing
    const timer2 = setTimeout(() => setAnimationPhase(2), Math.max(1800, evidence.length * 150 + 500));

    // Phase 3: Score reveal
    const timer3 = setTimeout(() => {
      setAnimationPhase(3);
      setShowScore(true);
    }, Math.max(2500, evidence.length * 150 + 1000));

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
    };
  }, [isOpen, evidence.length]);

  // Particle effect
  useEffect(() => {
    if (!isOpen || animationPhase < 2) return;

    const interval = setInterval(() => {
      setParticles(prev => {
        const newParticles = [...prev];
        if (newParticles.length < 15) {
          newParticles.push({
            id: Date.now(),
            x: Math.random() * 100,
            y: Math.random() * 100,
            color: ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981'][Math.floor(Math.random() * 5)]
          });
        }
        return newParticles.slice(-12);
      });
    }, 250);

    return () => clearInterval(interval);
  }, [isOpen, animationPhase]);

  if (!isOpen) return null;

  const getLevelColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'from-red-600 to-red-400';
      case 'high': return 'from-orange-600 to-orange-400';
      case 'medium': return 'from-yellow-600 to-yellow-400';
      case 'low': return 'from-green-600 to-green-400';
      default: return 'from-gray-600 to-gray-400';
    }
  };

  const getCategoryColor = (category: string) => {
    return CATEGORY_CONFIG[category]?.color || '#64748b';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-5xl max-h-[90vh] overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 border border-slate-700/50 shadow-2xl">
        {/* Animated background particles */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          {particles.map(p => (
            <div
              key={p.id}
              className="absolute w-2 h-2 rounded-full opacity-30 animate-ping"
              style={{
                left: `${p.x}%`,
                top: `${p.y}%`,
                backgroundColor: p.color,
              }}
            />
          ))}
        </div>

        {/* Grid pattern overlay */}
        <div 
          className="absolute inset-0 opacity-5"
          style={{
            backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
            backgroundSize: '20px 20px'
          }}
        />

        {/* Header */}
        <div className="relative px-6 py-4 border-b border-slate-700/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">Dynamic Intelligent Detection</h2>
                <p className="text-sm text-slate-400">
                  DIDA v3.0 • {hasRealData ? 'Live Analysis Data' : 'Demo Mode'}
                </p>
              </div>
            </div>
            <button 
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-slate-700/50 transition-colors"
            >
              <svg className="w-5 h-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div className="relative p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          {/* No Data State */}
          {!hasRealData && evidence.length === 0 && (
            <div className="text-center py-12">
              <div className="text-6xl mb-4">🔬</div>
              <h3 className="text-xl font-bold text-slate-200 mb-2">No Analysis Data</h3>
              <p className="text-slate-400 max-w-md mx-auto">
                Run an analysis first to see how the Dynamic Intelligent Detection Architecture 
                calculates risk scores from evidence, threat intelligence, and attack chain patterns.
              </p>
            </div>
          )}

          {/* Flow Diagram - Only show with data */}
          {(hasRealData || evidence.length > 0) && (
            <div className="grid grid-cols-12 gap-4 mb-8">
              {/* Evidence Sources */}
              <div className="col-span-3">
                <div className="text-sm font-medium text-slate-400 mb-3 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  Evidence ({evidence.length})
                </div>
                <div className="space-y-2 max-h-80 overflow-y-auto pr-2">
                  {evidence.map((ev, i) => (
                    <div
                      key={ev.id}
                      className={`
                        relative px-3 py-2 rounded-lg border transition-all duration-500
                        ${activeEvidence.has(ev.id) 
                          ? 'bg-slate-800/80 border-slate-600 translate-x-0 opacity-100' 
                          : 'bg-slate-800/30 border-slate-700/30 -translate-x-4 opacity-0'}
                      `}
                      style={{ transitionDelay: `${i * 100}ms` }}
                    >
                      <div className="flex items-center gap-2">
                        <div 
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: getCategoryColor(ev.category) }}
                        />
                        <span className="text-xs text-slate-300 truncate">{ev.label}</span>
                      </div>
                      <div className="mt-1 h-1 bg-slate-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full rounded-full transition-all duration-1000"
                          style={{ 
                            width: activeEvidence.has(ev.id) ? `${ev.quality * 100}%` : '0%',
                            backgroundColor: getCategoryColor(ev.category),
                            transitionDelay: `${i * 100 + 300}ms`
                          }}
                        />
                      </div>
                    </div>
                  ))}
                  {evidence.length === 0 && (
                    <div className="text-sm text-slate-500 italic">No evidence collected</div>
                  )}
                </div>
              </div>

              {/* Flow Lines SVG */}
              <div className="col-span-1 flex items-center justify-center">
                <svg className="w-full h-64" viewBox="0 0 50 200">
                  {[0, 1, 2, 3, 4].map(i => (
                    <g key={i}>
                      <path
                        d={`M 0 ${30 + i * 35} Q 25 ${30 + i * 35}, 50 100`}
                        fill="none"
                        stroke={`url(#gradient-${i})`}
                        strokeWidth="2"
                        strokeDasharray="5,5"
                        className={animationPhase >= 1 ? 'animate-dash' : 'opacity-20'}
                      />
                      <defs>
                        <linearGradient id={`gradient-${i}`} x1="0%" y1="0%" x2="100%" y2="0%">
                          <stop offset="0%" stopColor={['#3b82f6', '#f59e0b', '#8b5cf6', '#ef4444', '#10b981'][i]} />
                          <stop offset="100%" stopColor="#64748b" />
                        </linearGradient>
                      </defs>
                    </g>
                  ))}
                </svg>
              </div>

              {/* Processing Dimensions */}
              <div className="col-span-4">
                <div className="text-sm font-medium text-slate-400 mb-3 flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full bg-violet-400 ${animationPhase >= 2 ? 'animate-pulse' : 'opacity-30'}`} />
                  Scoring Dimensions
                </div>
                <div className="space-y-3">
                  {dimensions.map((dim, i) => (
                    <div
                      key={dim.name}
                      className={`
                        relative p-3 rounded-xl border transition-all duration-500
                        ${animationPhase >= 2 
                          ? 'bg-slate-800/60 border-slate-600 scale-100 opacity-100' 
                          : 'bg-slate-800/20 border-slate-700/30 scale-95 opacity-30'}
                      `}
                      style={{ transitionDelay: `${i * 100}ms` }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <div 
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: dim.color }}
                          />
                          <span className="text-sm font-medium text-slate-200">{dim.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-500">{(dim.weight * 100).toFixed(0)}%</span>
                          <span 
                            className={`text-sm font-bold bg-gradient-to-r ${dim.gradient} bg-clip-text text-transparent`}
                          >
                            {animationPhase >= 2 ? dim.score : '--'}
                          </span>
                        </div>
                      </div>
                      <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${dim.gradient} transition-all duration-1000 ease-out`}
                          style={{ 
                            width: animationPhase >= 2 ? `${Math.min(dim.score, 100)}%` : '0%',
                            transitionDelay: `${i * 150}ms`
                          }}
                        />
                      </div>
                    </div>
                  ))}
                  {dimensions.length === 0 && (
                    <div className="text-sm text-slate-500 italic p-3">No dimension data available</div>
                  )}
                </div>

                {/* Attack Chains */}
                {attackChains.length > 0 && (
                  <div className="mt-4">
                    <div className="text-sm font-medium text-slate-400 mb-2 flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full bg-orange-400 ${animationPhase >= 2 ? 'animate-pulse' : 'opacity-30'}`} />
                      Attack Chains ({attackChains.length})
                    </div>
                    <div className="space-y-2">
                      {attackChains.map((chain, i) => (
                        <div
                          key={chain.name}
                          className={`
                            flex items-center justify-between px-3 py-2 rounded-lg
                            bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30
                            transition-all duration-500
                            ${animationPhase >= 2 ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'}
                          `}
                          style={{ transitionDelay: `${(i + 5) * 100}ms` }}
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-lg">{chain.icon}</span>
                            <span className="text-sm text-slate-300 capitalize">{chain.name}</span>
                          </div>
                          <span className="text-sm font-bold text-orange-400">
                            {(chain.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Flow Lines to Score */}
              <div className="col-span-1 flex items-center justify-center">
                <svg className="w-full h-64" viewBox="0 0 50 200">
                  <path
                    d="M 0 100 L 50 100"
                    fill="none"
                    stroke="url(#score-gradient)"
                    strokeWidth="3"
                    strokeDasharray="10,5"
                    className={animationPhase >= 3 ? 'animate-dash' : 'opacity-20'}
                  />
                  <defs>
                    <linearGradient id="score-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#64748b" />
                      <stop offset="100%" stopColor="#ef4444" />
                    </linearGradient>
                  </defs>
                </svg>
              </div>

              {/* Final Score */}
              <div className="col-span-3 flex items-center justify-center">
                <div
                  className={`
                    relative w-48 h-48 rounded-2xl
                    bg-gradient-to-br from-slate-800 to-slate-900
                    border border-slate-600
                    flex flex-col items-center justify-center
                    transition-all duration-700
                    ${showScore ? 'scale-100 opacity-100' : 'scale-75 opacity-0'}
                  `}
                >
                  {/* Glow effect */}
                  <div 
                    className={`
                      absolute inset-0 rounded-2xl blur-xl opacity-30
                      bg-gradient-to-br ${getLevelColor(level)}
                    `}
                  />
                  
                  {/* Score ring */}
                  <svg className="absolute inset-0 w-full h-full -rotate-90">
                    <circle
                      cx="50%"
                      cy="50%"
                      r="45%"
                      fill="none"
                      stroke="#334155"
                      strokeWidth="8"
                    />
                    <circle
                      cx="50%"
                      cy="50%"
                      r="45%"
                      fill="none"
                      stroke="url(#score-ring-gradient)"
                      strokeWidth="8"
                      strokeLinecap="round"
                      strokeDasharray={`${(finalScore / 100) * 283} 283`}
                      className="transition-all duration-1000 ease-out"
                      style={{ 
                        strokeDasharray: showScore ? `${(finalScore / 100) * 283} 283` : '0 283'
                      }}
                    />
                    <defs>
                      <linearGradient id="score-ring-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#ef4444" />
                        <stop offset="100%" stopColor="#f59e0b" />
                      </linearGradient>
                    </defs>
                  </svg>

                  {/* Score value */}
                  <div className="relative z-10 text-center">
                    <div 
                      className={`text-5xl font-black bg-gradient-to-r ${getLevelColor(level)} bg-clip-text text-transparent`}
                    >
                      {showScore ? finalScore : '--'}
                    </div>
                    <div className="text-sm font-bold text-slate-400 uppercase tracking-wider mt-1">
                      {level}
                    </div>
                    <div className="text-xs text-slate-500 mt-2">
                      {(confidence * 100).toFixed(0)}% confidence
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Formula Section */}
          {hasRealData && (
            <div 
              className={`
                mt-6 p-4 rounded-xl bg-slate-800/50 border border-slate-700/50
                transition-all duration-500
                ${animationPhase >= 3 ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
              `}
            >
              <div className="text-sm font-medium text-slate-400 mb-3">Scoring Formula</div>
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-slate-500">(</span>
                <span className="px-2 py-1 rounded bg-slate-700 text-slate-300">Evidence Quality</span>
                <span className="text-slate-500">×</span>
                <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">Validation</span>
                <span className="text-slate-500">×</span>
                <span className="px-2 py-1 rounded bg-violet-500/20 text-violet-400 border border-violet-500/30">Correlation</span>
                <span className="text-slate-500">) +</span>
                <span className="px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30">TI Consensus</span>
                <span className="text-slate-500">+</span>
                <span className="px-2 py-1 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">Chain Bonus</span>
                <span className="text-slate-500">=</span>
                <span className="px-3 py-1 rounded-lg bg-gradient-to-r from-red-500 to-orange-500 text-white font-bold">
                  {finalScore}
                </span>
              </div>
            </div>
          )}

          {/* Key Principles */}
          <div 
            className={`
              mt-4 grid grid-cols-2 md:grid-cols-4 gap-3
              transition-all duration-500 delay-200
              ${animationPhase >= 3 || !hasRealData ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
            `}
          >
            {[
              { icon: '🔍', title: 'TI is King', desc: 'External validation heavily weighted' },
              { icon: '🔗', title: 'Correlation', desc: 'Multiple sources = higher confidence' },
              { icon: '⚖️', title: 'Quality > Quantity', desc: '3 strong evidence > 10 weak' },
              { icon: '🎯', title: 'Zero Hardcoding', desc: 'All values calculated dynamically' },
            ].map((principle) => (
              <div
                key={principle.title}
                className="p-3 rounded-lg bg-slate-800/30 border border-slate-700/30 hover:border-slate-600 transition-colors"
              >
                <div className="text-xl mb-1">{principle.icon}</div>
                <div className="text-sm font-medium text-slate-200">{principle.title}</div>
                <div className="text-xs text-slate-500">{principle.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="relative px-6 py-3 border-t border-slate-700/50 bg-slate-800/30">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>
              {evidence.length} Evidence • {attackChains.length} Chains • {dimensions.length} Dimensions
            </span>
            <span>NiksES Detection Engine v3.0</span>
          </div>
        </div>
      </div>

      {/* CSS Animations */}
      <style>{`
        @keyframes dash {
          to {
            stroke-dashoffset: -20;
          }
        }
        .animate-dash {
          animation: dash 1s linear infinite;
        }
      `}</style>
    </div>
  );
};

export default DetectionEngineViz;
