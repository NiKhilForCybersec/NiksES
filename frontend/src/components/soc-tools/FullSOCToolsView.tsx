/**
 * NiksES Full SOC Tools View
 * 
 * Comprehensive view combining all SOC analyst utilities:
 * - SOC Tools Panel (IOCs, Rules, Tickets, Playbooks, Notifications)
 * - Executive Summary
 * - Email Timeline
 * - Threat Intel Lookups
 */

import React, { useState } from 'react';
import {
  Shield,
  X,
  Clipboard,
  FileText,
  Clock,
  Database,
  Building,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import SOCToolsPanel from './SOCToolsPanel';
import ExecutiveSummary from './ExecutiveSummary';
import EmailTimeline from './EmailTimeline';
import ThreatIntelPanel from './ThreatIntelPanel';

interface FullSOCToolsViewProps {
  analysisResult: any;
  isOpen: boolean;
  onClose: () => void;
}

type SOCTab = 'tools' | 'executive' | 'timeline' | 'threatintel';

const FullSOCToolsView: React.FC<FullSOCToolsViewProps> = ({
  analysisResult,
  isOpen,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<SOCTab>('tools');
  const [collapsed, setCollapsed] = useState(false);

  if (!isOpen) return null;

  // Detect analysis type
  const isUrlAnalysis = analysisResult?.email?.sender?.email?.includes('url@analysis') ||
                        analysisResult?.email?.subject?.toLowerCase().includes('url analysis');
  const isSmsAnalysis = analysisResult?.email?.sender?.email?.includes('sms@analysis') ||
                        analysisResult?.email?.subject?.toLowerCase().includes('sms analysis');
  const isTextAnalysis = isUrlAnalysis || isSmsAnalysis;

  const tabs: { id: SOCTab; label: string; icon: React.ReactNode }[] = [
    { id: 'tools', label: 'SOC Tools', icon: <Clipboard className="w-4 h-4" /> },
    { id: 'executive', label: 'Executive Summary', icon: <Building className="w-4 h-4" /> },
    { 
      id: 'timeline', 
      label: isTextAnalysis ? 'Analysis Flow' : 'Email Timeline', 
      icon: <Clock className="w-4 h-4" /> 
    },
    { id: 'threatintel', label: 'Threat Intel', icon: <Database className="w-4 h-4" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/50 backdrop-blur-sm hidden md:block"
        onClick={onClose}
      />
      
      {/* Panel - Full screen on mobile, side panel on desktop */}
      <div 
        className={`relative md:ml-auto bg-gray-800 h-full shadow-2xl transition-all duration-300 flex flex-col w-full md:w-[90%] md:max-w-6xl ${
          collapsed ? 'md:w-16' : ''
        }`}
      >
        {/* Collapse Toggle - Hidden on mobile */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -left-4 top-1/2 transform -translate-y-1/2 w-8 h-8 bg-indigo-600 rounded-full items-center justify-center text-white shadow-lg hover:bg-indigo-700 z-10 hidden md:flex"
        >
          {collapsed ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>

        {collapsed ? (
          /* Collapsed View - Just Icons (Desktop only) */
          <div className="hidden md:flex flex-col items-center py-4 gap-4">
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-700 rounded-lg"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setCollapsed(false);
                }}
                className={`p-2 rounded-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-indigo-100 text-indigo-600'
                    : 'hover:bg-gray-700 text-gray-400'
                }`}
                title={tab.label}
              >
                {tab.icon}
              </button>
            ))}
          </div>
        ) : (
          /* Expanded View */
          <>
            {/* Header */}
            <div className="flex items-center justify-between px-4 md:px-6 py-3 md:py-4 border-b bg-gradient-to-r from-indigo-600 to-purple-600 text-white">
              <div className="flex items-center gap-2 md:gap-3">
                <Shield className="w-5 h-5 md:w-6 md:h-6" />
                <div>
                  <h2 className="text-lg md:text-xl font-bold">SOC Toolkit</h2>
                  <p className="text-xs md:text-sm text-indigo-200 hidden sm:block">
                    Incident investigation & response
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-2 hover:bg-gray-800/10 rounded-lg transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Tabs - Scrollable on mobile */}
            <div className="flex border-b bg-gray-900 px-2 md:px-4 overflow-x-auto hide-scrollbar">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-1.5 md:gap-2 px-3 md:px-4 py-2.5 md:py-3 border-b-2 transition-colors whitespace-nowrap text-sm md:text-base ${
                    activeTab === tab.id
                      ? 'border-indigo-600 text-indigo-600 bg-gray-800'
                      : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-gray-700'
                  }`}
                >
                  {tab.icon}
                  <span className="font-medium">{tab.label}</span>
                </button>
              ))}
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-3 md:p-6 bg-gray-900">
              {activeTab === 'tools' && (
                <SOCToolsPanel analysisResult={analysisResult} />
              )}
              {activeTab === 'executive' && (
                <ExecutiveSummary analysisResult={analysisResult} />
              )}
              {activeTab === 'timeline' && (
                <EmailTimeline analysisResult={analysisResult} />
              )}
              {activeTab === 'threatintel' && (
                <ThreatIntelPanel analysisResult={analysisResult} />
              )}
            </div>

            {/* Footer */}
            <div className="px-3 md:px-6 py-2 md:py-3 border-t bg-gray-800 text-xs md:text-sm text-gray-400 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1">
              <span className="truncate max-w-full">
                ID: {analysisResult?.analysis_id?.slice(0, 8) || 'N/A'}...
              </span>
              <span>
                {analysisResult?.analyzed_at 
                  ? new Date(analysisResult.analyzed_at).toLocaleString() 
                  : 'N/A'}
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default FullSOCToolsView;
