/**
 * ActionsCard Component
 * 
 * Provides export actions and response options for analysis results.
 */

import React, { useState } from 'react';
import { 
  downloadExport, 
  getExportFilename,
  exportExecutivePDF,
  exportTechnicalPDF 
} from '../../../services/analysisService';
import type { ExportFormat, AnalysisResult } from '../../../types';

interface ActionsCardProps {
  className?: string;
  analysis: AnalysisResult;
  onReanalyze?: () => void;
}

type ExportOption = {
  format: ExportFormat;
  label: string;
  description: string;
  icon: string;
  category: 'report' | 'data' | 'integration';
};

const EXPORT_OPTIONS: ExportOption[] = [
  {
    format: 'executive-pdf',
    label: 'Executive Report',
    description: 'Professional PDF for stakeholders',
    icon: '📊',
    category: 'report',
  },
  {
    format: 'pdf',
    label: 'Technical Report',
    description: 'Detailed PDF with all findings',
    icon: '📄',
    category: 'report',
  },
  {
    format: 'markdown',
    label: 'Markdown',
    description: 'Text report for documentation',
    icon: '📝',
    category: 'report',
  },
  {
    format: 'json',
    label: 'JSON',
    description: 'Full analysis data',
    icon: '{ }',
    category: 'data',
  },
  {
    format: 'iocs',
    label: 'IOCs Only',
    description: 'Indicators of compromise',
    icon: '🎯',
    category: 'data',
  },
  {
    format: 'stix',
    label: 'STIX 2.1',
    description: 'Threat intelligence format',
    icon: '🔗',
    category: 'integration',
  },
];

export function ActionsCard({ className, analysis, onReanalyze }: ActionsCardProps) {
  const [exportingFormat, setExportingFormat] = useState<ExportFormat | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [showAllFormats, setShowAllFormats] = useState(false);

  const handleExport = async (format: ExportFormat) => {
    setExportingFormat(format);
    setExportError(null);
    
    try {
      await downloadExport(analysis.analysis_id, format);
    } catch (error) {
      console.error('Export failed:', error);
      setExportError(`Failed to export as ${format}`);
    } finally {
      setExportingFormat(null);
    }
  };

  const handleQuickExport = async (type: 'executive' | 'technical') => {
    const format: ExportFormat = type === 'executive' ? 'executive-pdf' : 'pdf';
    setExportingFormat(format);
    setExportError(null);
    
    try {
      const blob = type === 'executive' 
        ? await exportExecutivePDF(analysis.analysis_id)
        : await exportTechnicalPDF(analysis.analysis_id);
      
      const filename = getExportFilename(analysis.analysis_id, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
      setExportError(`Failed to export ${type} report`);
    } finally {
      setExportingFormat(null);
    }
  };

  const primaryOptions = EXPORT_OPTIONS.filter(opt => 
    ['executive-pdf', 'pdf', 'json'].includes(opt.format)
  );
  const additionalOptions = EXPORT_OPTIONS.filter(opt => 
    !['executive-pdf', 'pdf', 'json'].includes(opt.format)
  );

  return (
    <div className={`bg-gray-800 rounded-lg border border-gray-700 ${className || ''}`}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-700">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <span className="text-lg">⚡</span>
          Quick Actions
        </h3>
      </div>

      <div className="p-4 space-y-4">
        {/* Quick Export Buttons */}
        <div className="space-y-2">
          <p className="text-xs text-gray-400 uppercase tracking-wide">Export Report</p>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => handleQuickExport('executive')}
              disabled={exportingFormat !== null}
              className="flex items-center justify-center gap-2 px-3 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
            >
              {exportingFormat === 'executive-pdf' ? (
                <span className="animate-spin">⏳</span>
              ) : (
                <span>📊</span>
              )}
              Executive PDF
            </button>
            <button
              onClick={() => handleQuickExport('technical')}
              disabled={exportingFormat !== null}
              className="flex items-center justify-center gap-2 px-3 py-2.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
            >
              {exportingFormat === 'pdf' ? (
                <span className="animate-spin">⏳</span>
              ) : (
                <span>📄</span>
              )}
              Technical PDF
            </button>
          </div>
        </div>

        {/* All Export Formats */}
        <div className="space-y-2">
          <button
            onClick={() => setShowAllFormats(!showAllFormats)}
            className="flex items-center justify-between w-full text-xs text-gray-400 hover:text-gray-300 uppercase tracking-wide"
          >
            <span>All Export Formats</span>
            <span className="transform transition-transform duration-200" style={{ transform: showAllFormats ? 'rotate(180deg)' : 'rotate(0deg)' }}>
              ▼
            </span>
          </button>
          
          {showAllFormats && (
            <div className="space-y-1 mt-2">
              {EXPORT_OPTIONS.map((option) => (
                <button
                  key={option.format}
                  onClick={() => handleExport(option.format)}
                  disabled={exportingFormat !== null}
                  className="flex items-center gap-3 w-full px-3 py-2 bg-gray-700/50 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors text-left"
                >
                  <span className="text-lg w-6 text-center">
                    {exportingFormat === option.format ? '⏳' : option.icon}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white font-medium">{option.label}</p>
                    <p className="text-xs text-gray-400 truncate">{option.description}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Re-analyze Button */}
        {onReanalyze && (
          <div className="pt-2 border-t border-gray-700">
            <button
              onClick={onReanalyze}
              className="flex items-center justify-center gap-2 w-full px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition-colors"
            >
              <span>🔄</span>
              Re-analyze with Different Options
            </button>
          </div>
        )}

        {/* Error Display */}
        {exportError && (
          <div className="p-2 bg-red-900/30 border border-red-700 rounded-lg">
            <p className="text-xs text-red-400">{exportError}</p>
          </div>
        )}

        {/* Analysis Info */}
        <div className="pt-2 border-t border-gray-700 text-xs text-gray-500">
          <p>Analysis ID: {analysis.analysis_id.slice(0, 8)}...</p>
          <p>Completed: {new Date(analysis.analyzed_at).toLocaleString()}</p>
        </div>
      </div>
    </div>
  );
}

export default ActionsCard;
