/**
 * NiksES History Panel
 * 
 * View, search, filter, and manage past email analyses.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  History, Search, Filter, Trash2, Eye, Download,
  ChevronLeft, ChevronRight, RefreshCw, Calendar,
  AlertTriangle, Shield, ShieldAlert, ShieldCheck, ShieldX,
  Mail, Paperclip, Link, Clock, X, Check,
  SortAsc, SortDesc, Loader2, Database, AlertCircle
} from 'lucide-react';
import { toast } from 'react-hot-toast';

interface AnalysisSummary {
  analysis_id: string;
  analyzed_at: string;
  subject: string | null;
  sender_email: string | null;
  sender_domain: string | null;
  risk_score: number;
  risk_level: string;
  classification: string;
  has_attachments: boolean;
  has_urls: boolean;
  attachment_count: number;
  url_count: number;
  ai_summary: string | null;
}

interface HistoryPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onViewAnalysis: (analysisId: string) => void;
  onExportAnalysis: (analysisId: string, format: string) => void;
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const HistoryPanel: React.FC<HistoryPanelProps> = ({
  isOpen,
  onClose,
  onViewAnalysis,
  onExportAnalysis,
}) => {
  // State
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  
  // Filters
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<string>('');
  const [classificationFilter, setClassificationFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('analyzed_at');
  const [sortOrder, setSortOrder] = useState<string>('desc');
  
  // Selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectAll, setSelectAll] = useState(false);
  
  // Delete confirmation
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [deleteAllConfirm, setDeleteAllConfirm] = useState(false);

  // Fetch analyses
  const fetchAnalyses = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
      });
      
      if (search) params.append('search', search);
      if (riskFilter) params.append('risk_level', riskFilter);
      if (classificationFilter) params.append('classification', classificationFilter);
      
      const response = await fetch(`${API_BASE}/api/v1/analyses?${params}`);
      
      if (response.ok) {
        const data = await response.json();
        setAnalyses(data.analyses || []);
        setTotal(data.total || 0);
      } else {
        toast.error('Failed to load history');
      }
    } catch (error) {
      console.error('Failed to fetch analyses:', error);
      toast.error('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, riskFilter, classificationFilter, sortBy, sortOrder]);

  // Load on open
  useEffect(() => {
    if (isOpen) {
      fetchAnalyses();
    }
  }, [isOpen, fetchAnalyses]);

  // Delete single analysis
  const deleteAnalysis = async (analysisId: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/analyses/${analysisId}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        toast.success('Analysis deleted');
        setDeleteConfirm(null);
        fetchAnalyses();
      } else {
        toast.error('Failed to delete analysis');
      }
    } catch (error) {
      toast.error('Failed to delete analysis');
    }
  };

  // Delete all analyses
  const deleteAllAnalyses = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/analyses`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        const data = await response.json();
        toast.success(`Deleted ${data.count} analyses`);
        setDeleteAllConfirm(false);
        fetchAnalyses();
      } else {
        toast.error('Failed to delete analyses');
      }
    } catch (error) {
      toast.error('Failed to delete analyses');
    }
  };

  // Delete selected
  const deleteSelected = async () => {
    for (const id of selectedIds) {
      await fetch(`${API_BASE}/api/v1/analyses/${id}`, { method: 'DELETE' });
    }
    toast.success(`Deleted ${selectedIds.size} analyses`);
    setSelectedIds(new Set());
    fetchAnalyses();
  };

  // Toggle selection
  const toggleSelect = (id: string) => {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  };

  // Toggle select all
  const toggleSelectAll = () => {
    if (selectAll) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(analyses.map(a => a.analysis_id)));
    }
    setSelectAll(!selectAll);
  };

  // Risk level colors
  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-green-100 text-green-800 border-green-200';
    }
  };

  // Classification badge
  const getClassificationBadge = (classification: string) => {
    const colors: Record<string, string> = {
      'phishing': 'bg-red-500',
      'bec': 'bg-orange-500',
      'malware': 'bg-purple-500',
      'spam': 'bg-yellow-500',
      'legitimate': 'bg-green-500',
    };
    return colors[classification?.toLowerCase()] || 'bg-gray-500';
  };

  // Pagination
  const totalPages = Math.ceil(total / pageSize);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-6xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b bg-gray-50 rounded-t-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-100 rounded-lg">
              <History className="w-5 h-5 text-indigo-600" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-900">Analysis History</h2>
              <p className="text-sm text-gray-500">{total} analyses stored</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-200 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Toolbar */}
        <div className="p-4 border-b bg-white space-y-3">
          {/* Search and filters row */}
          <div className="flex flex-wrap gap-3">
            {/* Search */}
            <div className="flex-grow min-w-[200px] relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search by subject or sender..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>

            {/* Risk filter */}
            <select
              value={riskFilter}
              onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }}
              className="px-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="minimal">Minimal</option>
            </select>

            {/* Classification filter */}
            <select
              value={classificationFilter}
              onChange={(e) => { setClassificationFilter(e.target.value); setPage(1); }}
              className="px-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">All Classifications</option>
              <option value="phishing">Phishing</option>
              <option value="bec">BEC</option>
              <option value="malware">Malware</option>
              <option value="spam">Spam</option>
              <option value="legitimate">Legitimate</option>
            </select>

            {/* Refresh */}
            <button
              onClick={fetchAnalyses}
              disabled={loading}
              className="px-3 py-2 border rounded-lg hover:bg-gray-50 transition-colors flex items-center gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {/* Actions row */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* Select all */}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectAll}
                  onChange={toggleSelectAll}
                  className="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="text-sm text-gray-600">Select all</span>
              </label>

              {/* Bulk actions */}
              {selectedIds.size > 0 && (
                <div className="flex items-center gap-2 ml-4">
                  <span className="text-sm text-gray-500">{selectedIds.size} selected</span>
                  <button
                    onClick={deleteSelected}
                    className="px-3 py-1.5 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200 flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" />
                    Delete Selected
                  </button>
                </div>
              )}
            </div>

            {/* Delete all */}
            <button
              onClick={() => setDeleteAllConfirm(true)}
              className="px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 rounded flex items-center gap-1"
            >
              <Trash2 className="w-4 h-4" />
              Clear All History
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="flex-grow overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
            </div>
          ) : analyses.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-gray-500">
              <Database className="w-12 h-12 mb-4 text-gray-300" />
              <p className="font-medium">No analyses found</p>
              <p className="text-sm">Upload an email to get started</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 sticky top-0">
                <tr>
                  <th className="w-10 px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectAll}
                      onChange={toggleSelectAll}
                      className="w-4 h-4 rounded border-gray-300 text-indigo-600"
                    />
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    <button
                      onClick={() => {
                        setSortBy('analyzed_at');
                        setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
                      }}
                      className="flex items-center gap-1 hover:text-gray-700"
                    >
                      Date
                      {sortBy === 'analyzed_at' && (sortOrder === 'desc' ? <SortDesc className="w-3 h-3" /> : <SortAsc className="w-3 h-3" />)}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Sender</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    <button
                      onClick={() => {
                        setSortBy('risk_score');
                        setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
                      }}
                      className="flex items-center gap-1 hover:text-gray-700"
                    >
                      Risk
                      {sortBy === 'risk_score' && (sortOrder === 'desc' ? <SortDesc className="w-3 h-3" /> : <SortAsc className="w-3 h-3" />)}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Indicators</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {analyses.map((analysis) => (
                  <tr
                    key={analysis.analysis_id}
                    className={`hover:bg-gray-50 transition-colors ${
                      selectedIds.has(analysis.analysis_id) ? 'bg-indigo-50' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(analysis.analysis_id)}
                        onChange={() => toggleSelect(analysis.analysis_id)}
                        className="w-4 h-4 rounded border-gray-300 text-indigo-600"
                      />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Clock className="w-4 h-4 text-gray-400" />
                        {new Date(analysis.analyzed_at).toLocaleDateString()}
                        <span className="text-xs text-gray-400">
                          {new Date(analysis.analyzed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="max-w-[200px] truncate text-sm font-medium text-gray-900">
                        {analysis.subject || '(No Subject)'}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="max-w-[150px] truncate text-sm text-gray-600">
                        {analysis.sender_email || 'Unknown'}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-gray-900">{analysis.risk_score}</span>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${getRiskColor(analysis.risk_level)}`}>
                          {analysis.risk_level?.toUpperCase()}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs font-medium text-white rounded ${getClassificationBadge(analysis.classification)}`}>
                        {analysis.classification?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3 text-gray-400">
                        {analysis.has_attachments && (
                          <div className="flex items-center gap-1" title={`${analysis.attachment_count} attachments`}>
                            <Paperclip className="w-4 h-4" />
                            <span className="text-xs">{analysis.attachment_count}</span>
                          </div>
                        )}
                        {analysis.has_urls && (
                          <div className="flex items-center gap-1" title={`${analysis.url_count} URLs`}>
                            <Link className="w-4 h-4" />
                            <span className="text-xs">{analysis.url_count}</span>
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onViewAnalysis(analysis.analysis_id)}
                          className="p-1.5 hover:bg-indigo-100 rounded text-indigo-600"
                          title="View Analysis"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => onExportAnalysis(analysis.analysis_id, 'json')}
                          className="p-1.5 hover:bg-gray-100 rounded text-gray-600"
                          title="Export JSON"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(analysis.analysis_id)}
                          className="p-1.5 hover:bg-red-100 rounded text-red-600"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between p-4 border-t bg-gray-50 rounded-b-xl">
            <div className="text-sm text-gray-500">
              Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, total)} of {total}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 border rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              
              {/* Page numbers */}
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum;
                if (totalPages <= 5) {
                  pageNum = i + 1;
                } else if (page <= 3) {
                  pageNum = i + 1;
                } else if (page >= totalPages - 2) {
                  pageNum = totalPages - 4 + i;
                } else {
                  pageNum = page - 2 + i;
                }
                return (
                  <button
                    key={pageNum}
                    onClick={() => setPage(pageNum)}
                    className={`w-8 h-8 rounded text-sm ${
                      page === pageNum
                        ? 'bg-indigo-600 text-white'
                        : 'border hover:bg-gray-100'
                    }`}
                  >
                    {pageNum}
                  </button>
                );
              })}
              
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-2 border rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Delete single confirmation */}
        {deleteConfirm && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-60">
            <div className="bg-white rounded-lg p-6 max-w-sm mx-4 shadow-xl">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-red-100 rounded-full">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                </div>
                <h3 className="font-semibold text-gray-900">Delete Analysis?</h3>
              </div>
              <p className="text-gray-600 mb-6">
                This will permanently delete this analysis. This action cannot be undone.
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setDeleteConfirm(null)}
                  className="px-4 py-2 border rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={() => deleteAnalysis(deleteConfirm)}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Delete all confirmation */}
        {deleteAllConfirm && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-60">
            <div className="bg-white rounded-lg p-6 max-w-sm mx-4 shadow-xl">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-red-100 rounded-full">
                  <AlertCircle className="w-5 h-5 text-red-600" />
                </div>
                <h3 className="font-semibold text-gray-900">Delete ALL Analyses?</h3>
              </div>
              <p className="text-gray-600 mb-6">
                This will permanently delete <strong>{total} analyses</strong>. This action cannot be undone.
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setDeleteAllConfirm(false)}
                  className="px-4 py-2 border rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={deleteAllAnalyses}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                >
                  Delete All
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default HistoryPanel;
