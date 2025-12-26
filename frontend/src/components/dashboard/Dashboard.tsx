import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  Eye,
  Download,
  Trash2,
  Mail,
  Calendar,
  Clock,
  TrendingUp,
  Activity,
  FileWarning,
  CheckCircle,
  XCircle,
  ChevronLeft,
  ChevronRight,
  BarChart3,
  PieChart,
  Link,
  MessageSquare,
  Globe,
} from 'lucide-react';
import { apiClient } from '../../services/api';

interface AnalysisSummary {
  // From backend AnalysisSummary
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
  // Computed/UI fields
  id?: string;
  sender?: string;
  verdict?: string;
  rules_triggered?: number;
  critical_findings?: number;
  ai_enabled?: boolean;
}

interface DashboardStats {
  total_analyses: number;
  malicious: number;
  suspicious: number;
  clean: number;
  avg_risk_score: number;
  analyses_today: number;
  analyses_this_week: number;
  top_threat_categories: { category: string; count: number }[];
}

interface DashboardProps {
  onViewAnalysis: (analysisId: string) => void;
  onClose: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onViewAnalysis, onClose }) => {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<string>('all');
  const [sortBy, setSortBy] = useState<string>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const pageSize = 10;

  // Helper to map classification/risk_level to verdict
  const getVerdictFromClassification = (classification: string): string => {
    const lowerClass = (classification || '').toLowerCase();
    if (['phishing', 'malware', 'bec', 'ransomware', 'credential_harvesting'].includes(lowerClass)) {
      return 'malicious';
    } else if (['suspicious', 'spam', 'unknown'].includes(lowerClass)) {
      return 'suspicious';
    } else if (['critical', 'high'].includes(lowerClass)) {
      return 'malicious';
    } else if (['medium'].includes(lowerClass)) {
      return 'suspicious';
    }
    return 'clean';
  };

  // Helper to detect analysis type from subject/sender
  const getAnalysisType = (analysis: AnalysisSummary): 'email' | 'url' | 'sms' => {
    const subject = (analysis.subject || '').toLowerCase();
    const sender = (analysis.sender_email || '').toLowerCase();
    
    if (subject.startsWith('url analysis') || sender.includes('url@analysis')) {
      return 'url';
    }
    if (subject.startsWith('sms analysis') || sender.includes('sms@analysis')) {
      return 'sms';
    }
    return 'email';
  };

  // Get icon for analysis type
  const getAnalysisTypeIcon = (type: 'email' | 'url' | 'sms') => {
    switch (type) {
      case 'url': return <Link className="w-4 h-4" />;
      case 'sms': return <MessageSquare className="w-4 h-4" />;
      default: return <Mail className="w-4 h-4" />;
    }
  };

  // Get label for analysis type
  const getAnalysisTypeLabel = (type: 'email' | 'url' | 'sms') => {
    switch (type) {
      case 'url': return 'URL';
      case 'sms': return 'SMS';
      default: return 'Email';
    }
  };

  // Get badge color for analysis type
  const getAnalysisTypeBadge = (type: 'email' | 'url' | 'sms') => {
    switch (type) {
      case 'url': return 'bg-blue-100 text-blue-700 border-blue-200';
      case 'sms': return 'bg-green-100 text-green-700 border-green-200';
      default: return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [currentPage, filterVerdict, sortBy, sortOrder]);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      // Map UI sort fields to backend field names
      const sortFieldMap: Record<string, string> = {
        'date': 'analyzed_at',
        'score': 'risk_score',
        'subject': 'subject',
      };
      const backendSortBy = sortFieldMap[sortBy] || 'analyzed_at';

      // Fetch analyses list using apiClient
      const analysesResponse = await apiClient.get('/analyses', {
        params: {
          page: currentPage,
          page_size: pageSize,
          sort_by: backendSortBy,
          sort_order: sortOrder,
          ...(filterVerdict !== 'all' && { risk_level: filterVerdict }),
        },
      });
      
      const data = analysesResponse.data;
      // Backend returns 'analyses' not 'items'
      const rawAnalyses = data.analyses || data.items || [];
      // Normalize backend data to UI format
      const normalizedAnalyses = rawAnalyses.map((a: any) => ({
        ...a,
        id: a.analysis_id || a.id,
        sender: a.sender_email || a.sender || 'Unknown',
        verdict: getVerdictFromClassification(a.classification || a.risk_level),
        rules_triggered: a.rules_triggered_count || a.rules_triggered || 0,
        critical_findings: a.critical_findings || 0,
        ai_enabled: !!a.ai_summary,
        subject: a.subject || '(No Subject)',
      }));
      setAnalyses(normalizedAnalyses);
      setTotalPages(Math.ceil((data.total || 0) / pageSize));

      // Fetch stats using apiClient
      const statsResponse = await apiClient.get('/analyses/stats');
      setStats(statsResponse.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      // Use mock data for demonstration
      setAnalyses(getMockAnalyses());
      setStats(getMockStats());
    }
    setLoading(false);
  };

  const getMockAnalyses = (): AnalysisSummary[] => [
    {
      analysis_id: 'analysis-001',
      id: 'analysis-001',
      subject: 'URGENT: Wire Transfer Required Immediately',
      sender_email: 'ceo@company-corp.com',
      sender: 'ceo@company-corp.com',
      sender_domain: 'company-corp.com',
      analyzed_at: new Date(Date.now() - 3600000).toISOString(),
      risk_score: 85,
      risk_level: 'critical',
      classification: 'bec',
      verdict: 'malicious',
      rules_triggered: 8,
      critical_findings: 3,
      has_attachments: true,
      has_urls: true,
      attachment_count: 1,
      url_count: 2,
      ai_summary: 'High-risk BEC attempt targeting finance',
      ai_enabled: true,
    },
    {
      analysis_id: 'analysis-002',
      id: 'analysis-002',
      subject: 'Invoice #INV-2024-0342 - Payment Due',
      sender_email: 'billing@vendor-payments.net',
      sender: 'billing@vendor-payments.net',
      sender_domain: 'vendor-payments.net',
      analyzed_at: new Date(Date.now() - 7200000).toISOString(),
      risk_score: 62,
      risk_level: 'high',
      classification: 'phishing',
      verdict: 'suspicious',
      rules_triggered: 5,
      critical_findings: 1,
      has_attachments: true,
      has_urls: true,
      attachment_count: 1,
      url_count: 3,
      ai_summary: 'Suspicious invoice with mismatched sender',
      ai_enabled: true,
    },
    {
      analysis_id: 'analysis-003',
      id: 'analysis-003',
      subject: 'Meeting Notes - Q4 Planning Session',
      sender_email: 'john.smith@company.com',
      sender: 'john.smith@company.com',
      sender_domain: 'company.com',
      analyzed_at: new Date(Date.now() - 10800000).toISOString(),
      risk_score: 12,
      risk_level: 'low',
      classification: 'legitimate',
      verdict: 'clean',
      rules_triggered: 1,
      critical_findings: 0,
      has_attachments: true,
      has_urls: false,
      attachment_count: 1,
      url_count: 0,
      ai_summary: null,
      ai_enabled: false,
    },
    {
      analysis_id: 'analysis-004',
      id: 'analysis-004',
      subject: 'Your password expires in 24 hours - Action Required',
      sender_email: 'security@micros0ft-support.com',
      sender: 'security@micros0ft-support.com',
      sender_domain: 'micros0ft-support.com',
      analyzed_at: new Date(Date.now() - 14400000).toISOString(),
      risk_score: 92,
      risk_level: 'critical',
      classification: 'phishing',
      verdict: 'malicious',
      rules_triggered: 12,
      critical_findings: 5,
      has_attachments: false,
      has_urls: true,
      attachment_count: 0,
      url_count: 2,
      ai_summary: 'Credential harvesting attempt impersonating Microsoft',
      ai_enabled: true,
    },
    {
      analysis_id: 'analysis-005',
      id: 'analysis-005',
      subject: 'Weekly Tech Newsletter - Issue #142',
      sender_email: 'newsletter@techdigest.com',
      sender: 'newsletter@techdigest.com',
      sender_domain: 'techdigest.com',
      analyzed_at: new Date(Date.now() - 18000000).toISOString(),
      risk_score: 8,
      risk_level: 'informational',
      classification: 'legitimate',
      verdict: 'clean',
      rules_triggered: 0,
      critical_findings: 0,
      has_attachments: false,
      has_urls: true,
      attachment_count: 0,
      url_count: 5,
      ai_summary: null,
      ai_enabled: false,
    },
  ];

  const getMockStats = (): DashboardStats => ({
    total_analyses: 47,
    malicious: 12,
    suspicious: 18,
    clean: 17,
    avg_risk_score: 45.3,
    analyses_today: 5,
    analyses_this_week: 23,
    top_threat_categories: [
      { category: 'Phishing', count: 15 },
      { category: 'BEC', count: 8 },
      { category: 'Malware', count: 5 },
      { category: 'Social Engineering', count: 4 },
    ],
  });

  const getVerdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'suspicious':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'clean':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return <ShieldX className="w-4 h-4" />;
      case 'suspicious':
        return <ShieldAlert className="w-4 h-4" />;
      case 'clean':
        return <ShieldCheck className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-600 bg-red-50';
    if (score >= 60) return 'text-orange-600 bg-orange-50';
    if (score >= 40) return 'text-yellow-600 bg-yellow-50';
    if (score >= 20) return 'text-blue-600 bg-blue-50';
    return 'text-green-600 bg-green-50';
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const filteredAnalyses = analyses.filter((analysis) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    const subject = (analysis.subject || '').toLowerCase();
    const sender = (analysis.sender || analysis.sender_email || '').toLowerCase();
    const domain = (analysis.sender_domain || '').toLowerCase();
    return (
      subject.includes(query) ||
      sender.includes(query) ||
      domain.includes(query)
    );
  });

  return (
    <div className="fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-7xl max-h-[95vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <LayoutDashboard className="w-8 h-8" />
              <div>
                <h1 className="text-2xl font-bold">Security Dashboard</h1>
                <p className="text-indigo-200 text-sm">Email Analysis Overview & History</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:bg-white/20 rounded-lg p-2 transition-colors"
            >
              <XCircle className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 p-6 bg-gray-50 border-b">
            <div className="bg-white rounded-lg p-4 shadow-sm border">
              <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                <Activity className="w-4 h-4" />
                Total Analyses
              </div>
              <div className="text-2xl font-bold text-gray-900">{stats.total_analyses}</div>
            </div>
            <div className="bg-white rounded-lg p-4 shadow-sm border border-red-100">
              <div className="flex items-center gap-2 text-red-500 text-sm mb-1">
                <ShieldX className="w-4 h-4" />
                Malicious
              </div>
              <div className="text-2xl font-bold text-red-600">{stats.malicious}</div>
            </div>
            <div className="bg-white rounded-lg p-4 shadow-sm border border-orange-100">
              <div className="flex items-center gap-2 text-orange-500 text-sm mb-1">
                <ShieldAlert className="w-4 h-4" />
                Suspicious
              </div>
              <div className="text-2xl font-bold text-orange-600">{stats.suspicious}</div>
            </div>
            <div className="bg-white rounded-lg p-4 shadow-sm border border-green-100">
              <div className="flex items-center gap-2 text-green-500 text-sm mb-1">
                <ShieldCheck className="w-4 h-4" />
                Clean
              </div>
              <div className="text-2xl font-bold text-green-600">{stats.clean}</div>
            </div>
            <div className="bg-white rounded-lg p-4 shadow-sm border">
              <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                <TrendingUp className="w-4 h-4" />
                Avg Risk Score
              </div>
              <div className="text-2xl font-bold text-gray-900">{stats.avg_risk_score.toFixed(1)}</div>
            </div>
            <div className="bg-white rounded-lg p-4 shadow-sm border">
              <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                <Calendar className="w-4 h-4" />
                Today
              </div>
              <div className="text-2xl font-bold text-indigo-600">{stats.analyses_today}</div>
            </div>
          </div>
        )}

        {/* Filters & Search */}
        <div className="flex flex-wrap items-center gap-4 p-4 border-b bg-white">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search by subject, sender, or filename..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="border rounded-lg px-3 py-2 focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="clean">Clean</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="border rounded-lg px-3 py-2 focus:ring-2 focus:ring-indigo-500"
            >
              <option value="date">Sort by Date</option>
              <option value="score">Sort by Risk Score</option>
              <option value="subject">Sort by Subject</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="p-2 border rounded-lg hover:bg-gray-50"
            >
              {sortOrder === 'desc' ? '↓' : '↑'}
            </button>
          </div>
          <button
            onClick={fetchDashboardData}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        {/* Analysis List */}
        <div className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center h-64">
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-600" />
            </div>
          ) : filteredAnalyses.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Mail className="w-16 h-16 mb-4 text-gray-300" />
              <p className="text-lg">No analyses found</p>
              <p className="text-sm">Upload an email to get started</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredAnalyses.map((analysis) => (
                <div
                  key={analysis.id || analysis.analysis_id}
                  className="bg-white border rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                  onClick={() => onViewAnalysis(analysis.id || analysis.analysis_id)}
                >
                  <div className="flex items-start gap-4">
                    {/* Risk Score Badge */}
                    <div
                      className={`flex-shrink-0 w-16 h-16 rounded-lg flex flex-col items-center justify-center ${getRiskScoreColor(
                        analysis.risk_score
                      )}`}
                    >
                      <span className="text-2xl font-bold">{analysis.risk_score}</span>
                      <span className="text-xs uppercase">Risk</span>
                    </div>

                    {/* Main Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        {/* Analysis Type Badge */}
                        {(() => {
                          const analysisType = getAnalysisType(analysis);
                          return (
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${getAnalysisTypeBadge(analysisType)}`}>
                              {getAnalysisTypeIcon(analysisType)}
                              {getAnalysisTypeLabel(analysisType)}
                            </span>
                          );
                        })()}
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${getVerdictColor(
                            analysis.verdict || 'unknown'
                          )}`}
                        >
                          {getVerdictIcon(analysis.verdict || 'unknown')}
                          {(analysis.verdict || 'unknown').toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatDate(analysis.analyzed_at)}
                        </span>
                        {analysis.ai_enabled && (
                          <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">
                            AI Analyzed
                          </span>
                        )}
                      </div>

                      <h3 className="font-semibold text-gray-900 truncate mb-1">
                        {/* Clean up subject for URL/SMS analysis */}
                        {(() => {
                          const subject = analysis.subject || '(No Subject)';
                          // Remove "URL Analysis: " or "SMS Analysis: " prefix for cleaner display
                          if (subject.toLowerCase().startsWith('url analysis:')) {
                            return subject.replace(/^url analysis:\s*/i, '🔗 ');
                          }
                          if (subject.toLowerCase().startsWith('sms analysis:')) {
                            return subject.replace(/^sms analysis:\s*/i, '📱 ');
                          }
                          return subject;
                        })()}
                      </h3>

                      <div className="flex items-center gap-4 text-sm text-gray-600">
                        <span className="flex items-center gap-1">
                          {getAnalysisTypeIcon(getAnalysisType(analysis))}
                          {(() => {
                            const analysisType = getAnalysisType(analysis);
                            if (analysisType === 'url') {
                              return analysis.url_count ? `${analysis.url_count} URL(s) analyzed` : 'URL Analysis';
                            }
                            if (analysisType === 'sms') {
                              return 'SMS/Message Analysis';
                            }
                            return analysis.sender || analysis.sender_email || 'Unknown';
                          })()}
                        </span>
                        {getAnalysisType(analysis) === 'email' && analysis.sender_domain && (
                          <>
                            <span className="text-gray-400">@</span>
                            <span className="text-gray-500">{analysis.sender_domain}</span>
                          </>
                        )}
                      </div>

                      <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          {analysis.rules_triggered} rules triggered
                        </span>
                        {(analysis.critical_findings ?? 0) > 0 && (
                          <span className="flex items-center gap-1 text-red-600">
                            <FileWarning className="w-3 h-3" />
                            {analysis.critical_findings} critical findings
                          </span>
                        )}
                        {analysis.has_attachments && (
                          <span className="bg-gray-100 px-2 py-0.5 rounded">📎 Attachments</span>
                        )}
                        {analysis.has_urls && (
                          <span className="bg-gray-100 px-2 py-0.5 rounded">🔗 URLs</span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onViewAnalysis(analysis.id || analysis.analysis_id);
                        }}
                        className="p-2 text-indigo-600 hover:bg-indigo-50 rounded-lg"
                        title="View Details"
                      >
                        <Eye className="w-5 h-5" />
                      </button>
                      <button
                        onClick={(e) => e.stopPropagation()}
                        className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg"
                        title="Export"
                      >
                        <Download className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-6 py-4 border-t bg-gray-50">
          <div className="text-sm text-gray-600">
            Showing {filteredAnalyses.length} of {stats?.total_analyses || 0} analyses
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="p-2 border rounded-lg hover:bg-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <span className="px-4 py-2 text-sm">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="p-2 border rounded-lg hover:bg-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
