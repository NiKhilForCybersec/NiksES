/**
 * NiksES Advanced Rules Manager
 * 
 * Professional-grade detection rule creation with:
 * - Advanced field conditions (authentication, threat intel, behavioral)
 * - Multiple operators (regex, threshold, similarity)
 * - Compound logic (AND/OR grouping)
 * - MITRE ATT&CK mapping
 * - YARA-style pattern matching
 * - Rule import/export (Sigma compatible)
 */

import React, { useState, useEffect } from 'react';
import {
  Shield, Plus, Trash2, Save, X, AlertTriangle,
  ChevronDown, ChevronRight, Code, FileText, Upload,
  Download, Copy, Eye, EyeOff, Zap, Target, Globe,
  Mail, Link, Paperclip, Key, Server, Clock, Hash,
  AlertCircle, CheckCircle, Info, HelpCircle, Layers,
  GitBranch, Database, Search, Filter, MoreVertical,
  Play, Pause, RefreshCw, Settings, BookOpen, Award
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { apiClient } from '../../services/api';

// ============================================
// FIELD DEFINITIONS - What can be checked
// ============================================
const FIELD_CATEGORIES = {
  email_metadata: {
    label: 'Email Metadata',
    icon: Mail,
    fields: [
      { id: 'subject', label: 'Subject', type: 'string', description: 'Email subject line' },
      { id: 'body', label: 'Body Content', type: 'string', description: 'Email body text (HTML stripped)' },
      { id: 'body_html', label: 'Body HTML', type: 'string', description: 'Raw HTML content' },
      { id: 'sender_email', label: 'Sender Email', type: 'string', description: 'From address' },
      { id: 'sender_domain', label: 'Sender Domain', type: 'string', description: 'Domain of sender' },
      { id: 'sender_display_name', label: 'Display Name', type: 'string', description: 'Sender display name' },
      { id: 'reply_to', label: 'Reply-To', type: 'string', description: 'Reply-To address' },
      { id: 'return_path', label: 'Return-Path', type: 'string', description: 'Bounce address' },
      { id: 'recipient_count', label: 'Recipient Count', type: 'number', description: 'Number of recipients' },
    ]
  },
  authentication: {
    label: 'Authentication',
    icon: Key,
    fields: [
      { id: 'spf_result', label: 'SPF Result', type: 'enum', options: ['pass', 'fail', 'softfail', 'neutral', 'none'], description: 'SPF check result' },
      { id: 'dkim_result', label: 'DKIM Result', type: 'enum', options: ['pass', 'fail', 'none'], description: 'DKIM signature result' },
      { id: 'dmarc_result', label: 'DMARC Result', type: 'enum', options: ['pass', 'fail', 'none'], description: 'DMARC policy result' },
      { id: 'auth_all_pass', label: 'All Auth Pass', type: 'boolean', description: 'SPF + DKIM + DMARC all pass' },
      { id: 'auth_any_fail', label: 'Any Auth Fail', type: 'boolean', description: 'Any authentication failed' },
    ]
  },
  threat_intel: {
    label: 'Threat Intelligence',
    icon: Database,
    fields: [
      { id: 'sender_domain_vt_score', label: 'Sender Domain VT Score', type: 'number', description: 'VirusTotal detection count' },
      { id: 'sender_domain_age_days', label: 'Domain Age (days)', type: 'number', description: 'Days since domain registration' },
      { id: 'sender_domain_is_new', label: 'Newly Registered Domain', type: 'boolean', description: 'Domain < 30 days old' },
      { id: 'originating_ip_abuse_score', label: 'IP Abuse Score', type: 'number', description: 'AbuseIPDB confidence score (0-100)' },
      { id: 'originating_ip_is_tor', label: 'IP is Tor Exit', type: 'boolean', description: 'Originates from Tor network' },
      { id: 'originating_ip_is_vpn', label: 'IP is VPN', type: 'boolean', description: 'Originates from VPN provider' },
      { id: 'originating_ip_country', label: 'IP Country', type: 'string', description: 'Geolocation country code' },
      { id: 'url_any_malicious', label: 'Any Malicious URL', type: 'boolean', description: 'Any URL flagged by threat intel' },
      { id: 'attachment_any_malicious', label: 'Any Malicious Attachment', type: 'boolean', description: 'Any attachment flagged' },
    ]
  },
  urls_links: {
    label: 'URLs & Links',
    icon: Link,
    fields: [
      { id: 'url_count', label: 'URL Count', type: 'number', description: 'Number of URLs in email' },
      { id: 'urls', label: 'URL Content', type: 'string', description: 'Any URL in email' },
      { id: 'url_domains', label: 'URL Domains', type: 'string', description: 'Domains in URLs' },
      { id: 'has_shortened_url', label: 'Has Shortened URL', type: 'boolean', description: 'Contains bit.ly, tinyurl, etc.' },
      { id: 'has_ip_url', label: 'Has IP-based URL', type: 'boolean', description: 'URL with IP instead of domain' },
      { id: 'has_data_uri', label: 'Has Data URI', type: 'boolean', description: 'Contains data: URI scheme' },
      { id: 'url_mismatch', label: 'URL/Text Mismatch', type: 'boolean', description: 'Display text differs from href' },
      { id: 'has_credential_harvesting_url', label: 'Credential Harvesting URL', type: 'boolean', description: 'URL contains login/signin patterns' },
    ]
  },
  attachments: {
    label: 'Attachments',
    icon: Paperclip,
    fields: [
      { id: 'attachment_count', label: 'Attachment Count', type: 'number', description: 'Number of attachments' },
      { id: 'attachment_names', label: 'Attachment Names', type: 'string', description: 'Filename of any attachment' },
      { id: 'attachment_extensions', label: 'Attachment Extensions', type: 'string', description: 'File extension (.exe, .zip, etc.)' },
      { id: 'attachment_size_total', label: 'Total Size (KB)', type: 'number', description: 'Total attachment size' },
      { id: 'has_executable', label: 'Has Executable', type: 'boolean', description: 'Contains .exe, .dll, .bat, etc.' },
      { id: 'has_macro_document', label: 'Has Macro Document', type: 'boolean', description: 'Contains .docm, .xlsm, etc.' },
      { id: 'has_archive', label: 'Has Archive', type: 'boolean', description: 'Contains .zip, .rar, .7z, etc.' },
      { id: 'has_double_extension', label: 'Double Extension', type: 'boolean', description: 'File like invoice.pdf.exe' },
      { id: 'has_password_protected', label: 'Password Protected', type: 'boolean', description: 'Encrypted attachment' },
    ]
  },
  headers: {
    label: 'Headers & Routing',
    icon: Server,
    fields: [
      { id: 'headers', label: 'Raw Headers', type: 'string', description: 'Any header content' },
      { id: 'x_mailer', label: 'X-Mailer', type: 'string', description: 'Mail client identifier' },
      { id: 'received_hop_count', label: 'Received Hops', type: 'number', description: 'Number of mail servers traversed' },
      { id: 'received_delay_total', label: 'Total Delay (sec)', type: 'number', description: 'Time from first to last hop' },
      { id: 'has_received_localhost', label: 'Localhost in Received', type: 'boolean', description: 'Suspicious localhost routing' },
      { id: 'header_from_mismatch', label: 'Header From Mismatch', type: 'boolean', description: 'From header differs from envelope' },
    ]
  },
  behavioral: {
    label: 'Behavioral Patterns',
    icon: Zap,
    fields: [
      { id: 'urgency_score', label: 'Urgency Score', type: 'number', description: 'Urgency language intensity (0-100)' },
      { id: 'has_urgency_language', label: 'Has Urgency Language', type: 'boolean', description: 'URGENT, ASAP, immediately, etc.' },
      { id: 'has_threat_language', label: 'Has Threat Language', type: 'boolean', description: 'Account suspended, legal action, etc.' },
      { id: 'has_financial_request', label: 'Financial Request', type: 'boolean', description: 'Wire transfer, gift cards, payment' },
      { id: 'has_credential_request', label: 'Credential Request', type: 'boolean', description: 'Password, login, verify account' },
      { id: 'has_pii_request', label: 'PII Request', type: 'boolean', description: 'SSN, DOB, address requests' },
      { id: 'impersonates_brand', label: 'Brand Impersonation', type: 'boolean', description: 'Mentions known brand names' },
      { id: 'impersonates_executive', label: 'Executive Impersonation', type: 'boolean', description: 'CEO, CFO name patterns' },
      { id: 'sent_outside_business_hours', label: 'Outside Business Hours', type: 'boolean', description: 'Sent outside 9-5 local time' },
    ]
  },
};

// ============================================
// OPERATORS - How to compare values
// ============================================
const OPERATORS = {
  string: [
    { id: 'contains', label: 'contains', description: 'Text contains value (case-insensitive)' },
    { id: 'not_contains', label: 'does not contain', description: 'Text does not contain value' },
    { id: 'equals', label: 'equals', description: 'Exact match (case-insensitive)' },
    { id: 'not_equals', label: 'does not equal', description: 'Does not match exactly' },
    { id: 'starts_with', label: 'starts with', description: 'Begins with value' },
    { id: 'ends_with', label: 'ends with', description: 'Ends with value' },
    { id: 'regex', label: 'matches regex', description: 'Regular expression match' },
    { id: 'in_list', label: 'is in list', description: 'Matches any item in comma-separated list' },
    { id: 'similarity', label: 'similar to (fuzzy)', description: 'Fuzzy string matching (typosquatting)' },
  ],
  number: [
    { id: 'equals', label: '=', description: 'Equal to' },
    { id: 'not_equals', label: '≠', description: 'Not equal to' },
    { id: 'greater_than', label: '>', description: 'Greater than' },
    { id: 'less_than', label: '<', description: 'Less than' },
    { id: 'greater_equal', label: '≥', description: 'Greater than or equal' },
    { id: 'less_equal', label: '≤', description: 'Less than or equal' },
    { id: 'between', label: 'between', description: 'Value is between two numbers' },
  ],
  boolean: [
    { id: 'is_true', label: 'is true', description: 'Condition is true' },
    { id: 'is_false', label: 'is false', description: 'Condition is false' },
  ],
  enum: [
    { id: 'equals', label: 'is', description: 'Equals selected value' },
    { id: 'not_equals', label: 'is not', description: 'Does not equal selected value' },
    { id: 'in_list', label: 'is one of', description: 'Matches any selected value' },
  ],
};

// ============================================
// SEVERITY LEVELS
// ============================================
const SEVERITY_LEVELS = [
  { id: 'critical', label: 'Critical', color: 'bg-red-600', textColor: 'text-red-400', score: 40 },
  { id: 'high', label: 'High', color: 'bg-orange-600', textColor: 'text-orange-400', score: 25 },
  { id: 'medium', label: 'Medium', color: 'bg-yellow-600', textColor: 'text-yellow-400', score: 15 },
  { id: 'low', label: 'Low', color: 'bg-blue-600', textColor: 'text-blue-400', score: 5 },
  { id: 'info', label: 'Informational', color: 'bg-gray-600', textColor: 'text-gray-400', score: 0 },
];

// ============================================
// MITRE ATT&CK TECHNIQUES
// ============================================
const MITRE_TECHNIQUES = [
  { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
  { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
  { id: 'T1566.003', name: 'Spearphishing via Service', tactic: 'Initial Access' },
  { id: 'T1598.002', name: 'Spearphishing for Information', tactic: 'Reconnaissance' },
  { id: 'T1598.003', name: 'Spearphishing Link (Recon)', tactic: 'Reconnaissance' },
  { id: 'T1204.001', name: 'Malicious Link', tactic: 'Execution' },
  { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution' },
  { id: 'T1656', name: 'Impersonation', tactic: 'Defense Evasion' },
  { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion' },
  { id: 'T1589.001', name: 'Gather Victim Identity - Credentials', tactic: 'Reconnaissance' },
];

// ============================================
// RULE TEMPLATES
// ============================================
const RULE_TEMPLATES = [
  {
    name: 'Authentication Failure',
    description: 'Detect emails failing SPF, DKIM, or DMARC',
    conditions: [{ field: 'auth_any_fail', operator: 'is_true', value: 'true' }],
    severity: 'high',
    mitre: ['T1566.001'],
  },
  {
    name: 'Newly Registered Domain',
    description: 'Sender domain registered within last 30 days',
    conditions: [{ field: 'sender_domain_is_new', operator: 'is_true', value: 'true' }],
    severity: 'medium',
    mitre: ['T1566.002'],
  },
  {
    name: 'Credential Harvesting',
    description: 'URLs with login/password patterns',
    conditions: [{ field: 'has_credential_harvesting_url', operator: 'is_true', value: 'true' }],
    severity: 'critical',
    mitre: ['T1566.002', 'T1589.001'],
  },
  {
    name: 'Executive Impersonation (BEC)',
    description: 'Possible CEO/CFO impersonation attempt',
    conditions: [
      { field: 'impersonates_executive', operator: 'is_true', value: 'true' },
      { field: 'has_financial_request', operator: 'is_true', value: 'true' },
    ],
    logic: 'AND',
    severity: 'critical',
    mitre: ['T1656', 'T1598.002'],
  },
  {
    name: 'Malicious Attachment Type',
    description: 'Dangerous file extensions attached',
    conditions: [{ field: 'has_executable', operator: 'is_true', value: 'true' }],
    severity: 'critical',
    mitre: ['T1566.001', 'T1204.002'],
  },
  {
    name: 'High IP Abuse Score',
    description: 'Originating IP has high abuse confidence',
    conditions: [{ field: 'originating_ip_abuse_score', operator: 'greater_than', value: '50' }],
    severity: 'high',
    mitre: ['T1566.001'],
  },
  {
    name: 'URL Shortener with Urgency',
    description: 'Shortened URLs combined with urgent language',
    conditions: [
      { field: 'has_shortened_url', operator: 'is_true', value: 'true' },
      { field: 'has_urgency_language', operator: 'is_true', value: 'true' },
    ],
    logic: 'AND',
    severity: 'high',
    mitre: ['T1566.002', 'T1204.001'],
  },
  {
    name: 'Tor/VPN Origin',
    description: 'Email originates from anonymizing network',
    conditions: [
      { field: 'originating_ip_is_tor', operator: 'is_true', value: 'true' },
    ],
    severity: 'medium',
    mitre: ['T1566.001'],
  },
];

// ============================================
// MAIN COMPONENT
// ============================================
interface AdvancedRulesManagerProps {
  isOpen: boolean;
  onClose: () => void;
}

interface Condition {
  id: string;
  field: string;
  operator: string;
  value: string;
  value2?: string; // For "between" operator
}

interface ConditionGroup {
  id: string;
  logic: 'AND' | 'OR';
  conditions: Condition[];
}

interface Rule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  category: string;
  conditionGroups: ConditionGroup[];
  groupLogic: 'AND' | 'OR';
  mitreTechniques: string[];
  tags: string[];
  score: number;
  created_at: string;
  updated_at: string;
}

const AdvancedRulesManager: React.FC<AdvancedRulesManagerProps> = ({ isOpen, onClose }) => {
  // State
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showYaraEditor, setShowYaraEditor] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [loading, setLoading] = useState(false);
  
  // Edit form state
  const [editForm, setEditForm] = useState<Partial<Rule>>({
    name: '',
    description: '',
    severity: 'medium',
    category: 'custom',
    conditionGroups: [{ id: '1', logic: 'AND', conditions: [{ id: '1', field: '', operator: '', value: '' }] }],
    groupLogic: 'AND',
    mitreTechniques: [],
    tags: [],
    enabled: true,
  });

  // Load rules
  useEffect(() => {
    if (isOpen) {
      loadRules();
    }
  }, [isOpen]);

  const loadRules = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/rules');
      const data = response.data;
      // Convert old format to new if needed
      const convertedRules = (data.rules || []).map((r: any) => ({
        ...r,
        conditionGroups: r.conditionGroups || [{
          id: '1',
          logic: 'AND',
          conditions: r.conditions?.map((c: any, i: number) => ({
            id: String(i + 1),
            field: c.field,
            operator: c.operator,
            value: c.value,
          })) || []
        }],
        groupLogic: r.groupLogic || 'AND',
        mitreTechniques: r.mitreTechniques || r.mitre || [],
        tags: r.tags || [],
      }));
      setRules(convertedRules);
    } catch (error) {
      console.error('Failed to load rules:', error);
    } finally {
      setLoading(false);
    }
  };

  // Get field info
  const getFieldInfo = (fieldId: string) => {
    for (const category of Object.values(FIELD_CATEGORIES)) {
      const field = category.fields.find(f => f.id === fieldId);
      if (field) return field;
    }
    return null;
  };

  // Get operators for field type
  const getOperatorsForField = (fieldId: string) => {
    const field = getFieldInfo(fieldId);
    if (!field) return OPERATORS.string;
    return OPERATORS[field.type as keyof typeof OPERATORS] || OPERATORS.string;
  };

  // Add condition to group
  const addCondition = (groupIndex: number) => {
    const newGroups = [...(editForm.conditionGroups || [])];
    newGroups[groupIndex].conditions.push({
      id: String(Date.now()),
      field: '',
      operator: '',
      value: '',
    });
    setEditForm({ ...editForm, conditionGroups: newGroups });
  };

  // Remove condition from group
  const removeCondition = (groupIndex: number, condIndex: number) => {
    const newGroups = [...(editForm.conditionGroups || [])];
    newGroups[groupIndex].conditions.splice(condIndex, 1);
    if (newGroups[groupIndex].conditions.length === 0) {
      newGroups.splice(groupIndex, 1);
    }
    if (newGroups.length === 0) {
      newGroups.push({ id: String(Date.now()), logic: 'AND', conditions: [{ id: '1', field: '', operator: '', value: '' }] });
    }
    setEditForm({ ...editForm, conditionGroups: newGroups });
  };

  // Update condition
  const updateCondition = (groupIndex: number, condIndex: number, updates: Partial<Condition>) => {
    const newGroups = [...(editForm.conditionGroups || [])];
    newGroups[groupIndex].conditions[condIndex] = {
      ...newGroups[groupIndex].conditions[condIndex],
      ...updates,
    };
    // Reset operator and value if field changes
    if (updates.field) {
      newGroups[groupIndex].conditions[condIndex].operator = '';
      newGroups[groupIndex].conditions[condIndex].value = '';
    }
    setEditForm({ ...editForm, conditionGroups: newGroups });
  };

  // Add condition group
  const addConditionGroup = () => {
    const newGroups = [...(editForm.conditionGroups || [])];
    newGroups.push({
      id: String(Date.now()),
      logic: 'AND',
      conditions: [{ id: '1', field: '', operator: '', value: '' }],
    });
    setEditForm({ ...editForm, conditionGroups: newGroups });
  };

  // Toggle MITRE technique
  const toggleMitreTechnique = (techId: string) => {
    const techniques = editForm.mitreTechniques || [];
    if (techniques.includes(techId)) {
      setEditForm({ ...editForm, mitreTechniques: techniques.filter(t => t !== techId) });
    } else {
      setEditForm({ ...editForm, mitreTechniques: [...techniques, techId] });
    }
  };

  // Save rule
  const saveRule = async () => {
    if (!editForm.name) {
      toast.error('Rule name is required');
      return;
    }

    // Validate conditions
    const hasValidCondition = editForm.conditionGroups?.some(g => 
      g.conditions.some(c => c.field && c.operator)
    );
    if (!hasValidCondition) {
      toast.error('At least one condition is required');
      return;
    }

    try {
      const ruleData = {
        ...editForm,
        id: editForm.id || `custom_${Date.now()}`,
        score: SEVERITY_LEVELS.find(s => s.id === editForm.severity)?.score || 10,
        updated_at: new Date().toISOString(),
        created_at: editForm.created_at || new Date().toISOString(),
      };

      await apiClient.post('/rules', ruleData);
      toast.success(selectedRule ? 'Rule updated' : 'Rule created');
      setIsEditing(false);
      setSelectedRule(null);
      loadRules();
    } catch (error) {
      toast.error('Failed to save rule');
    }
  };

  // Delete rule
  const deleteRule = async (ruleId: string) => {
    try {
      await apiClient.delete(`/rules/${ruleId}`);
      toast.success('Rule deleted');
      loadRules();
    } catch (error) {
      toast.error('Failed to delete rule');
    }
  };

  // Apply template
  const applyTemplate = (template: typeof RULE_TEMPLATES[0]) => {
    setEditForm({
      name: template.name,
      description: template.description,
      severity: template.severity,
      category: 'custom',
      conditionGroups: [{
        id: '1',
        logic: (template as any).logic || 'AND',
        conditions: template.conditions.map((c, i) => ({
          id: String(i + 1),
          ...c,
        })),
      }],
      groupLogic: 'AND',
      mitreTechniques: template.mitre,
      tags: [],
      enabled: true,
    });
    setShowTemplates(false);
    setIsEditing(true);
  };

  // Export rules
  const exportRules = () => {
    const data = JSON.stringify(rules, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nikses-rules.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Rules exported');
  };

  // Filter rules
  const filteredRules = rules.filter(rule => {
    const matchesSearch = !searchTerm || 
      rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.description?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = !filterSeverity || rule.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-xl shadow-2xl w-full max-w-6xl max-h-[90vh] flex flex-col border border-gray-700">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-600 rounded-lg">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Advanced Detection Rules</h2>
              <p className="text-sm text-gray-400">{rules.length} rules configured</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowTemplates(true)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded text-sm flex items-center gap-1"
            >
              <BookOpen className="w-4 h-4" />
              Templates
            </button>
            <button
              onClick={exportRules}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center gap-1"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-700 rounded-lg"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>

        <div className="flex flex-grow overflow-hidden">
          {/* Left Panel - Rule List */}
          <div className="w-1/3 border-r border-gray-700 flex flex-col">
            {/* Search & Filter */}
            <div className="p-3 border-b border-gray-700 space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  placeholder="Search rules..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-gray-800 border border-gray-600 rounded text-sm focus:ring-2 focus:ring-purple-500"
                />
              </div>
              <div className="flex gap-2">
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="flex-grow px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm"
                >
                  <option value="">All Severities</option>
                  {SEVERITY_LEVELS.map(s => (
                    <option key={s.id} value={s.id}>{s.label}</option>
                  ))}
                </select>
                <button
                  onClick={() => {
                    setSelectedRule(null);
                    setEditForm({
                      name: '',
                      description: '',
                      severity: 'medium',
                      category: 'custom',
                      conditionGroups: [{ id: '1', logic: 'AND', conditions: [{ id: '1', field: '', operator: '', value: '' }] }],
                      groupLogic: 'AND',
                      mitreTechniques: [],
                      tags: [],
                      enabled: true,
                    });
                    setIsEditing(true);
                  }}
                  className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 rounded text-sm flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  New
                </button>
              </div>
            </div>

            {/* Rule List */}
            <div className="flex-grow overflow-auto">
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="w-6 h-6 animate-spin text-gray-500" />
                </div>
              ) : filteredRules.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p>No rules found</p>
                  <button
                    onClick={() => setShowTemplates(true)}
                    className="mt-2 text-sm text-purple-400 hover:text-purple-300"
                  >
                    Start with a template →
                  </button>
                </div>
              ) : (
                filteredRules.map(rule => (
                  <div
                    key={rule.id}
                    onClick={() => {
                      setSelectedRule(rule);
                      setEditForm(rule);
                      setIsEditing(false);
                    }}
                    className={`p-3 border-b border-gray-800 cursor-pointer hover:bg-gray-800/50 ${
                      selectedRule?.id === rule.id ? 'bg-gray-800' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-grow min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${
                            SEVERITY_LEVELS.find(s => s.id === rule.severity)?.color || 'bg-gray-500'
                          }`} />
                          <span className="font-medium text-white truncate">{rule.name}</span>
                        </div>
                        <p className="text-xs text-gray-500 truncate mt-1">{rule.description}</p>
                      </div>
                      <div className="flex items-center gap-1 ml-2">
                        {!rule.enabled && (
                          <span className="px-1.5 py-0.5 bg-gray-700 text-gray-400 text-xs rounded">
                            Disabled
                          </span>
                        )}
                      </div>
                    </div>
                    {rule.mitreTechniques?.length > 0 && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {rule.mitreTechniques.slice(0, 2).map(t => (
                          <span key={t} className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded">
                            {t}
                          </span>
                        ))}
                        {rule.mitreTechniques.length > 2 && (
                          <span className="text-xs text-gray-500">+{rule.mitreTechniques.length - 2}</span>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right Panel - Rule Editor */}
          <div className="flex-grow flex flex-col overflow-hidden">
            {isEditing ? (
              /* Edit Mode */
              <div className="flex-grow overflow-auto p-4 space-y-4">
                {/* Basic Info */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">Rule Name *</label>
                    <input
                      type="text"
                      value={editForm.name || ''}
                      onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                      placeholder="e.g., Credential Harvesting Detection"
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded focus:ring-2 focus:ring-purple-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">Severity</label>
                    <select
                      value={editForm.severity || 'medium'}
                      onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded focus:ring-2 focus:ring-purple-500"
                    >
                      {SEVERITY_LEVELS.map(s => (
                        <option key={s.id} value={s.id}>{s.label} (+{s.score} points)</option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Description</label>
                  <textarea
                    value={editForm.description || ''}
                    onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                    placeholder="Describe what this rule detects..."
                    rows={2}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                {/* Condition Groups */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-gray-400">Detection Conditions</label>
                    <button
                      onClick={addConditionGroup}
                      className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1"
                    >
                      <Plus className="w-3 h-3" />
                      Add Group
                    </button>
                  </div>

                  {editForm.conditionGroups?.map((group, groupIndex) => (
                    <div key={group.id} className="mb-4 p-3 bg-gray-800/50 border border-gray-700 rounded-lg">
                      {groupIndex > 0 && (
                        <div className="flex items-center justify-center mb-3">
                          <select
                            value={editForm.groupLogic}
                            onChange={(e) => setEditForm({ ...editForm, groupLogic: e.target.value as 'AND' | 'OR' })}
                            className="px-2 py-1 bg-gray-700 border border-gray-600 rounded text-xs font-mono"
                          >
                            <option value="AND">AND</option>
                            <option value="OR">OR</option>
                          </select>
                        </div>
                      )}

                      <div className="space-y-2">
                        {group.conditions.map((condition, condIndex) => (
                          <div key={condition.id} className="flex items-start gap-2">
                            {condIndex > 0 && (
                              <select
                                value={group.logic}
                                onChange={(e) => {
                                  const newGroups = [...(editForm.conditionGroups || [])];
                                  newGroups[groupIndex].logic = e.target.value as 'AND' | 'OR';
                                  setEditForm({ ...editForm, conditionGroups: newGroups });
                                }}
                                className="w-16 px-1 py-2 bg-gray-700 border border-gray-600 rounded text-xs font-mono"
                              >
                                <option value="AND">AND</option>
                                <option value="OR">OR</option>
                              </select>
                            )}
                            {condIndex === 0 && <div className="w-16" />}

                            {/* Field Select */}
                            <select
                              value={condition.field}
                              onChange={(e) => updateCondition(groupIndex, condIndex, { field: e.target.value })}
                              className="flex-grow px-2 py-2 bg-gray-700 border border-gray-600 rounded text-sm"
                            >
                              <option value="">Select field...</option>
                              {Object.entries(FIELD_CATEGORIES).map(([catId, cat]) => (
                                <optgroup key={catId} label={cat.label}>
                                  {cat.fields.map(field => (
                                    <option key={field.id} value={field.id}>{field.label}</option>
                                  ))}
                                </optgroup>
                              ))}
                            </select>

                            {/* Operator Select */}
                            <select
                              value={condition.operator}
                              onChange={(e) => updateCondition(groupIndex, condIndex, { operator: e.target.value })}
                              disabled={!condition.field}
                              className="w-32 px-2 py-2 bg-gray-700 border border-gray-600 rounded text-sm disabled:opacity-50"
                            >
                              <option value="">operator</option>
                              {getOperatorsForField(condition.field).map(op => (
                                <option key={op.id} value={op.id}>{op.label}</option>
                              ))}
                            </select>

                            {/* Value Input */}
                            {getFieldInfo(condition.field)?.type === 'boolean' ? (
                              <div className="w-32" />
                            ) : getFieldInfo(condition.field)?.type === 'enum' ? (
                              <select
                                value={condition.value}
                                onChange={(e) => updateCondition(groupIndex, condIndex, { value: e.target.value })}
                                className="w-32 px-2 py-2 bg-gray-700 border border-gray-600 rounded text-sm"
                              >
                                <option value="">value</option>
                                {(getFieldInfo(condition.field) as any)?.options?.map((opt: string) => (
                                  <option key={opt} value={opt}>{opt}</option>
                                ))}
                              </select>
                            ) : (
                              <input
                                type={getFieldInfo(condition.field)?.type === 'number' ? 'number' : 'text'}
                                value={condition.value}
                                onChange={(e) => updateCondition(groupIndex, condIndex, { value: e.target.value })}
                                placeholder="value"
                                className="w-32 px-2 py-2 bg-gray-700 border border-gray-600 rounded text-sm"
                              />
                            )}

                            <button
                              onClick={() => removeCondition(groupIndex, condIndex)}
                              className="p-2 hover:bg-red-900/50 rounded text-red-400"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>

                      <button
                        onClick={() => addCondition(groupIndex)}
                        className="mt-2 text-xs text-gray-400 hover:text-gray-300 flex items-center gap-1"
                      >
                        <Plus className="w-3 h-3" />
                        Add condition
                      </button>
                    </div>
                  ))}
                </div>

                {/* MITRE ATT&CK Mapping */}
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK Techniques</label>
                  <div className="grid grid-cols-2 gap-2 max-h-32 overflow-auto p-2 bg-gray-800/50 rounded border border-gray-700">
                    {MITRE_TECHNIQUES.map(tech => (
                      <label
                        key={tech.id}
                        className={`flex items-center gap-2 p-2 rounded cursor-pointer hover:bg-gray-700 ${
                          editForm.mitreTechniques?.includes(tech.id) ? 'bg-red-900/30' : ''
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={editForm.mitreTechniques?.includes(tech.id) || false}
                          onChange={() => toggleMitreTechnique(tech.id)}
                          className="rounded border-gray-600 text-red-600 focus:ring-red-500"
                        />
                        <span className="text-xs">
                          <span className="font-mono text-red-400">{tech.id}</span>
                          <span className="text-gray-400 ml-1">{tech.name}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                  <button
                    onClick={() => {
                      setIsEditing(false);
                      if (!selectedRule) setSelectedRule(null);
                    }}
                    className="px-4 py-2 border border-gray-600 rounded hover:bg-gray-800"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={saveRule}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded flex items-center gap-2"
                  >
                    <Save className="w-4 h-4" />
                    Save Rule
                  </button>
                </div>
              </div>
            ) : selectedRule ? (
              /* View Mode */
              <div className="flex-grow overflow-auto p-4">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        SEVERITY_LEVELS.find(s => s.id === selectedRule.severity)?.color || 'bg-gray-600'
                      }`}>
                        {selectedRule.severity?.toUpperCase()}
                      </span>
                      {!selectedRule.enabled && (
                        <span className="px-2 py-0.5 bg-gray-700 text-gray-400 rounded text-xs">DISABLED</span>
                      )}
                    </div>
                    <h3 className="text-xl font-bold text-white">{selectedRule.name}</h3>
                    <p className="text-gray-400 mt-1">{selectedRule.description}</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setIsEditing(true)}
                      className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deleteRule(selectedRule.id)}
                      className="px-3 py-1.5 bg-red-900/50 hover:bg-red-900 text-red-400 rounded text-sm"
                    >
                      Delete
                    </button>
                  </div>
                </div>

                {/* Conditions Display */}
                <div className="mb-4">
                  <h4 className="text-sm font-medium text-gray-400 mb-2">Detection Logic</h4>
                  <div className="p-3 bg-gray-800 rounded-lg font-mono text-sm">
                    {selectedRule.conditionGroups?.map((group, gi) => (
                      <div key={gi}>
                        {gi > 0 && <div className="text-purple-400 my-1">{selectedRule.groupLogic}</div>}
                        <div className="pl-2 border-l-2 border-gray-700">
                          {group.conditions.map((c, ci) => (
                            <div key={ci} className="flex items-center gap-2 py-1">
                              {ci > 0 && <span className="text-blue-400">{group.logic}</span>}
                              <span className="text-green-400">{c.field}</span>
                              <span className="text-gray-500">{c.operator}</span>
                              <span className="text-yellow-400">"{c.value}"</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* MITRE Techniques */}
                {selectedRule.mitreTechniques?.length > 0 && (
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK Mapping</h4>
                    <div className="flex flex-wrap gap-2">
                      {selectedRule.mitreTechniques.map(techId => {
                        const tech = MITRE_TECHNIQUES.find(t => t.id === techId);
                        return (
                          <a
                            key={techId}
                            href={`https://attack.mitre.org/techniques/${techId.replace('.', '/')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-2 py-1 bg-red-900/50 border border-red-800 rounded text-sm hover:bg-red-900"
                          >
                            <span className="font-mono text-red-400">{techId}</span>
                            {tech && <span className="text-gray-400 ml-1">- {tech.name}</span>}
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Metadata */}
                <div className="text-xs text-gray-500 mt-4 pt-4 border-t border-gray-700">
                  <p>Rule ID: {selectedRule.id}</p>
                  <p>Score: +{selectedRule.score || SEVERITY_LEVELS.find(s => s.id === selectedRule.severity)?.score || 0} points</p>
                  {selectedRule.created_at && <p>Created: {new Date(selectedRule.created_at).toLocaleString()}</p>}
                </div>
              </div>
            ) : (
              /* No Selection */
              <div className="flex-grow flex items-center justify-center text-gray-500">
                <div className="text-center">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p>Select a rule to view details</p>
                  <p className="text-sm mt-1">or create a new one</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Templates Modal */}
        {showTemplates && (
          <div className="absolute inset-0 bg-black/50 flex items-center justify-center p-4">
            <div className="bg-gray-800 rounded-lg p-4 max-w-2xl w-full max-h-[70vh] overflow-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold">Rule Templates</h3>
                <button onClick={() => setShowTemplates(false)} className="p-1 hover:bg-gray-700 rounded">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {RULE_TEMPLATES.map((template, idx) => (
                  <div
                    key={idx}
                    onClick={() => applyTemplate(template)}
                    className="p-3 bg-gray-700/50 rounded-lg cursor-pointer hover:bg-gray-700 border border-gray-600"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`w-2 h-2 rounded-full ${
                        SEVERITY_LEVELS.find(s => s.id === template.severity)?.color
                      }`} />
                      <span className="font-medium">{template.name}</span>
                    </div>
                    <p className="text-xs text-gray-400">{template.description}</p>
                    <div className="flex gap-1 mt-2">
                      {template.mitre.map(t => (
                        <span key={t} className="px-1 py-0.5 bg-red-900/50 text-red-400 text-xs rounded font-mono">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdvancedRulesManager;
