/**
 * NiksES Custom Rules Manager Component
 * 
 * Allows users to create, edit, and manage custom detection rules.
 */

import { useState, useEffect, useCallback } from 'react';
import { 
  Plus, Edit2, Trash2, Power, PowerOff, Save, X, 
  AlertTriangle, ChevronDown, ChevronUp, Copy, Download,
  Upload, TestTube, Check, Info
} from 'lucide-react';
import { apiClient } from '../services/api';

// Types
interface RuleCondition {
  field: string;
  match_type: string;
  value: string;
  case_sensitive: boolean;
}

interface CustomRule {
  rule_id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  conditions: RuleCondition[];
  logic: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  author: string;
  tags: string[];
  mitre_technique?: string;
}

interface RuleCategories {
  categories: string[];
  field_targets: string[];
  match_types: string[];
  severities: string[];
}

interface RulesManagerProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function RulesManager({ isOpen, onClose }: RulesManagerProps) {
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [categories, setCategories] = useState<RuleCategories | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingRule, setEditingRule] = useState<CustomRule | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<any>(null);

  // Form state for new/edit rule
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: 'custom',
    severity: 'medium',
    logic: 'AND',
    conditions: [{ field: 'subject', match_type: 'contains', value: '', case_sensitive: false }],
    tags: '',
    mitre_technique: '',
  });

  // Fetch rules and categories
  const fetchRules = useCallback(async () => {
    try {
      const [rulesRes, catsRes] = await Promise.all([
        apiClient.get('/rules'),
        apiClient.get('/rules/categories'),
      ]);
      
      setRules(rulesRes.data.rules || []);
      setCategories(catsRes.data);
    } catch (error) {
      console.error('Failed to fetch rules:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchRules();
    }
  }, [isOpen, fetchRules]);

  // Create or update rule
  const handleSaveRule = async () => {
    const payload = {
      name: formData.name,
      description: formData.description,
      category: formData.category,
      severity: formData.severity,
      logic: formData.logic,
      conditions: formData.conditions,
      tags: formData.tags.split(',').map(t => t.trim()).filter(Boolean),
      mitre_technique: formData.mitre_technique || null,
    };

    try {
      if (editingRule) {
        await apiClient.patch(`/rules/${editingRule.rule_id}`, payload);
      } else {
        await apiClient.post('/rules', payload);
      }
      await fetchRules();
      resetForm();
    } catch (error) {
      console.error('Failed to save rule:', error);
    }
  };

  // Delete rule
  const handleDeleteRule = async (ruleId: string) => {
    if (!confirm('Delete this rule?')) return;
    
    try {
      await apiClient.delete(`/rules/${ruleId}`);
      await fetchRules();
    } catch (error) {
      console.error('Failed to delete rule:', error);
    }
  };

  // Toggle rule enabled/disabled
  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await apiClient.post(`/rules/${ruleId}/toggle?enabled=${enabled}`);
      await fetchRules();
    } catch (error) {
      console.error('Failed to toggle rule:', error);
    }
  };

  // Test rule
  const handleTestRule = async () => {
    const payload = {
      rule: {
        name: formData.name,
        description: formData.description,
        category: formData.category,
        severity: formData.severity,
        logic: formData.logic,
        conditions: formData.conditions,
        tags: [],
      },
      email_sample: {
        subject: 'Test email subject',
        body: 'Test email body content',
        sender_email: 'sender@example.com',
      },
    };

    try {
      const response = await apiClient.post('/rules/test', payload);
      setTestResult(response.data);
    } catch (error) {
      console.error('Failed to test rule:', error);
    }
  };

  // Edit existing rule
  const handleEditRule = (rule: CustomRule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      description: rule.description,
      category: rule.category,
      severity: rule.severity,
      logic: rule.logic,
      conditions: rule.conditions,
      tags: rule.tags.join(', '),
      mitre_technique: rule.mitre_technique || '',
    });
    setIsCreating(true);
  };

  // Reset form
  const resetForm = () => {
    setEditingRule(null);
    setIsCreating(false);
    setTestResult(null);
    setFormData({
      name: '',
      description: '',
      category: 'custom',
      severity: 'medium',
      logic: 'AND',
      conditions: [{ field: 'subject', match_type: 'contains', value: '', case_sensitive: false }],
      tags: '',
      mitre_technique: '',
    });
  };

  // Add condition
  const addCondition = () => {
    setFormData({
      ...formData,
      conditions: [
        ...formData.conditions,
        { field: 'subject', match_type: 'contains', value: '', case_sensitive: false },
      ],
    });
  };

  // Remove condition
  const removeCondition = (index: number) => {
    if (formData.conditions.length <= 1) return;
    setFormData({
      ...formData,
      conditions: formData.conditions.filter((_, i) => i !== index),
    });
  };

  // Update condition
  const updateCondition = (index: number, field: string, value: any) => {
    const updated = [...formData.conditions];
    updated[index] = { ...updated[index], [field]: value };
    setFormData({ ...formData, conditions: updated });
  };

  // Severity badge color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400';
      case 'high': return 'bg-orange-500/20 text-orange-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'low': return 'bg-green-500/20 text-green-400';
      default: return 'bg-blue-500/20 text-blue-400';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 rounded-xl w-full max-w-5xl max-h-[90vh] overflow-hidden border border-slate-700 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <div>
            <h2 className="text-xl font-semibold">Custom Detection Rules</h2>
            <p className="text-sm text-slate-400">Create and manage your own detection rules</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-700 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="text-center py-8 text-slate-400">Loading rules...</div>
          ) : isCreating ? (
            /* Rule Editor */
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-medium">
                  {editingRule ? 'Edit Rule' : 'Create New Rule'}
                </h3>
                <button onClick={resetForm} className="text-slate-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Rule Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g., Suspicious Sender Detection"
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Category</label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                  >
                    {categories?.categories.map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm text-slate-400 mb-1">Description *</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Describe what this rule detects..."
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg h-20"
                />
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Severity</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                  >
                    {categories?.severities.map((sev) => (
                      <option key={sev} value={sev}>{sev.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Logic</label>
                  <select
                    value={formData.logic}
                    onChange={(e) => setFormData({ ...formData, logic: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                  >
                    <option value="AND">ALL conditions (AND)</option>
                    <option value="OR">ANY condition (OR)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">MITRE Technique</label>
                  <input
                    type="text"
                    value={formData.mitre_technique}
                    onChange={(e) => setFormData({ ...formData, mitre_technique: e.target.value })}
                    placeholder="e.g., T1566.001"
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                  />
                </div>
              </div>

              {/* Conditions */}
              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="text-sm text-slate-400">Conditions</label>
                  <button
                    onClick={addCondition}
                    className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                  >
                    <Plus className="w-4 h-4" /> Add Condition
                  </button>
                </div>

                <div className="space-y-2">
                  {formData.conditions.map((cond, idx) => (
                    <div key={idx} className="flex gap-2 items-center bg-slate-700/50 p-3 rounded-lg">
                      <select
                        value={cond.field}
                        onChange={(e) => updateCondition(idx, 'field', e.target.value)}
                        className="px-2 py-1.5 bg-slate-600 border border-slate-500 rounded text-sm"
                      >
                        {categories?.field_targets.map((f) => (
                          <option key={f} value={f}>{f}</option>
                        ))}
                      </select>
                      <select
                        value={cond.match_type}
                        onChange={(e) => updateCondition(idx, 'match_type', e.target.value)}
                        className="px-2 py-1.5 bg-slate-600 border border-slate-500 rounded text-sm"
                      >
                        {categories?.match_types.map((m) => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={cond.value}
                        onChange={(e) => updateCondition(idx, 'value', e.target.value)}
                        placeholder="Value to match"
                        className="flex-1 px-2 py-1.5 bg-slate-600 border border-slate-500 rounded text-sm"
                      />
                      <label className="flex items-center gap-1 text-xs text-slate-400">
                        <input
                          type="checkbox"
                          checked={cond.case_sensitive}
                          onChange={(e) => updateCondition(idx, 'case_sensitive', e.target.checked)}
                          className="rounded"
                        />
                        Case
                      </label>
                      {formData.conditions.length > 1 && (
                        <button
                          onClick={() => removeCondition(idx)}
                          className="p-1 text-red-400 hover:text-red-300"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Tags */}
              <div>
                <label className="block text-sm text-slate-400 mb-1">Tags (comma separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="e.g., phishing, urgent, finance"
                  className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg"
                />
              </div>

              {/* Test Result */}
              {testResult && (
                <div className={`p-3 rounded-lg ${testResult.triggered ? 'bg-red-500/20 border border-red-500/50' : 'bg-green-500/20 border border-green-500/50'}`}>
                  <div className="flex items-center gap-2">
                    {testResult.triggered ? (
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                    ) : (
                      <Check className="w-5 h-5 text-green-400" />
                    )}
                    <span className="font-medium">
                      {testResult.triggered ? 'Rule would trigger!' : 'Rule would not trigger'}
                    </span>
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-3 pt-4">
                <button
                  onClick={handleSaveRule}
                  disabled={!formData.name || !formData.description || !formData.conditions[0].value}
                  className="flex-1 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg font-medium flex items-center justify-center gap-2"
                >
                  <Save className="w-4 h-4" />
                  {editingRule ? 'Update Rule' : 'Create Rule'}
                </button>
                <button
                  onClick={handleTestRule}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg flex items-center gap-2"
                >
                  <TestTube className="w-4 h-4" />
                  Test
                </button>
              </div>
            </div>
          ) : (
            /* Rules List */
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="text-sm text-slate-400">
                  {rules.length} custom rule{rules.length !== 1 ? 's' : ''}
                </div>
                <button
                  onClick={() => setIsCreating(true)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium flex items-center gap-2"
                >
                  <Plus className="w-4 h-4" />
                  New Rule
                </button>
              </div>

              {rules.length === 0 ? (
                <div className="text-center py-12">
                  <AlertTriangle className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400">No custom rules yet</p>
                  <p className="text-sm text-slate-500 mt-1">Create your first detection rule</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {rules.map((rule) => (
                    <div
                      key={rule.rule_id}
                      className="bg-slate-700/50 rounded-lg border border-slate-600"
                    >
                      {/* Rule Header */}
                      <div
                        className="flex items-center justify-between p-3 cursor-pointer"
                        onClick={() => setExpandedRule(expandedRule === rule.rule_id ? null : rule.rule_id)}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-slate-500'}`} />
                          <div>
                            <div className="font-medium">{rule.name}</div>
                            <div className="text-sm text-slate-400">{rule.rule_id}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(rule.severity)}`}>
                            {(rule.severity || 'medium').toUpperCase()}
                          </span>
                          <span className="text-xs text-slate-400">{rule.category}</span>
                          {expandedRule === rule.rule_id ? (
                            <ChevronUp className="w-4 h-4 text-slate-400" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-slate-400" />
                          )}
                        </div>
                      </div>

                      {/* Expanded Details */}
                      {expandedRule === rule.rule_id && (
                        <div className="px-3 pb-3 border-t border-slate-600 pt-3">
                          <p className="text-sm text-slate-300 mb-3">{rule.description}</p>
                          
                          <div className="mb-3">
                            <div className="text-xs text-slate-400 mb-1">
                              Conditions ({rule.logic}):
                            </div>
                            <div className="space-y-1">
                              {rule.conditions.map((cond, idx) => (
                                <div key={idx} className="text-sm bg-slate-800 px-2 py-1 rounded font-mono">
                                  {cond.field} {cond.match_type} "{cond.value}"
                                </div>
                              ))}
                            </div>
                          </div>

                          {rule.tags.length > 0 && (
                            <div className="flex gap-1 mb-3">
                              {rule.tags.map((tag) => (
                                <span key={tag} className="px-2 py-0.5 bg-slate-600 rounded text-xs">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}

                          <div className="flex gap-2">
                            <button
                              onClick={() => handleEditRule(rule)}
                              className="px-3 py-1.5 bg-slate-600 hover:bg-slate-500 rounded flex items-center gap-1 text-sm"
                            >
                              <Edit2 className="w-3 h-3" /> Edit
                            </button>
                            <button
                              onClick={() => handleToggleRule(rule.rule_id, !rule.enabled)}
                              className={`px-3 py-1.5 rounded flex items-center gap-1 text-sm ${
                                rule.enabled 
                                  ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30'
                                  : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                              }`}
                            >
                              {rule.enabled ? <PowerOff className="w-3 h-3" /> : <Power className="w-3 h-3" />}
                              {rule.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              onClick={() => handleDeleteRule(rule.rule_id)}
                              className="px-3 py-1.5 bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded flex items-center gap-1 text-sm"
                            >
                              <Trash2 className="w-3 h-3" /> Delete
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-700 bg-slate-800/50">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-1">
              <Info className="w-3 h-3" />
              Custom rules are evaluated alongside the 51 built-in detection rules
            </div>
            <div>
              {rules.filter(r => r.enabled).length} active / {rules.length} total
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
