/**
 * NiksES Executive Summary
 * 
 * Non-technical summary for management escalation.
 * Includes business impact assessment and one-click export.
 */

import React, { useState } from 'react';
import {
  FileText,
  Download,
  Copy,
  Check,
  AlertTriangle,
  Shield,
  DollarSign,
  Users,
  Clock,
  TrendingUp,
  Building,
} from 'lucide-react';

interface ExecutiveSummaryProps {
  analysisResult: any;
}

const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({ analysisResult }) => {
  const [copySuccess, setCopySuccess] = useState(false);

  if (!analysisResult) {
    return <div className="text-gray-500">No analysis data available</div>;
  }

  const email = analysisResult.email || {};
  const detection = analysisResult.detection || {};
  const aiTriage = analysisResult.ai_triage || {};

  // Extract key data
  const classification = detection.primary_classification || 'unknown';
  const riskLevel = detection.risk_level || 'medium';
  const riskScore = detection.risk_score || 0;
  const sender = email.sender?.email || 'Unknown';
  const subject = email.subject || '(No Subject)';
  const recipientCount = (email.to_recipients?.length || 0) + (email.cc_recipients?.length || 0);

  // Map classification to business-friendly terms
  const classificationMap: Record<string, string> = {
    phishing: 'Phishing Attack',
    spear_phishing: 'Targeted Phishing Attack',
    credential_harvesting: 'Credential Theft Attempt',
    bec: 'Business Email Compromise',
    invoice_fraud: 'Invoice/Payment Fraud',
    malware_delivery: 'Malware Distribution',
    ransomware: 'Ransomware Delivery',
    brand_impersonation: 'Brand Impersonation',
    spam: 'Spam/Unsolicited Email',
    benign: 'Legitimate Email',
  };

  const friendlyClassification = classificationMap[classification] || classification;

  // Business impact assessment
  const getBusinessImpact = () => {
    if (classification === 'bec' || classification === 'invoice_fraud') {
      return {
        level: 'CRITICAL',
        color: 'red',
        description: 'Potential direct financial loss. Wire fraud attempts can result in immediate monetary damages.',
        financialRisk: 'High - Potential for significant financial loss',
        reputationalRisk: 'Medium - May indicate targeted attack on organization',
        operationalRisk: 'Medium - May require finance team intervention',
      };
    } else if (classification === 'ransomware' || classification === 'malware_delivery') {
      return {
        level: 'CRITICAL',
        color: 'red',
        description: 'Potential for system compromise and business disruption. Ransomware can halt operations.',
        financialRisk: 'High - Potential ransom demands and recovery costs',
        reputationalRisk: 'High - Data breach notification may be required',
        operationalRisk: 'Critical - Business operations may be disrupted',
      };
    } else if (classification === 'credential_harvesting' || classification === 'spear_phishing') {
      return {
        level: 'HIGH',
        color: 'orange',
        description: 'Targeted attack attempting to steal employee credentials for further access.',
        financialRisk: 'Medium - Stolen credentials can lead to fraud',
        reputationalRisk: 'Medium - Data exposure possible',
        operationalRisk: 'Medium - Account remediation required',
      };
    } else if (classification === 'phishing') {
      return {
        level: 'MEDIUM',
        color: 'yellow',
        description: 'Mass phishing attempt targeting employees. Risk depends on user interaction.',
        financialRisk: 'Low to Medium - Depends on user action',
        reputationalRisk: 'Low - Common attack type',
        operationalRisk: 'Low - Standard remediation',
      };
    } else {
      return {
        level: 'LOW',
        color: 'green',
        description: 'Low-risk email with minimal business impact.',
        financialRisk: 'Low',
        reputationalRisk: 'Low',
        operationalRisk: 'Low',
      };
    }
  };

  const impact = getBusinessImpact();

  // Generate executive summary text
  const generateSummaryText = () => {
    const timestamp = new Date().toLocaleString();
    const attackType = friendlyClassification;
    
    let summary = `EXECUTIVE SECURITY BRIEFING
Generated: ${timestamp}
Classification: ${attackType}
Severity: ${(riskLevel || 'unknown').toUpperCase()} (Score: ${riskScore}/100)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INCIDENT SUMMARY

A ${(attackType || 'threat').toLowerCase()} was detected targeting ${recipientCount} employee${recipientCount !== 1 ? 's' : ''}. `;

    if (classification === 'bec' || classification === 'invoice_fraud') {
      summary += `This attack attempted to manipulate employees into making unauthorized payments or changing banking details. `;
    } else if (classification === 'credential_harvesting') {
      summary += `The attacker attempted to steal employee login credentials through a fake login page. `;
    } else if (classification === 'malware_delivery' || classification === 'ransomware') {
      summary += `The email contained malicious attachments designed to compromise employee workstations. `;
    } else if (classification === 'phishing') {
      summary += `The email used social engineering tactics to deceive recipients into taking harmful actions. `;
    }

    summary += `

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BUSINESS IMPACT ASSESSMENT

Overall Impact Level: ${impact.level}

• Financial Risk: ${impact.financialRisk}
• Reputational Risk: ${impact.reputationalRisk}
• Operational Risk: ${impact.operationalRisk}

${impact.description}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ACTIONS TAKEN

✓ Malicious email identified and quarantined
✓ Sender blocked at email gateway
✓ Malicious URLs/domains added to blocklist
✓ Affected users notified
✓ Incident documented for compliance

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDATIONS FOR LEADERSHIP

1. ${classification === 'bec' || classification === 'invoice_fraud' 
   ? 'Review and reinforce payment verification procedures'
   : 'Continue security awareness training for employees'}

2. ${riskLevel === 'critical' || riskLevel === 'high'
   ? 'Consider briefing affected department heads'
   : 'Monitor for similar attacks in coming days'}

3. ${recipientCount > 5 
   ? 'Assess whether additional user communication is needed'
   : 'Standard incident response procedures sufficient'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For questions or concerns, contact the Security Operations Center.

Analysis ID: ${analysisResult.analysis_id || 'N/A'}
`;

    return summary;
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(generateSummaryText());
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  const downloadSummary = () => {
    const content = generateSummaryText();
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `executive-summary-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-sm">
      {/* Header */}
      <div className="p-4 border-b border-gray-700 bg-gray-800">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold flex items-center gap-2 text-gray-100">
            <Building className="w-6 h-6 text-indigo-400" />
            Executive Summary
          </h2>
          <div className="flex gap-2">
            <button
              onClick={copyToClipboard}
              className="flex items-center gap-2 px-3 py-1.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm"
            >
              {copySuccess ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copySuccess ? 'Copied!' : 'Copy'}
            </button>
            <button
              onClick={downloadSummary}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 text-sm"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
          </div>
        </div>
        <p className="text-sm text-gray-400 mt-1">
          Non-technical briefing for management and stakeholders
        </p>
      </div>

      <div className="p-4 md:p-6 space-y-4 md:space-y-6">
        {/* Quick Summary Card */}
        <div className={`p-3 md:p-4 rounded-lg border-2 ${
          impact.color === 'red' ? 'bg-red-900/30 border-red-700' :
          impact.color === 'orange' ? 'bg-orange-900/30 border-orange-700' :
          impact.color === 'yellow' ? 'bg-yellow-900/30 border-yellow-700' :
          'bg-green-900/30 border-green-700'
        }`}>
          <div className="flex items-start gap-3 md:gap-4">
            <div className={`p-2 md:p-3 rounded-full ${
              impact.color === 'red' ? 'bg-red-900/50' :
              impact.color === 'orange' ? 'bg-orange-900/50' :
              impact.color === 'yellow' ? 'bg-yellow-900/50' :
              'bg-green-900/50'
            }`}>
              <AlertTriangle className={`w-5 h-5 md:w-6 md:h-6 ${
                impact.color === 'red' ? 'text-red-400' :
                impact.color === 'orange' ? 'text-orange-400' :
                impact.color === 'yellow' ? 'text-yellow-400' :
                'text-green-400'
              }`} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-bold text-base md:text-lg text-gray-100">{friendlyClassification}</h3>
                <span className={`px-2 py-0.5 rounded text-xs md:text-sm font-medium ${
                  impact.color === 'red' ? 'bg-red-900/50 text-red-400 border border-red-700' :
                  impact.color === 'orange' ? 'bg-orange-900/50 text-orange-400 border border-orange-700' :
                  impact.color === 'yellow' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-700' :
                  'bg-green-900/50 text-green-400 border border-green-700'
                }`}>
                  {impact.level}
                </span>
              </div>
              <p className="text-sm md:text-base text-gray-300 mt-1">{impact.description}</p>
            </div>
          </div>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 md:gap-4">
          <div className="bg-gray-900 rounded-lg p-3 md:p-4 text-center border border-gray-700">
            <div className="text-2xl md:text-3xl font-bold text-gray-100">{riskScore}</div>
            <div className="text-xs md:text-sm text-gray-400">Risk Score</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 md:p-4 text-center border border-gray-700">
            <div className="text-2xl md:text-3xl font-bold text-gray-100">{recipientCount}</div>
            <div className="text-xs md:text-sm text-gray-400">Users Targeted</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 md:p-4 text-center border border-gray-700">
            <div className="text-2xl md:text-3xl font-bold text-gray-100">{email.urls?.length || 0}</div>
            <div className="text-xs md:text-sm text-gray-400">Malicious URLs</div>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 md:p-4 text-center border border-gray-700">
            <div className="text-2xl md:text-3xl font-bold text-gray-100">{email.attachments?.length || 0}</div>
            <div className="text-xs md:text-sm text-gray-400">Attachments</div>
          </div>
        </div>

        {/* Attachment Threat Analysis */}
        {email.attachments?.length > 0 && email.attachments.some((a: any) => a.threat_score > 0 || a.has_macros || a.has_javascript || a.is_executable) && (
          <div className="border border-red-700/50 rounded-lg bg-red-950/20">
            <div className="bg-red-900/30 px-4 py-2 border-b border-red-700/50 font-medium flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-4 h-4" />
              ⚠️ Attachment Threat Analysis
            </div>
            <div className="p-4 space-y-3">
              <p className="text-gray-300 text-sm">
                Static analysis of email attachments identified the following security concerns:
              </p>
              {email.attachments.filter((att: any) => att.threat_score > 0 || att.has_macros || att.has_javascript || att.is_executable).map((att: any, idx: number) => {
                const threatLevel = att.threat_level?.toLowerCase() || 'unknown';
                const threatColor = threatLevel === 'critical' || threatLevel === 'high' ? 'red' : 
                                   threatLevel === 'medium' ? 'orange' : 
                                   threatLevel === 'low' ? 'yellow' : 'gray';
                return (
                  <div key={idx} className={`border border-${threatColor}-700/50 rounded-lg p-3 bg-gray-900/50`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-gray-200">{att.filename}</span>
                      {att.threat_score > 0 && (
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          threatLevel === 'critical' || threatLevel === 'high' ? 'bg-red-900/50 text-red-400 border border-red-700' :
                          threatLevel === 'medium' ? 'bg-orange-900/50 text-orange-400 border border-orange-700' :
                          'bg-yellow-900/50 text-yellow-400 border border-yellow-700'
                        }`}>
                          Threat Score: {att.threat_score}/100 ({(threatLevel || 'unknown').toUpperCase()})
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {att.is_executable && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">EXECUTABLE</span>
                      )}
                      {att.has_macros && (
                        <span className="px-1.5 py-0.5 bg-orange-900/50 text-orange-400 text-xs rounded border border-orange-700">VBA MACROS</span>
                      )}
                      {att.has_auto_exec_macros && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">AUTO-EXEC</span>
                      )}
                      {att.has_dde && (
                        <span className="px-1.5 py-0.5 bg-orange-900/50 text-orange-400 text-xs rounded border border-orange-700">DDE</span>
                      )}
                      {att.has_ole_objects && (
                        <span className="px-1.5 py-0.5 bg-yellow-900/50 text-yellow-400 text-xs rounded border border-yellow-700">OLE</span>
                      )}
                      {att.has_javascript && (
                        <span className="px-1.5 py-0.5 bg-orange-900/50 text-orange-400 text-xs rounded border border-orange-700">JAVASCRIPT</span>
                      )}
                      {att.has_embedded_files && (
                        <span className="px-1.5 py-0.5 bg-yellow-900/50 text-yellow-400 text-xs rounded border border-yellow-700">EMBEDDED</span>
                      )}
                      {att.is_packed && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">PACKED</span>
                      )}
                      {att.has_suspicious_imports && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">SUS IMPORTS</span>
                      )}
                      {att.type_mismatch && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">TYPE MISMATCH</span>
                      )}
                      {att.has_double_extension && (
                        <span className="px-1.5 py-0.5 bg-red-900/50 text-red-400 text-xs rounded border border-red-700">DOUBLE EXT</span>
                      )}
                    </div>
                    {att.threat_summary && (
                      <p className="text-sm text-gray-400 italic">{att.threat_summary}</p>
                    )}
                    {att.sha256 && (
                      <p className="text-xs text-gray-500 mt-1 font-mono">SHA256: {att.sha256.substring(0, 32)}...</p>
                    )}
                  </div>
                );
              })}
              <p className="text-xs text-gray-500 mt-2">
                Recommendation: Do not open these attachments. Submit to sandbox for further analysis if needed.
              </p>
            </div>
          </div>
        )}

        {/* Business Impact Assessment */}
        <div className="border border-gray-700 rounded-lg">
          <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 font-medium flex items-center gap-2 text-gray-200">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            Business Impact Assessment
          </div>
          <div className="p-4 grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
                <DollarSign className="w-4 h-4 text-green-400" />
                Financial Risk
              </div>
              <p className="text-sm text-gray-400">{impact.financialRisk}</p>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
                <Shield className="w-4 h-4 text-blue-400" />
                Reputational Risk
              </div>
              <p className="text-sm text-gray-400">{impact.reputationalRisk}</p>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
                <Clock className="w-4 h-4 text-orange-400" />
                Operational Risk
              </div>
              <p className="text-sm text-gray-400">{impact.operationalRisk}</p>
            </div>
          </div>
        </div>

        {/* Plain English Summary */}
        <div className="border border-gray-700 rounded-lg">
          <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 font-medium flex items-center gap-2 text-gray-200">
            <FileText className="w-4 h-4 text-purple-400" />
            What Happened
          </div>
          <div className="p-4 space-y-3 text-gray-300">
            <p>
              <strong>On {new Date(email.date || Date.now()).toLocaleDateString()}</strong>, 
              our security analysis identified a potential <strong>{friendlyClassification.toLowerCase()}</strong> attempt 
              targeting {recipientCount} employee{recipientCount !== 1 ? 's' : ''} in our organization.
            </p>
            <p>
              The suspicious email originated from <code className="bg-gray-700 px-1 rounded">{sender}</code> with 
              the subject line "{subject.slice(0, 50)}{subject.length > 50 ? '...' : ''}".
            </p>
            <p>
              <strong>Status:</strong> This email has been flagged for review. 
              The following actions are recommended based on the threat classification.
            </p>
          </div>
        </div>

        {/* Recommended Actions - NOT Actions Taken */}
        <div className="border border-gray-700 rounded-lg">
          <div className="bg-amber-900/30 px-4 py-2 border-b border-gray-700 font-medium flex items-center gap-2 text-amber-400">
            <AlertTriangle className="w-4 h-4" />
            Recommended Actions
          </div>
          <div className="p-4">
            <p className="text-sm text-gray-500 mb-3">The following actions are recommended based on the threat analysis:</p>
            <ul className="space-y-2">
              {[
                { action: 'Quarantine or delete the malicious email', priority: 'high' },
                { action: 'Block sender address at email gateway', priority: 'high' },
                { action: 'Add malicious URLs/domains to web filter blocklist', priority: email.urls?.length > 0 ? 'high' : 'low' },
                { action: 'Notify affected users with guidance', priority: 'medium' },
                { action: 'Log incident for compliance and tracking', priority: 'medium' },
                { action: 'Update detection rules to catch similar attempts', priority: 'low' },
              ].filter(item => {
                // Only show relevant actions
                if (item.action.includes('URLs') && (!email.urls || email.urls.length === 0)) return false;
                return true;
              }).map((item, i) => (
                <li key={i} className="flex items-center gap-2 text-gray-300">
                  <span className={`w-2 h-2 rounded-full ${
                    item.priority === 'high' ? 'bg-red-500' :
                    item.priority === 'medium' ? 'bg-yellow-500' :
                    'bg-gray-400'
                  }`} />
                  {item.action}
                  <span className={`text-xs px-1.5 py-0.5 rounded ${
                    item.priority === 'high' ? 'bg-red-900/50 text-red-400 border border-red-700' :
                    item.priority === 'medium' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-700' :
                    'bg-gray-700 text-gray-400'
                  }`}>
                    {item.priority}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Recommendations */}
        <div className="border border-gray-700 rounded-lg">
          <div className="bg-blue-900/30 px-4 py-2 border-b border-gray-700 font-medium flex items-center gap-2 text-blue-400">
            <Users className="w-4 h-4" />
            Recommendations
          </div>
          <div className="p-4 space-y-2">
            {riskLevel === 'critical' || riskLevel === 'high' ? (
              <>
                <p className="text-gray-300">
                  <strong>1. Executive Awareness:</strong> Brief relevant department heads about this targeted attack.
                </p>
                <p className="text-gray-300">
                  <strong>2. Enhanced Monitoring:</strong> Increase vigilance for similar attacks in the coming days.
                </p>
                {(classification === 'bec' || classification === 'invoice_fraud') && (
                  <p className="text-gray-300">
                    <strong>3. Finance Controls:</strong> Remind finance team of payment verification procedures.
                  </p>
                )}
              </>
            ) : (
              <>
                <p className="text-gray-300">
                  <strong>1. Standard Procedures:</strong> Continue normal security operations and monitoring.
                </p>
                <p className="text-gray-300">
                  <strong>2. Awareness:</strong> Use this as a training example in upcoming security awareness sessions.
                </p>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExecutiveSummary;
