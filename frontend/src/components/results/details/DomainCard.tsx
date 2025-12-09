/**
 * DomainCard Component
 * 
 * Displays domain reputation and WHOIS information.
 */

import React from 'react';

interface DomainEnrichment {
  domain: string;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  age_days?: number;
  is_newly_registered?: boolean;
  registrant_country?: string;
  has_mx_records?: boolean;
  has_spf_record?: boolean;
  has_dmarc_record?: boolean;
  nameservers?: string[];
  virustotal_verdict?: string;
  virustotal_positives?: number;
  virustotal_total?: number;
  is_known_phishing?: boolean;
  is_disposable_email?: boolean;
  is_lookalike?: boolean;
  lookalike_target?: string;
  lookalike_technique?: string;
  blacklists_listed?: string[];
  blacklist_count?: number;
}

interface DomainCardProps {
  domain: DomainEnrichment;
  className?: string;
}

export function DomainCard({ domain, className = '' }: DomainCardProps) {
  const getVerdictBadge = (verdict: string | undefined) => {
    if (!verdict || verdict === 'unknown') {
      return <span className="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-400">Unknown</span>;
    }
    if (verdict === 'malicious') {
      return <span className="px-2 py-0.5 rounded text-xs bg-red-900 text-red-300">Malicious</span>;
    }
    if (verdict === 'suspicious') {
      return <span className="px-2 py-0.5 rounded text-xs bg-yellow-900 text-yellow-300">Suspicious</span>;
    }
    return <span className="px-2 py-0.5 rounded text-xs bg-green-900 text-green-300">Clean</span>;
  };

  const warnings: string[] = [];
  if (domain.is_newly_registered) warnings.push(`🆕 Newly registered (${domain.age_days} days)`);
  if (domain.is_disposable_email) warnings.push('🗑️ Disposable email domain');
  if (domain.is_known_phishing) warnings.push('🎣 Known phishing domain');
  if (domain.is_lookalike) warnings.push(`⚠️ Lookalike of ${domain.lookalike_target}`);
  if (!domain.has_mx_records) warnings.push('📧 No MX records');
  if (domain.blacklist_count && domain.blacklist_count > 0) {
    warnings.push(`🚫 Listed on ${domain.blacklist_count} blacklist(s)`);
  }

  return (
    <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <span className="font-mono text-lg text-white">{domain.domain}</span>
        {getVerdictBadge(domain.virustotal_verdict)}
      </div>

      {/* VirusTotal Score */}
      {domain.virustotal_positives !== undefined && domain.virustotal_total !== undefined && (
        <div className={`mb-3 p-2 rounded ${domain.virustotal_positives > 0 ? 'bg-red-900/30' : 'bg-green-900/30'}`}>
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-300">VirusTotal</span>
            <span className={`font-bold ${domain.virustotal_positives > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {domain.virustotal_positives}/{domain.virustotal_total} detections
            </span>
          </div>
        </div>
      )}

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="mb-4 p-3 bg-yellow-900/30 rounded border border-yellow-700">
          <div className="space-y-1">
            {warnings.map((warning, i) => (
              <div key={i} className="text-sm text-yellow-300">{warning}</div>
            ))}
          </div>
        </div>
      )}

      {/* Blacklist Details */}
      {domain.blacklists_listed && domain.blacklists_listed.length > 0 && (
        <div className="mb-3 p-2 bg-red-900/20 rounded border border-red-800">
          <div className="text-xs text-red-400 mb-1">Blacklisted on:</div>
          <div className="flex flex-wrap gap-1">
            {domain.blacklists_listed.slice(0, 5).map((bl, i) => (
              <span key={i} className="px-2 py-0.5 text-xs bg-red-900/50 text-red-300 rounded">
                {bl}
              </span>
            ))}
            {domain.blacklists_listed.length > 5 && (
              <span className="px-2 py-0.5 text-xs bg-gray-700 text-gray-400 rounded">
                +{domain.blacklists_listed.length - 5} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* Domain Details */}
      <div className="space-y-2 text-sm">
        {domain.registrar && (
          <div className="flex justify-between">
            <span className="text-gray-400">Registrar</span>
            <span className="text-gray-200">{domain.registrar}</span>
          </div>
        )}
        {domain.age_days !== undefined && (
          <div className="flex justify-between">
            <span className="text-gray-400">Domain Age</span>
            <span className="text-gray-200">{domain.age_days} days</span>
          </div>
        )}
        {domain.registrant_country && (
          <div className="flex justify-between">
            <span className="text-gray-400">Registrant Country</span>
            <span className="text-gray-200">{domain.registrant_country}</span>
          </div>
        )}
      </div>

      {/* DNS Records */}
      <div className="border-t border-gray-700 pt-3 mt-3">
        <div className="text-sm text-gray-400 mb-2">DNS Records</div>
        <div className="flex flex-wrap gap-2">
          <span className={`px-2 py-1 text-xs rounded ${domain.has_mx_records ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-400'}`}>
            {domain.has_mx_records ? '✓' : '✗'} MX
          </span>
          <span className={`px-2 py-1 text-xs rounded ${domain.has_spf_record ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-400'}`}>
            {domain.has_spf_record ? '✓' : '✗'} SPF
          </span>
          <span className={`px-2 py-1 text-xs rounded ${domain.has_dmarc_record ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-400'}`}>
            {domain.has_dmarc_record ? '✓' : '✗'} DMARC
          </span>
        </div>
      </div>
    </div>
  );
}

export default DomainCard;
