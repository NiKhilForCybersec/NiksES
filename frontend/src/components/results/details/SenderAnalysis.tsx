/**
 * SenderAnalysis Component
 * 
 * Displays sender information and potential spoofing indicators.
 */

import React from 'react';

interface EmailAddress {
  raw: string;
  email: string;
  display_name?: string;
  domain: string;
  local_part: string;
}

interface DomainEnrichment {
  domain: string;
  is_newly_registered?: boolean;
  age_days?: number;
  registrar?: string;
  is_disposable_email?: boolean;
  is_lookalike?: boolean;
  lookalike_target?: string;
}

interface SenderAnalysisProps {
  sender: EmailAddress;
  replyTo?: EmailAddress[];
  envelopeFrom?: EmailAddress;
  domainEnrichment?: DomainEnrichment;
  className?: string;
}

export function SenderAnalysis({ 
  sender, 
  replyTo, 
  envelopeFrom, 
  domainEnrichment,
  className = '' 
}: SenderAnalysisProps) {
  const hasReplyToMismatch = replyTo && replyTo.length > 0 && 
    replyTo[0].domain !== sender.domain;
  
  const hasEnvelopeMismatch = envelopeFrom && 
    envelopeFrom.domain !== sender.domain;

  return (
    <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
      {/* From Address */}
      <div className="mb-4">
        <div className="text-sm text-gray-400 mb-1">From</div>
        <div className="text-gray-200">
          {sender.display_name && (
            <span className="font-medium">{sender.display_name}</span>
          )}
          <span className={`${sender.display_name ? 'text-gray-400 ml-2' : ''}`}>
            &lt;{sender.email}&gt;
          </span>
        </div>
      </div>

      {/* Reply-To (if different) */}
      {hasReplyToMismatch && replyTo && (
        <div className="mb-4 p-3 bg-yellow-900/30 rounded border border-yellow-700">
          <div className="text-sm text-yellow-400 mb-1">⚠️ Reply-To (Different Domain)</div>
          <div className="text-gray-200">
            {replyTo[0].display_name && (
              <span className="font-medium">{replyTo[0].display_name}</span>
            )}
            <span className={`${replyTo[0].display_name ? 'text-gray-400 ml-2' : ''}`}>
              &lt;{replyTo[0].email}&gt;
            </span>
          </div>
        </div>
      )}

      {/* Envelope-From (if different) */}
      {hasEnvelopeMismatch && envelopeFrom && (
        <div className="mb-4 p-3 bg-yellow-900/30 rounded border border-yellow-700">
          <div className="text-sm text-yellow-400 mb-1">⚠️ Envelope-From (Different Domain)</div>
          <div className="text-gray-200">
            &lt;{envelopeFrom.email}&gt;
          </div>
        </div>
      )}

      {/* Domain Info */}
      {domainEnrichment && (
        <div className="border-t border-gray-700 pt-4 mt-4">
          <div className="text-sm text-gray-400 mb-2">Sender Domain: {domainEnrichment.domain}</div>
          <div className="flex flex-wrap gap-2">
            {domainEnrichment.is_newly_registered && (
              <span className="px-2 py-1 text-xs bg-yellow-900 text-yellow-300 rounded">
                🆕 Newly Registered ({domainEnrichment.age_days} days)
              </span>
            )}
            {domainEnrichment.is_disposable_email && (
              <span className="px-2 py-1 text-xs bg-red-900 text-red-300 rounded">
                🗑️ Disposable Email
              </span>
            )}
            {domainEnrichment.is_lookalike && (
              <span className="px-2 py-1 text-xs bg-red-900 text-red-300 rounded">
                ⚠️ Lookalike of {domainEnrichment.lookalike_target}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default SenderAnalysis;
