/**
 * DetailsTab Component
 * 
 * Displays detailed email analysis including sender, authentication, and IP reputation.
 */

import React from 'react';
import { SenderAnalysis } from './SenderAnalysis';
import { AuthResultsCard } from './AuthResultsCard';
import { IPCard } from './IPCard';
import { DomainCard } from './DomainCard';
import { EmailMetadata } from './EmailMetadata';

interface DetailsTabProps {
  analysis: any;
  className?: string;
}

export function DetailsTab({ analysis, className = '' }: DetailsTabProps) {
  const email = analysis?.email;
  const enrichment = analysis?.enrichment;
  const detection = analysis?.detection;

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Email Metadata */}
      <section>
        <h3 className="text-lg font-semibold text-gray-200 mb-3">Email Metadata</h3>
        <EmailMetadata email={email} />
      </section>

      {/* Sender Analysis */}
      {email?.sender && (
        <section>
          <h3 className="text-lg font-semibold text-gray-200 mb-3">Sender Analysis</h3>
          <SenderAnalysis 
            sender={email.sender}
            replyTo={email.reply_to}
            envelopeFrom={email.envelope_from}
            domainEnrichment={enrichment?.sender_domain}
          />
        </section>
      )}

      {/* Authentication Results */}
      {email && (
        <section>
          <h3 className="text-lg font-semibold text-gray-200 mb-3">Email Authentication</h3>
          <AuthResultsCard email={email} />
        </section>
      )}

      {/* IP Reputation */}
      {(enrichment?.originating_ip || (enrichment?.all_ips && enrichment.all_ips.length > 0)) && (
        <section>
          <h3 className="text-lg font-semibold text-gray-200 mb-3">IP Reputation</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {enrichment?.originating_ip && (
              <IPCard 
                ip={enrichment.originating_ip} 
                label="Originating IP"
              />
            )}
            {enrichment?.all_ips?.filter((ip: any) => 
              ip.ip_address !== enrichment?.originating_ip?.ip_address
            ).slice(0, 3).map((ip: any, idx: number) => (
              <IPCard 
                key={ip.ip_address || idx}
                ip={ip} 
                label={`Relay IP ${idx + 1}`}
              />
            ))}
          </div>
        </section>
      )}

      {/* Domain Enrichment */}
      {enrichment?.sender_domain && (
        <section>
          <h3 className="text-lg font-semibold text-gray-200 mb-3">Sender Domain Analysis</h3>
          <DomainCard domain={enrichment.sender_domain} />
        </section>
      )}

      {/* Detection Rules Triggered */}
      {detection?.rules_triggered && detection.rules_triggered.length > 0 && (
        <section>
          <h3 className="text-lg font-semibold text-gray-200 mb-3">
            Detection Rules Triggered ({detection.rules_triggered.length})
          </h3>
          <div className="space-y-2">
            {detection.rules_triggered.map((rule: any) => (
              <div 
                key={rule.rule_id}
                className="bg-gray-800 rounded-lg p-3 border-l-4"
                style={{
                  borderLeftColor: 
                    rule.severity === 'critical' ? '#ef4444' :
                    rule.severity === 'high' ? '#f97316' :
                    rule.severity === 'medium' ? '#eab308' :
                    rule.severity === 'low' ? '#3b82f6' : '#6b7280'
                }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-mono text-xs text-gray-400 mr-2">{rule.rule_id}</span>
                    <span className="text-gray-200">{rule.rule_name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      rule.severity === 'critical' ? 'bg-red-900 text-red-300' :
                      rule.severity === 'high' ? 'bg-orange-900 text-orange-300' :
                      rule.severity === 'medium' ? 'bg-yellow-900 text-yellow-300' :
                      rule.severity === 'low' ? 'bg-blue-900 text-blue-300' : 'bg-gray-700 text-gray-300'
                    }`}>
                      {rule.severity?.toUpperCase()}
                    </span>
                    <span className="text-xs text-gray-400">+{rule.score_impact}</span>
                  </div>
                </div>
                <p className="text-sm text-gray-400 mt-1">{rule.description}</p>
                {rule.evidence && rule.evidence.length > 0 && (
                  <div className="mt-2 text-xs text-gray-500 bg-gray-900 rounded p-2">
                    {rule.evidence.slice(0, 3).map((ev: string, i: number) => (
                      <div key={i} className="truncate">{ev}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

export default DetailsTab;
