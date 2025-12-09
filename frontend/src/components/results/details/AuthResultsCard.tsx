/**
 * AuthResultsCard Component
 * 
 * Displays email authentication results (SPF, DKIM, DMARC).
 */

import React from 'react';

interface AuthResult {
  mechanism: string;
  result: string;
  details?: string;
  domain?: string;
  selector?: string;
}

interface AuthResultsCardProps {
  email: any;
  className?: string;
}

export function AuthResultsCard({ email, className = '' }: AuthResultsCardProps) {
  const getResultColor = (result: string): string => {
    const r = result?.toLowerCase();
    if (r === 'pass') return 'bg-green-900 text-green-300';
    if (r === 'fail' || r === 'hardfail') return 'bg-red-900 text-red-300';
    if (r === 'softfail') return 'bg-yellow-900 text-yellow-300';
    if (r === 'neutral' || r === 'none') return 'bg-gray-700 text-gray-300';
    return 'bg-gray-700 text-gray-400';
  };

  const getResultIcon = (result: string): string => {
    const r = result?.toLowerCase();
    if (r === 'pass') return '✓';
    if (r === 'fail' || r === 'hardfail') return '✗';
    if (r === 'softfail') return '~';
    return '?';
  };

  const spf = email?.header_analysis?.spf_result || email?.spf_result;
  const dkim = email?.header_analysis?.dkim_result || email?.dkim_result;
  const dmarc = email?.header_analysis?.dmarc_result || email?.dmarc_result;

  const hasAnyAuth = spf || dkim || dmarc;

  if (!hasAnyAuth) {
    return (
      <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
        <div className="text-yellow-400 text-center">
          ⚠️ No email authentication records found
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
      <div className="grid grid-cols-3 gap-4">
        {/* SPF */}
        <div className="text-center">
          <div className="text-sm text-gray-400 mb-2">SPF</div>
          {spf ? (
            <div className={`inline-flex items-center px-3 py-1 rounded ${getResultColor(spf.result)}`}>
              <span className="mr-1">{getResultIcon(spf.result)}</span>
              {spf.result?.toUpperCase()}
            </div>
          ) : (
            <span className="text-gray-500">None</span>
          )}
          {spf?.domain && (
            <div className="text-xs text-gray-500 mt-1 truncate">{spf.domain}</div>
          )}
        </div>

        {/* DKIM */}
        <div className="text-center">
          <div className="text-sm text-gray-400 mb-2">DKIM</div>
          {dkim ? (
            <div className={`inline-flex items-center px-3 py-1 rounded ${getResultColor(dkim.result)}`}>
              <span className="mr-1">{getResultIcon(dkim.result)}</span>
              {dkim.result?.toUpperCase()}
            </div>
          ) : (
            <span className="text-gray-500">None</span>
          )}
          {dkim?.selector && (
            <div className="text-xs text-gray-500 mt-1 truncate">
              Selector: {dkim.selector}
            </div>
          )}
        </div>

        {/* DMARC */}
        <div className="text-center">
          <div className="text-sm text-gray-400 mb-2">DMARC</div>
          {dmarc ? (
            <div className={`inline-flex items-center px-3 py-1 rounded ${getResultColor(dmarc.result)}`}>
              <span className="mr-1">{getResultIcon(dmarc.result)}</span>
              {dmarc.result?.toUpperCase()}
            </div>
          ) : (
            <span className="text-gray-500">None</span>
          )}
          {dmarc?.domain && (
            <div className="text-xs text-gray-500 mt-1 truncate">{dmarc.domain}</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default AuthResultsCard;
