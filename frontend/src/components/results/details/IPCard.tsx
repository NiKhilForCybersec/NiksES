/**
 * IPCard Component
 * 
 * Displays IP reputation and geolocation information.
 */

import React from 'react';

interface IPEnrichment {
  ip_address: string;
  country?: string;
  country_code?: string;
  city?: string;
  region?: string;
  asn?: number;
  as_org?: string;
  isp?: string;
  abuseipdb_score?: number;
  abuseipdb_reports?: number;
  abuseipdb_verdict?: string;
  virustotal_verdict?: string;
  virustotal_positives?: number;
  virustotal_total?: number;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
  is_datacenter?: boolean;
  is_known_attacker?: boolean;
  blacklists_listed?: string[];
  blacklist_count?: number;
}

interface IPCardProps {
  ip: IPEnrichment;
  label?: string;
  className?: string;
}

export function IPCard({ ip, label = 'IP Address', className = '' }: IPCardProps) {
  const getScoreColor = (score: number | undefined): string => {
    if (score === undefined || score === null) return 'text-gray-400';
    if (score >= 75) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getScoreBgColor = (score: number | undefined): string => {
    if (score === undefined || score === null) return 'bg-gray-700';
    if (score >= 75) return 'bg-red-900/50';
    if (score >= 50) return 'bg-orange-900/50';
    if (score >= 25) return 'bg-yellow-900/50';
    return 'bg-green-900/50';
  };

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

  const flags: string[] = [];
  if (ip.is_tor) flags.push('🧅 Tor');
  if (ip.is_vpn) flags.push('🔒 VPN');
  if (ip.is_proxy) flags.push('🔄 Proxy');
  if (ip.is_datacenter) flags.push('🏢 Datacenter');
  if (ip.is_known_attacker) flags.push('⚠️ Known Attacker');
  if (ip.blacklist_count && ip.blacklist_count > 0) flags.push(`🚫 ${ip.blacklist_count} blacklist(s)`);

  return (
    <div className={`bg-gray-800 rounded-lg p-4 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-gray-400">{label}</span>
        {getVerdictBadge(ip.abuseipdb_verdict)}
      </div>
      
      {/* IP Address */}
      <div className="font-mono text-lg text-white mb-3">{ip.ip_address}</div>
      
      {/* AbuseIPDB Score */}
      {ip.abuseipdb_score !== undefined && ip.abuseipdb_score !== null && (
        <div className={`${getScoreBgColor(ip.abuseipdb_score)} rounded-lg p-3 mb-3`}>
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-300">AbuseIPDB Score</span>
            <span className={`text-2xl font-bold ${getScoreColor(ip.abuseipdb_score)}`}>
              {ip.abuseipdb_score}
              <span className="text-sm text-gray-400">/100</span>
            </span>
          </div>
          {ip.abuseipdb_reports !== undefined && (
            <div className="text-xs text-gray-400 mt-1">
              {ip.abuseipdb_reports} abuse report{ip.abuseipdb_reports !== 1 ? 's' : ''}
            </div>
          )}
        </div>
      )}

      {/* VirusTotal Score */}
      {ip.virustotal_positives !== undefined && ip.virustotal_total !== undefined && (
        <div className={`rounded-lg p-3 mb-3 ${ip.virustotal_positives > 0 ? 'bg-red-900/30' : 'bg-green-900/30'}`}>
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-300">VirusTotal</span>
            <span className={`font-bold ${ip.virustotal_positives > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {ip.virustotal_positives}/{ip.virustotal_total} detections
            </span>
          </div>
        </div>
      )}

      {/* Blacklist Details */}
      {ip.blacklists_listed && ip.blacklists_listed.length > 0 && (
        <div className="mb-3 p-2 bg-red-900/20 rounded border border-red-800">
          <div className="text-xs text-red-400 mb-1">Blacklisted on:</div>
          <div className="flex flex-wrap gap-1">
            {ip.blacklists_listed.slice(0, 3).map((bl, i) => (
              <span key={i} className="px-2 py-0.5 text-xs bg-red-900/50 text-red-300 rounded">
                {bl}
              </span>
            ))}
            {ip.blacklists_listed.length > 3 && (
              <span className="px-2 py-0.5 text-xs bg-gray-700 text-gray-400 rounded">
                +{ip.blacklists_listed.length - 3} more
              </span>
            )}
          </div>
        </div>
      )}
      
      {/* Flags */}
      {flags.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-3">
          {flags.map((flag, i) => (
            <span key={i} className="px-2 py-1 text-xs bg-gray-700 rounded text-gray-300">
              {flag}
            </span>
          ))}
        </div>
      )}
      
      {/* Geolocation */}
      <div className="space-y-1 text-sm">
        {(ip.country || ip.country_code) && (
          <div className="flex justify-between">
            <span className="text-gray-400">Location</span>
            <span className="text-gray-200">
              {ip.city && `${ip.city}, `}
              {ip.region && `${ip.region}, `}
              {ip.country || ip.country_code}
            </span>
          </div>
        )}
        {ip.isp && (
          <div className="flex justify-between">
            <span className="text-gray-400">ISP</span>
            <span className="text-gray-200 truncate max-w-[200px]" title={ip.isp}>
              {ip.isp}
            </span>
          </div>
        )}
        {ip.as_org && (
          <div className="flex justify-between">
            <span className="text-gray-400">AS Org</span>
            <span className="text-gray-200 truncate max-w-[200px]" title={ip.as_org}>
              {ip.asn && `AS${ip.asn} - `}{ip.as_org}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

export default IPCard;
