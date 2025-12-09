/**
 * NiksES Email Timeline
 * 
 * Visual representation of email delivery chain.
 * Highlights suspicious hops, delays, and anomalies.
 */

import React, { useMemo } from 'react';
import {
  Clock,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowDown,
  Globe,
  Shield,
  Mail,
  Zap,
} from 'lucide-react';

interface EmailTimelineProps {
  analysisResult: any;
}

interface TimelineHop {
  id: number;
  timestamp: string;
  server: string;
  ip?: string;
  delay?: number;
  action: string;
  suspicious: boolean;
  suspiciousReasons: string[];
}

const EmailTimeline: React.FC<EmailTimelineProps> = ({ analysisResult }) => {
  // Parse email headers to build timeline
  const timeline = useMemo(() => {
    if (!analysisResult?.email) return [];

    const email = analysisResult.email;
    const headers = email.headers || {};
    const hops: TimelineHop[] = [];

    // Parse Received headers (they come in reverse order)
    const receivedHeaders = headers['received'] || [];
    const receivedList = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];

    // Reverse to get chronological order
    const chronological = [...receivedList].reverse();

    let previousTime: Date | null = null;

    chronological.forEach((received: string, index: number) => {
      if (!received) return;

      // Parse the received header
      const fromMatch = received.match(/from\s+([^\s]+)/i);
      const byMatch = received.match(/by\s+([^\s]+)/i);
      const dateMatch = received.match(/;\s*(.+)$/);
      const ipMatch = received.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);

      const server = byMatch?.[1] || fromMatch?.[1] || `Server ${index + 1}`;
      const ip = ipMatch?.[1];
      let timestamp = dateMatch?.[1] || '';
      
      // Try to parse timestamp
      let parsedTime: Date | null = null;
      try {
        parsedTime = new Date(timestamp);
        if (isNaN(parsedTime.getTime())) parsedTime = null;
      } catch {
        parsedTime = null;
      }

      // Calculate delay from previous hop
      let delay = 0;
      if (parsedTime && previousTime) {
        delay = Math.round((parsedTime.getTime() - previousTime.getTime()) / 1000);
      }
      previousTime = parsedTime;

      // Check for suspicious indicators
      const suspiciousReasons: string[] = [];
      
      // Long delays (> 5 minutes)
      if (delay > 300) {
        suspiciousReasons.push(`Long delay: ${Math.round(delay / 60)} minutes`);
      }
      
      // Suspicious server names
      if (server.includes('unknown') || server.includes('localhost')) {
        suspiciousReasons.push('Suspicious server name');
      }

      // IP geolocation mismatches could be checked here
      if (ip) {
        // Check if IP is in a suspicious range (simplified)
        const firstOctet = parseInt(ip.split('.')[0]);
        if (firstOctet === 10 || firstOctet === 192 || firstOctet === 172) {
          // Private IP - could be suspicious if appearing in public relay
        }
      }

      hops.push({
        id: index,
        timestamp: parsedTime ? parsedTime.toLocaleString() : timestamp || 'Unknown',
        server: server.slice(0, 40),
        ip,
        delay,
        action: fromMatch ? `Received from ${fromMatch[1]?.slice(0, 30)}` : 'Received',
        suspicious: suspiciousReasons.length > 0,
        suspiciousReasons,
      });
    });

    // Add final delivery hop
    if (hops.length > 0) {
      const recipients = email.to_recipients || [];
      const recipientEmail = recipients[0]?.email || 'recipient';
      
      hops.push({
        id: hops.length,
        timestamp: email.date ? new Date(email.date).toLocaleString() : 'Unknown',
        server: 'Mailbox',
        action: `Delivered to ${recipientEmail}`,
        suspicious: false,
        suspiciousReasons: [],
      });
    }

    return hops;
  }, [analysisResult]);

  // Calculate total transit time
  const totalTransitTime = useMemo(() => {
    const totalDelay = timeline.reduce((sum, hop) => sum + (hop.delay || 0), 0);
    if (totalDelay < 60) return `${totalDelay} seconds`;
    if (totalDelay < 3600) return `${Math.round(totalDelay / 60)} minutes`;
    return `${Math.round(totalDelay / 3600)} hours`;
  }, [timeline]);

  // Count suspicious hops
  const suspiciousCount = timeline.filter(h => h.suspicious).length;

  // Authentication results
  const authResults = useMemo(() => {
    const headers = analysisResult?.email?.headers || {};
    const authHeader = headers['authentication-results'] || '';
    
    return {
      spf: authHeader.toLowerCase().includes('spf=pass') ? 'pass' : 
           authHeader.toLowerCase().includes('spf=fail') ? 'fail' : 
           authHeader.toLowerCase().includes('spf=') ? 'neutral' : 'unknown',
      dkim: authHeader.toLowerCase().includes('dkim=pass') ? 'pass' :
            authHeader.toLowerCase().includes('dkim=fail') ? 'fail' :
            authHeader.toLowerCase().includes('dkim=') ? 'neutral' : 'unknown',
      dmarc: authHeader.toLowerCase().includes('dmarc=pass') ? 'pass' :
             authHeader.toLowerCase().includes('dmarc=fail') ? 'fail' :
             authHeader.toLowerCase().includes('dmarc=') ? 'neutral' : 'unknown',
    };
  }, [analysisResult]);

  const AuthBadge: React.FC<{ label: string; status: string }> = ({ label, status }) => (
    <div className={`flex items-center gap-1 px-2 py-1 rounded text-sm ${
      status === 'pass' ? 'bg-green-100 text-green-700' :
      status === 'fail' ? 'bg-red-100 text-red-700' :
      status === 'neutral' ? 'bg-yellow-100 text-yellow-700' :
      'bg-gray-700 text-gray-400'
    }`}>
      {status === 'pass' ? <CheckCircle className="w-3 h-3" /> :
       status === 'fail' ? <XCircle className="w-3 h-3" /> :
       <AlertTriangle className="w-3 h-3" />}
      <span className="font-medium">{label}</span>
      <span className="text-xs">({status})</span>
    </div>
  );

  if (timeline.length === 0) {
    return (
      <div className="bg-gray-800 rounded-xl border shadow-sm p-6">
        <h2 className="text-xl font-bold flex items-center gap-2 text-gray-900 mb-4">
          <Clock className="w-6 h-6" />
          Email Delivery Timeline
        </h2>
        <div className="text-gray-400 text-center py-8">
          <Server className="w-12 h-12 mx-auto mb-2 text-gray-300" />
          <p>No delivery path information available</p>
          <p className="text-sm">Received headers may not be present in this email</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-xl border shadow-sm">
      {/* Header */}
      <div className="p-4 border-b bg-gradient-to-r from-blue-50 to-indigo-50">
        <h2 className="text-xl font-bold flex items-center gap-2 text-gray-900">
          <Clock className="w-6 h-6" />
          Email Delivery Timeline
        </h2>
        <p className="text-sm text-gray-400 mt-1">
          Visual representation of the email's journey from sender to recipient
        </p>
      </div>

      {/* Summary Stats */}
      <div className="p-4 bg-gray-900 border-b flex flex-wrap gap-6">
        <div className="flex items-center gap-2">
          <Server className="w-5 h-5 text-blue-600" />
          <span className="text-sm">
            <strong>{timeline.length}</strong> hops
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Clock className="w-5 h-5 text-blue-600" />
          <span className="text-sm">
            <strong>{totalTransitTime}</strong> total transit
          </span>
        </div>
        {suspiciousCount > 0 && (
          <div className="flex items-center gap-2 text-orange-600">
            <AlertTriangle className="w-5 h-5" />
            <span className="text-sm">
              <strong>{suspiciousCount}</strong> suspicious hop{suspiciousCount !== 1 ? 's' : ''}
            </span>
          </div>
        )}
        <div className="flex items-center gap-4 ml-auto">
          <AuthBadge label="SPF" status={authResults.spf} />
          <AuthBadge label="DKIM" status={authResults.dkim} />
          <AuthBadge label="DMARC" status={authResults.dmarc} />
        </div>
      </div>

      {/* Timeline */}
      <div className="p-6">
        <div className="relative">
          {timeline.map((hop, index) => (
            <div key={hop.id} className="relative pl-8 pb-8 last:pb-0">
              {/* Vertical Line */}
              {index < timeline.length - 1 && (
                <div className="absolute left-3 top-6 w-0.5 h-full bg-gray-200" />
              )}
              
              {/* Node */}
              <div className={`absolute left-0 top-1 w-6 h-6 rounded-full flex items-center justify-center ${
                hop.suspicious 
                  ? 'bg-orange-100 border-2 border-orange-400' 
                  : index === timeline.length - 1
                    ? 'bg-green-100 border-2 border-green-400'
                    : 'bg-blue-100 border-2 border-blue-400'
              }`}>
                {hop.suspicious ? (
                  <AlertTriangle className="w-3 h-3 text-orange-600" />
                ) : index === timeline.length - 1 ? (
                  <Mail className="w-3 h-3 text-green-600" />
                ) : (
                  <Server className="w-3 h-3 text-blue-600" />
                )}
              </div>

              {/* Content */}
              <div className={`ml-4 p-3 rounded-lg border ${
                hop.suspicious 
                  ? 'bg-orange-50 border-orange-200' 
                  : 'bg-gray-800 border-gray-600'
              }`}>
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-medium text-gray-900 flex items-center gap-2">
                      {hop.server}
                      {hop.ip && (
                        <span className="text-xs text-gray-400 font-normal">
                          ({hop.ip})
                        </span>
                      )}
                    </div>
                    <div className="text-sm text-gray-400 mt-1">
                      {hop.action}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-gray-400">{hop.timestamp}</div>
                    {hop.delay !== undefined && hop.delay > 0 && (
                      <div className={`text-xs mt-1 flex items-center gap-1 justify-end ${
                        hop.delay > 300 ? 'text-orange-600' : 'text-gray-400'
                      }`}>
                        <Zap className="w-3 h-3" />
                        +{hop.delay < 60 ? `${hop.delay}s` : `${Math.round(hop.delay / 60)}m`}
                      </div>
                    )}
                  </div>
                </div>

                {/* Suspicious reasons */}
                {hop.suspicious && hop.suspiciousReasons.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-orange-200">
                    <div className="text-xs text-orange-700 font-medium flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Anomalies detected:
                    </div>
                    <ul className="mt-1 text-xs text-orange-600">
                      {hop.suspiciousReasons.map((reason, i) => (
                        <li key={i}>• {reason}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Arrow between hops */}
              {index < timeline.length - 1 && (
                <div className="absolute left-2 top-14 text-gray-300">
                  <ArrowDown className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="p-4 bg-gray-900 border-t flex items-center gap-6 text-sm">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-blue-100 border-2 border-blue-400" />
          <span className="text-gray-400">Normal hop</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-orange-100 border-2 border-orange-400" />
          <span className="text-gray-400">Suspicious hop</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-green-100 border-2 border-green-400" />
          <span className="text-gray-400">Final delivery</span>
        </div>
      </div>
    </div>
  );
};

export default EmailTimeline;
