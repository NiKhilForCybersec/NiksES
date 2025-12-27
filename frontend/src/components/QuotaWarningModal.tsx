import React, { useState, useEffect } from 'react';
import { AlertTriangle, X, Zap, Shield, ExternalLink } from 'lucide-react';

interface QuotaWarningModalProps {
  onClose?: () => void;
}

const QuotaWarningModal: React.FC<QuotaWarningModalProps> = ({ onClose }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [dontShowAgain, setDontShowAgain] = useState(false);

  useEffect(() => {
    // Check if user has dismissed the warning before
    const dismissed = localStorage.getItem('nikses_quota_warning_dismissed');
    const dismissedDate = localStorage.getItem('nikses_quota_warning_date');
    
    // Show warning if never dismissed, or dismissed more than 7 days ago
    if (!dismissed) {
      setIsVisible(true);
    } else if (dismissedDate) {
      const daysSinceDismissed = (Date.now() - parseInt(dismissedDate)) / (1000 * 60 * 60 * 24);
      if (daysSinceDismissed > 7) {
        setIsVisible(true);
      }
    }
  }, []);

  const handleClose = () => {
    if (dontShowAgain) {
      localStorage.setItem('nikses_quota_warning_dismissed', 'true');
      localStorage.setItem('nikses_quota_warning_date', Date.now().toString());
    }
    setIsVisible(false);
    onClose?.();
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg bg-gray-900 border border-yellow-500/30 rounded-xl shadow-2xl shadow-yellow-500/10 overflow-hidden">
        {/* Header with warning gradient */}
        <div className="bg-gradient-to-r from-yellow-500/20 via-orange-500/20 to-red-500/20 px-6 py-4 border-b border-yellow-500/20">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-500/20 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-yellow-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-yellow-400">
                ⚠️ Free Tier API Quota Notice
              </h2>
              <p className="text-sm text-gray-400">Please read before analyzing</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            className="absolute top-4 right-4 p-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-5 space-y-4">
          {/* Main warning */}
          <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
            <p className="text-yellow-200 font-medium">
              This instance uses <span className="text-yellow-400 font-bold">FREE TIER</span> threat intelligence APIs with limited daily quotas.
            </p>
          </div>

          {/* Quota details */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
              Daily Limits (Approximate)
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <QuotaItem name="VirusTotal" limit="4/min, ~500/day" color="blue" />
              <QuotaItem name="IPQualityScore" limit="~200/day" color="purple" />
              <QuotaItem name="AbuseIPDB" limit="~1000/day" color="green" />
              <QuotaItem name="URLScan.io" limit="~50/day" color="orange" />
            </div>
          </div>

          {/* Tips */}
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-blue-400" />
              Smart Usage Tips
            </h3>
            <ul className="space-y-2 text-sm text-gray-400">
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                <span>System auto-filters safe URLs (images, tracking, known domains)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                <span>Only suspicious URLs are sent to threat intel APIs</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                <span>Analyze important/suspicious emails first</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 mt-0.5">💡</span>
                <span>For production use, consider upgrading API plans</span>
              </li>
            </ul>
          </div>

          {/* Shield note */}
          <div className="flex items-center gap-3 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <Shield className="w-5 h-5 text-blue-400 flex-shrink-0" />
            <p className="text-sm text-blue-200">
              AI analysis and detection rules work without external APIs and have no quota limits.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-gray-800/50 border-t border-gray-700 flex items-center justify-between">
          <label className="flex items-center gap-2 cursor-pointer group">
            <input
              type="checkbox"
              checked={dontShowAgain}
              onChange={(e) => setDontShowAgain(e.target.checked)}
              className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0 cursor-pointer"
            />
            <span className="text-sm text-gray-400 group-hover:text-gray-300">
              Don't show for 7 days
            </span>
          </label>
          <button
            onClick={handleClose}
            className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors flex items-center gap-2"
          >
            I Understand
          </button>
        </div>
      </div>
    </div>
  );
};

// Sub-component for quota items
const QuotaItem: React.FC<{ name: string; limit: string; color: string }> = ({ name, limit, color }) => {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    green: 'bg-green-500/10 border-green-500/20 text-green-400',
    orange: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
  };

  return (
    <div className={`p-3 rounded-lg border ${colorClasses[color]}`}>
      <div className="font-medium text-sm">{name}</div>
      <div className="text-xs text-gray-400 mt-0.5">{limit}</div>
    </div>
  );
};

export default QuotaWarningModal;
