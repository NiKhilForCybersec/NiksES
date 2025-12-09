/**
 * NiksES Formatting Utilities
 * 
 * Functions for formatting dates, sizes, risk scores, etc.
 */

import { RISK_LEVELS } from './constants';
import type { RiskLevel } from './theme';

/**
 * Format a date to a human-readable string
 */
export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return 'N/A';
  
  const d = typeof date === 'string' ? new Date(date) : date;
  
  if (isNaN(d.getTime())) return 'Invalid date';
  
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format a date to relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(date: string | Date | null | undefined): string {
  if (!date) return 'N/A';
  
  const d = typeof date === 'string' ? new Date(date) : date;
  
  if (isNaN(d.getTime())) return 'Invalid date';
  
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);
  
  if (diffSeconds < 60) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  
  return formatDate(d);
}

/**
 * Format file size to human-readable string
 */
export function formatFileSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return 'N/A';
  
  if (bytes === 0) return '0 B';
  
  const units = ['B', 'KB', 'MB', 'GB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${units[i]}`;
}

/**
 * Get risk level from score
 */
export function getRiskLevelFromScore(score: number): RiskLevel {
  for (const [level, config] of Object.entries(RISK_LEVELS)) {
    if (score >= config.min && score <= config.max) {
      return level as RiskLevel;
    }
  }
  return 'informational';
}

/**
 * Format risk score with level label
 */
export function formatRiskScore(score: number): string {
  const level = getRiskLevelFromScore(score);
  const config = RISK_LEVELS[level];
  return `${score}/100 (${config.label})`;
}

/**
 * Format duration in milliseconds to human-readable string
 */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return 'N/A';
  
  if (ms < 1000) return `${ms}ms`;
  
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  return `${minutes}m ${remainingSeconds}s`;
}

/**
 * Truncate string with ellipsis
 */
export function truncate(str: string | null | undefined, maxLength: number): string {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return `${str.slice(0, maxLength - 3)}...`;
}

/**
 * Defang URL for safe display
 */
export function defangUrl(url: string): string {
  return url
    .replace(/https?:\/\//gi, 'hxxps://')
    .replace(/\./g, '[.]');
}

/**
 * Defang IP address for safe display
 */
export function defangIp(ip: string): string {
  return ip.replace(/\./g, '[.]');
}

/**
 * Format email address for display
 */
export function formatEmailAddress(
  email: string | null | undefined,
  displayName?: string | null
): string {
  if (!email) return 'N/A';
  if (displayName) return `${displayName} <${email}>`;
  return email;
}

/**
 * Format count with plural label
 */
export function formatCount(count: number, singular: string, plural?: string): string {
  const p = plural || `${singular}s`;
  return `${count} ${count === 1 ? singular : p}`;
}
