/**
 * NiksES Frontend Constants
 * 
 * Central location for ALL frontend constant values.
 * NO MAGIC NUMBERS OR STRINGS ANYWHERE ELSE IN THE CODEBASE.
 */

// =============================================================================
// APPLICATION INFO
// =============================================================================
export const APP_NAME = "NiksES";
export const APP_FULL_NAME = "Niks Email Security";
export const APP_VERSION = "1.0.0";
export const APP_TAGLINE = "AI-Powered Email Investigation Copilot";

// =============================================================================
// API CONFIGURATION
// =============================================================================
export const API_BASE_URL = (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL.trim()) || "/api/v1";
export const API_TIMEOUT = 30000; // 30 seconds

// =============================================================================
// FILE LIMITS
// =============================================================================
export const MAX_FILE_SIZE_MB = 25;
export const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;
export const ALLOWED_FILE_TYPES = [".eml", ".msg"];
export const ALLOWED_MIME_TYPES = ["message/rfc822", "application/vnd.ms-outlook"];

// =============================================================================
// UI CONFIGURATION
// =============================================================================
export const DEFAULT_PAGE_SIZE = 50;
export const TOAST_DURATION = 4000;
export const DEBOUNCE_DELAY = 300;

// =============================================================================
// RISK LEVEL CONFIGURATION
// =============================================================================
export const RISK_LEVELS = {
  informational: { min: 0, max: 19, label: "Informational", color: "blue" },
  low: { min: 20, max: 39, label: "Low", color: "green" },
  medium: { min: 40, max: 59, label: "Medium", color: "yellow" },
  high: { min: 60, max: 79, label: "High", color: "orange" },
  critical: { min: 80, max: 100, label: "Critical", color: "red" },
} as const;

// =============================================================================
// VERDICT CONFIGURATION
// =============================================================================
export const VERDICTS = {
  clean: { label: "Clean", color: "green", icon: "CheckCircle" },
  suspicious: { label: "Suspicious", color: "yellow", icon: "AlertTriangle" },
  malicious: { label: "Malicious", color: "red", icon: "XCircle" },
  unknown: { label: "Unknown", color: "gray", icon: "HelpCircle" },
  error: { label: "Error", color: "gray", icon: "AlertCircle" },
} as const;

// =============================================================================
// CLASSIFICATION LABELS
// =============================================================================
export const CLASSIFICATIONS = {
  benign: "Benign",
  spam: "Spam",
  marketing: "Marketing",
  phishing: "Phishing",
  spear_phishing: "Spear Phishing",
  credential_harvesting: "Credential Harvesting",
  bec: "Business Email Compromise",
  invoice_fraud: "Invoice Fraud",
  gift_card_scam: "Gift Card Scam",
  callback_phishing: "Callback Phishing",
  malware_delivery: "Malware Delivery",
  ransomware: "Ransomware",
  qr_phishing: "QR Phishing",
  brand_impersonation: "Brand Impersonation",
  account_takeover: "Account Takeover",
  unknown: "Unknown",
} as const;

// =============================================================================
// KEYBOARD SHORTCUTS
// =============================================================================
export const KEYBOARD_SHORTCUTS = {
  analyze: "Ctrl+Enter",
  search: "Ctrl+K",
  settings: "Ctrl+,",
  tabSummary: "Ctrl+1",
  tabDetails: "Ctrl+2",
  tabIOCs: "Ctrl+3",
  tabHeaders: "Ctrl+4",
  tabJSON: "Ctrl+5",
  closeModal: "Escape",
} as const;

// =============================================================================
// API SERVICE NAMES
// =============================================================================
export const API_SERVICES = {
  virustotal: { name: "VirusTotal", requiresKey: true },
  abuseipdb: { name: "AbuseIPDB", requiresKey: true },
  urlhaus: { name: "URLhaus", requiresKey: false },
  phishtank: { name: "PhishTank", requiresKey: false },
  whois: { name: "WHOIS", requiresKey: false },
  openai: { name: "OpenAI", requiresKey: true },
  shodan: { name: "Shodan", requiresKey: true },
  greynoise: { name: "GreyNoise", requiresKey: true },
} as const;

// =============================================================================
// RESULTS TAB CONFIGURATION
// =============================================================================
export const RESULTS_TABS = [
  { id: "summary", label: "Summary", shortcut: "1" },
  { id: "details", label: "Details", shortcut: "2" },
  { id: "iocs", label: "IOCs", shortcut: "3" },
  { id: "headers", label: "Headers", shortcut: "4" },
  { id: "json", label: "JSON", shortcut: "5" },
] as const;
