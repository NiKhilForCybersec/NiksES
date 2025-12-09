/**
 * NiksES Analysis Types
 * 
 * TypeScript interfaces for analysis results.
 * Must match backend Pydantic models exactly.
 */

import type { ParsedEmail } from './email';

// =============================================================================
// ENUMS
// =============================================================================

export type ThreatIntelVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error';

export type RiskLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type EmailClassification =
  | 'benign'
  | 'spam'
  | 'marketing'
  | 'phishing'
  | 'spear_phishing'
  | 'credential_harvesting'
  | 'bec'
  | 'invoice_fraud'
  | 'gift_card_scam'
  | 'callback_phishing'
  | 'malware_delivery'
  | 'ransomware'
  | 'qr_phishing'
  | 'brand_impersonation'
  | 'account_takeover'
  | 'unknown';

// =============================================================================
// ENHANCED ANALYSIS TYPES (NEW)
// =============================================================================

/** Social Engineering Analysis Result */
export interface SEAnalysisResult {
  se_score: number;
  se_level: string;
  confidence: number;
  primary_intent: string;
  secondary_intents: string[];
  techniques: string[];
  technique_scores: Record<string, number>;
  explanation: string;
  key_indicators: string[];
  used_llm: boolean;
  llm_error: string | null;
  heuristic_breakdown: {
    urgency: number;
    fear: number;
    authority: number;
    reward: number;
    scarcity: number;
  };
}

/** Content Deconstruction Analysis Result */
export interface ContentAnalysisResult {
  intent: string;
  confidence: number;
  requested_actions: string[];
  target_data: string[];
  business_process_abused: string;
  spoofed_brand: string | null;
  spoofed_entity_type: string | null;
  potential_impact: string[];
  mentioned_amounts: string[];
  mentioned_deadlines: string[];
  mentioned_organizations: string[];
  analysis_method: string;
}

/** Lookalike Domain Match */
export interface LookalikeMatch {
  suspicious_domain: string;
  target_brand: string;
  legitimate_domain: string;
  confidence: number;
  detection_methods: string[];
  edit_distance: number | null;
  homoglyphs_found: string[];
}

/** Lookalike Analysis Result */
export interface LookalikeAnalysisResult {
  has_lookalikes: boolean;
  matches: LookalikeMatch[];
  highest_confidence: number;
  primary_target: string | null;
}

/** TI Source Result */
export interface TISourceResult {
  source: string;
  available: boolean;
  verdict: string;
  score: number | null;
  error: string | null;
  attempts: number;
  was_rate_limited: boolean;
  raw_data: Record<string, any>;
}

/** Fused Threat Intel Result */
export interface FusedTIResult {
  fused_score: number;
  fused_verdict: string;
  confidence: number;
  sources_checked: number;
  sources_available: number;
  sources_flagged: number;
  api_status: Record<string, string>;
  findings: string[];
  source_details: Record<string, TISourceResult>;
}

/** Risk Dimension Score */
export interface DimensionScore {
  dimension: string;
  score: number;
  level: string;
  weight: number;
  indicators: string[];
  details: Record<string, any>;
}

/** MITRE Technique */
export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

/** Unified Risk Score */
export interface UnifiedRiskScore {
  overall_score: number;
  overall_level: string;
  confidence: number;
  primary_classification: string;
  secondary_classifications: string[];
  dimensions: Record<string, DimensionScore>;
  top_indicators: string[];
  summary: string;
  detailed_explanation: string;
  recommended_actions: RecommendedAction[];
  mitre_techniques: MitreTechnique[];
  rules_triggered: number;
  data_sources_available: number;
}

/** Analysis Metadata */
export interface AnalysisMetadata {
  started_at: string;
  completed_at: string | null;
  duration_ms: number;
  components_run: string[];
  components_failed: string[];
  components_skipped: string[];
  api_status: Record<string, string>;
  apis_rate_limited: string[];
  warnings: string[];
  errors: string[];
}

/** Enhanced Analysis Result */
export interface EnhancedAnalysisResult {
  analysis_id: string;
  analysis_duration_ms: number;
  overall_score: number;
  overall_level: string;
  classification: string;
  risk_score: UnifiedRiskScore | null;
  se_analysis: SEAnalysisResult | null;
  content_analysis: ContentAnalysisResult | null;
  lookalike_analysis: LookalikeAnalysisResult | null;
  ti_results: FusedTIResult | null;
  detection_results: any | null;
  header_analysis: any | null;
  metadata: AnalysisMetadata;
}

// =============================================================================
// ENRICHMENT TYPES
// =============================================================================

export interface DomainEnrichment {
  domain: string;
  
  // WHOIS data
  registrar: string | null;
  creation_date: string | null;
  expiration_date: string | null;
  age_days: number | null;
  is_newly_registered: boolean;
  registrant_country: string | null;
  
  // DNS data
  has_mx_records: boolean;
  has_spf_record: boolean;
  has_dmarc_record: boolean;
  nameservers: string[];
  
  // Reputation - VirusTotal
  virustotal_stats: Record<string, number> | null;
  virustotal_positives: number | null;
  virustotal_total: number | null;
  virustotal_verdict: ThreatIntelVerdict;
  is_known_phishing: boolean;
  is_disposable_email: boolean;
  
  // Blacklist data (MXToolbox)
  blacklists_listed: string[];
  blacklist_count: number;
  
  // Lookalike analysis
  is_lookalike: boolean;
  lookalike_target: string | null;
  lookalike_distance: number | null;
  lookalike_technique: string | null;
}

export interface IPEnrichment {
  ip_address: string;
  
  // Geolocation
  country: string | null;
  country_code: string | null;
  city: string | null;
  region: string | null;
  asn: number | null;
  as_org: string | null;
  isp: string | null;
  
  // Reputation - AbuseIPDB
  abuseipdb_score: number | null;
  abuseipdb_reports: number | null;
  abuseipdb_verdict: ThreatIntelVerdict;
  
  // Reputation - VirusTotal
  virustotal_stats: Record<string, number> | null;
  virustotal_positives: number | null;
  virustotal_total: number | null;
  virustotal_verdict: ThreatIntelVerdict;
  
  // Blacklist data (MXToolbox)
  blacklists_listed: string[];
  blacklist_count: number;
  
  // Classification
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  is_known_attacker: boolean;
}

export interface URLEnrichment {
  url: string;
  domain: string;
  
  // VirusTotal
  virustotal_positives: number | null;
  virustotal_total: number | null;
  virustotal_verdict: ThreatIntelVerdict;
  virustotal_categories: string[];
  
  // URLhaus
  urlhaus_status: string | null;
  urlhaus_threat: string | null;
  urlhaus_tags: string[];
  
  // PhishTank
  phishtank_in_database: boolean;
  phishtank_verified: boolean;
  phishtank_verified_at: string | null;
  
  // Overall
  final_verdict: ThreatIntelVerdict;
  is_shortened: boolean;
  redirect_chain: string[];
}

export interface AttachmentEnrichment {
  sha256: string;
  md5: string;
  filename: string;
  
  // VirusTotal
  virustotal_positives: number | null;
  virustotal_total: number | null;
  virustotal_verdict: ThreatIntelVerdict;
  virustotal_threat_names: string[];
  
  // MalwareBazaar
  malwarebazaar_known: boolean;
  malwarebazaar_tags: string[];
  
  // Overall
  final_verdict: ThreatIntelVerdict;
}

export interface EnrichmentResults {
  sender_domain: DomainEnrichment | null;
  reply_to_domain: DomainEnrichment | null;
  url_domains: DomainEnrichment[];
  
  originating_ip: IPEnrichment | null;
  all_ips: IPEnrichment[];
  
  urls: URLEnrichment[];
  attachments: AttachmentEnrichment[];
}

// =============================================================================
// DETECTION TYPES
// =============================================================================

export interface DetectionRule {
  rule_id: string;
  rule_name: string;
  category: string;
  description: string;
  severity: RiskLevel;
  score_impact: number;
  triggered: boolean;
  evidence: string[];
  mitre_technique: string | null;
}

export interface DetectionResults {
  rules_triggered: DetectionRule[];
  rules_passed: DetectionRule[];
  
  // Scoring
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  
  // Classification
  primary_classification: EmailClassification;
  secondary_classifications: EmailClassification[];
  
  // Social engineering indicators
  urgency_score: number;
  authority_score: number;
  fear_score: number;
  reward_score: number;
  
  // Brand impersonation
  impersonated_brand: string | null;
  brand_confidence: number | null;
}

// =============================================================================
// AI TRIAGE TYPES
// =============================================================================

export interface RecommendedAction {
  action: string;
  priority: number;
  description: string;
  automated: boolean;
}

export interface AITriageResult {
  summary: string;
  detailed_analysis: string;
  classification_reasoning: string;
  risk_reasoning: string;
  recommended_actions: RecommendedAction[];
  
  // MITRE ATT&CK mapping
  mitre_tactics: string[];
  mitre_techniques: string[];
  
  // Metadata
  model_used: string;
  tokens_used: number;
  analysis_timestamp: string;
}

// =============================================================================
// IOC TYPES
// =============================================================================

export interface ExtractedIOCs {
  domains: string[];
  urls: string[];
  ips: string[];
  email_addresses: string[];
  file_hashes_md5: string[];
  file_hashes_sha256: string[];
  phone_numbers: string[];
}

// =============================================================================
// MAIN ANALYSIS RESULT
// =============================================================================

export interface AnalysisResult {
  // Identification
  analysis_id: string;
  analyzed_at: string;
  analysis_duration_ms: number;
  
  // Parsed email
  email: ParsedEmail;
  
  // Enrichment
  enrichment: EnrichmentResults;
  
  // Detection
  detection: DetectionResults;
  
  // AI Triage
  ai_triage: AITriageResult | null;
  
  // Extracted IOCs for export
  iocs: ExtractedIOCs;
  
  // Metadata
  api_keys_used: string[];
  enrichment_errors: string[];
  
  // Top-level convenience fields (may be populated by API)
  risk_level?: RiskLevel | string;
  risk_score?: number;
  classification?: EmailClassification | string;
  verdict?: string;
  critical_findings?: number;
}

// =============================================================================
// LIST/SUMMARY TYPES
// =============================================================================

export interface AnalysisSummary {
  analysis_id: string;
  analyzed_at: string;
  subject: string | null;
  sender_email: string | null;
  sender_domain: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  classification: EmailClassification;
  has_attachments: boolean;
  has_urls: boolean;
  attachment_count: number;
  url_count: number;
  ai_summary: string | null;
}

export interface AnalysisListResponse {
  total: number;
  offset: number;
  limit: number;
  analyses: AnalysisSummary[];
}
