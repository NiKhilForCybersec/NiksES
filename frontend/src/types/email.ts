/**
 * NiksES Email Types
 * 
 * TypeScript interfaces for email data structures.
 * Must match backend Pydantic models exactly.
 */

/**
 * Parsed email address with display name
 */
export interface EmailAddress {
  raw: string;
  email: string;
  display_name: string | null;
  domain: string;
  local_part: string;
}

/**
 * Single hop in the Received header chain
 */
export interface ReceivedHop {
  hop_number: number;
  from_host: string | null;
  from_ip: string | null;
  by_host: string | null;
  by_ip: string | null;
  protocol: string | null;
  timestamp: string | null;
  delay_seconds: number | null;
  raw_header: string;
}

/**
 * Email authentication check result
 */
export interface AuthenticationResult {
  mechanism: 'SPF' | 'DKIM' | 'DMARC';
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  details: string | null;
  domain: string | null;
  selector: string | null;
}

/**
 * URL extracted from email
 */
export interface ExtractedURL {
  url: string;
  normalized_url: string;
  domain: string;
  scheme: string;
  path: string | null;
  query_params: Record<string, string> | null;
  source: 'body_text' | 'body_html' | 'attachment' | 'qr_code';
  is_shortened: boolean;
  final_url: string | null;
}

/**
 * Email attachment metadata
 */
export interface AttachmentInfo {
  filename: string;
  content_type: string;
  size_bytes: number;
  md5: string;
  sha256: string;
  is_executable: boolean;
  is_archive: boolean;
  is_office_with_macros: boolean;
  is_script: boolean;
  extension: string;
  magic_type: string | null;
}

/**
 * Extracted QR code data
 */
export interface QRCodeInfo {
  source_attachment: string;
  decoded_data: string;
  data_type: string;
  extracted_url: string | null;
}

/**
 * Complete parsed email structure
 */
export interface ParsedEmail {
  // Metadata
  message_id: string | null;
  date: string | null;
  subject: string | null;
  
  // Addresses
  sender: EmailAddress | null;
  envelope_from: EmailAddress | null;
  reply_to: EmailAddress | null;
  to_recipients: EmailAddress[];
  cc_recipients: EmailAddress[];
  bcc_recipients: EmailAddress[];
  
  // Routing
  received_chain: ReceivedHop[];
  originating_ip: string | null;
  
  // Authentication
  auth_results: AuthenticationResult[];
  spf_result: AuthenticationResult | null;
  dkim_result: AuthenticationResult | null;
  dmarc_result: AuthenticationResult | null;
  
  // Content
  body_text: string | null;
  body_html: string | null;
  
  // Extracted indicators
  urls: ExtractedURL[];
  attachments: AttachmentInfo[];
  qr_codes: QRCodeInfo[];
  phone_numbers: string[];
  
  // Raw data
  raw_headers: Record<string, string>;
  raw_email: string | null;
}
