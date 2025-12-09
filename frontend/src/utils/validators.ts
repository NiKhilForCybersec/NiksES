/**
 * NiksES Validation Utilities
 * 
 * Functions for validating user input.
 */

import { MAX_FILE_SIZE_BYTES, ALLOWED_FILE_TYPES } from './constants';

/**
 * Validate uploaded file
 */
export function validateFile(file: File): { valid: boolean; error?: string } {
  // Check file size
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `File size exceeds maximum of ${MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB`,
    };
  }
  
  // Check file extension
  const extension = `.${file.name.split('.').pop()?.toLowerCase()}`;
  if (!ALLOWED_FILE_TYPES.includes(extension)) {
    return {
      valid: false,
      error: `Invalid file type. Allowed types: ${ALLOWED_FILE_TYPES.join(', ')}`,
    };
  }
  
  return { valid: true };
}

/**
 * Validate raw email text
 */
export function validateRawEmail(text: string): { valid: boolean; error?: string } {
  if (!text || text.trim().length === 0) {
    return { valid: false, error: 'Email content is required' };
  }
  
  // Check for basic email headers
  const hasFrom = /^From:/im.test(text);
  const hasTo = /^To:/im.test(text);
  const hasSubject = /^Subject:/im.test(text);
  const hasReceived = /^Received:/im.test(text);
  
  if (!hasFrom && !hasReceived) {
    return {
      valid: false,
      error: 'Invalid email format. Missing required headers (From or Received)',
    };
  }
  
  return { valid: true };
}

/**
 * Validate API key format
 */
export function validateApiKey(service: string, key: string): { valid: boolean; error?: string } {
  if (!key || key.trim().length === 0) {
    return { valid: false, error: 'API key is required' };
  }
  
  // Service-specific validation
  switch (service) {
    case 'virustotal':
      if (!/^[a-f0-9]{64}$/i.test(key)) {
        return { valid: false, error: 'VirusTotal API key should be 64 hexadecimal characters' };
      }
      break;
    case 'abuseipdb':
      if (!/^[a-f0-9]{80}$/i.test(key)) {
        return { valid: false, error: 'AbuseIPDB API key should be 80 hexadecimal characters' };
      }
      break;
    case 'openai':
      if (!key.startsWith('sk-')) {
        return { valid: false, error: 'OpenAI API key should start with "sk-"' };
      }
      break;
  }
  
  return { valid: true };
}

/**
 * Validate search query
 */
export function validateSearchQuery(query: string): { valid: boolean; error?: string } {
  if (query.length > 500) {
    return { valid: false, error: 'Search query too long (max 500 characters)' };
  }
  
  return { valid: true };
}

/**
 * Check if string is a valid email address
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Check if string is a valid URL
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if string is a valid IP address (v4 or v6)
 */
export function isValidIp(ip: string): boolean {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => parseInt(part, 10) <= 255);
  }
  
  // IPv6 (simplified check)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Check if string is a valid domain
 */
export function isValidDomain(domain: string): boolean {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}
