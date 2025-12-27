"""
NiksES String Extractor

Extract interesting strings from file content:
- URLs and domains
- IP addresses
- Email addresses
- File paths
- Registry keys
- Suspicious patterns
"""

import re
from typing import Dict, List, Any
from collections import Counter

from app.models.static_analysis import ExtractedString


class StringExtractor:
    """
    Extract interesting and suspicious strings from binary content.
    
    Useful for finding IOCs embedded in documents, executables, etc.
    """
    
    # Minimum string length to consider
    MIN_STRING_LENGTH = 4
    
    # Maximum strings to keep per category
    MAX_STRINGS_PER_CATEGORY = 50
    
    # Patterns for extraction
    PATTERNS = {
        'url': re.compile(
            rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,500}',
            re.IGNORECASE
        ),
        'domain': re.compile(
            rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            re.IGNORECASE
        ),
        'ipv4': re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ipv6': re.compile(
            rb'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        'email': re.compile(
            rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        ),
        'windows_path': re.compile(
            rb'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        ),
        'unix_path': re.compile(
            rb'/(?:usr|etc|var|tmp|home|opt|bin|sbin|lib|root)/[a-zA-Z0-9._/-]+',
        ),
        'registry': re.compile(
            rb'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\[a-zA-Z0-9\\._-]+',
            re.IGNORECASE
        ),
    }
    
    # Suspicious string patterns
    SUSPICIOUS_PATTERNS = {
        'shell_commands': re.compile(
            rb'(?:cmd\.exe|powershell|bash|sh -c|/bin/sh|wscript|cscript|mshta)',
            re.IGNORECASE
        ),
        'download_functions': re.compile(
            rb'(?:UrlDownloadToFile|WebClient|Invoke-WebRequest|wget|curl|bitsadmin)',
            re.IGNORECASE
        ),
        'execution_functions': re.compile(
            rb'(?:ShellExecute|CreateProcess|WinExec|system\(|exec\(|eval\(|spawn)',
            re.IGNORECASE
        ),
        'encoding_functions': re.compile(
            rb'(?:base64|FromBase64|ToBase64|atob|btoa|decode|encode)',
            re.IGNORECASE
        ),
        'credential_access': re.compile(
            rb'(?:password|passwd|credential|login|secret|token|api_key|apikey)',
            re.IGNORECASE
        ),
        'persistence': re.compile(
            rb'(?:CurrentVersion\\Run|Scheduled Tasks|crontab|launchd|systemctl)',
            re.IGNORECASE
        ),
        'network_functions': re.compile(
            rb'(?:socket|connect|bind|listen|send|recv|WSAStartup|InternetOpen)',
            re.IGNORECASE
        ),
        'crypto_functions': re.compile(
            rb'(?:AES|RSA|DES|encrypt|decrypt|CryptoAPI|CryptAcquire)',
            re.IGNORECASE
        ),
        'anti_analysis': re.compile(
            rb'(?:IsDebuggerPresent|CheckRemoteDebugger|vmware|virtualbox|sandbox)',
            re.IGNORECASE
        ),
    }
    
    # Known malicious/suspicious strings
    SUSPICIOUS_STRINGS = {
        b'mimikatz',
        b'lazagne',
        b'cobaltstrike',
        b'meterpreter',
        b'metasploit',
        b'bloodhound',
        b'sharphound',
        b'rubeus',
        b'kerberoast',
        b'psexec',
        b'certutil',
        b'rundll32',
        b'regsvr32',
        b'msiexec',
    }
    
    def extract(self, content: bytes) -> Dict[str, Any]:
        """
        Extract all interesting strings from content.
        
        Args:
            content: File content as bytes
            
        Returns:
            Dictionary with extracted strings organized by type
        """
        results = {
            'urls': [],
            'domains': [],
            'ips': [],
            'emails': [],
            'paths': [],
            'registry_keys': [],
            'suspicious': [],
            'strings': [],
            'summary': {},
        }
        
        # Extract URLs
        url_matches = self.PATTERNS['url'].findall(content)
        for match in url_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                url = match.decode('utf-8', errors='ignore')
                if url not in results['urls']:
                    results['urls'].append(url)
                    results['strings'].append(ExtractedString(
                        value=url,
                        string_type='url',
                        context=None
                    ))
            except Exception:
                pass
        
        # Extract IPs
        ip_matches = self.PATTERNS['ipv4'].findall(content)
        for match in ip_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                ip = match.decode('utf-8', errors='ignore')
                # Filter out common false positives
                if not self._is_valid_ip(ip):
                    continue
                if ip not in results['ips']:
                    results['ips'].append(ip)
                    results['strings'].append(ExtractedString(
                        value=ip,
                        string_type='ip',
                        context=None
                    ))
            except Exception:
                pass
        
        # Extract emails
        email_matches = self.PATTERNS['email'].findall(content)
        for match in email_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                email = match.decode('utf-8', errors='ignore')
                if email not in results['emails']:
                    results['emails'].append(email)
                    results['strings'].append(ExtractedString(
                        value=email,
                        string_type='email',
                        context=None
                    ))
            except Exception:
                pass
        
        # Extract Windows paths
        path_matches = self.PATTERNS['windows_path'].findall(content)
        for match in path_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                path = match.decode('utf-8', errors='ignore')
                if len(path) > 5 and path not in results['paths']:
                    results['paths'].append(path)
                    results['strings'].append(ExtractedString(
                        value=path,
                        string_type='path',
                        context=None
                    ))
            except Exception:
                pass
        
        # Extract Unix paths
        unix_path_matches = self.PATTERNS['unix_path'].findall(content)
        for match in unix_path_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                path = match.decode('utf-8', errors='ignore')
                if path not in results['paths']:
                    results['paths'].append(path)
                    results['strings'].append(ExtractedString(
                        value=path,
                        string_type='path',
                        context=None
                    ))
            except Exception:
                pass
        
        # Extract registry keys
        reg_matches = self.PATTERNS['registry'].findall(content)
        for match in reg_matches[:self.MAX_STRINGS_PER_CATEGORY]:
            try:
                key = match.decode('utf-8', errors='ignore')
                if key not in results['registry_keys']:
                    results['registry_keys'].append(key)
                    results['strings'].append(ExtractedString(
                        value=key,
                        string_type='registry',
                        context=None
                    ))
            except Exception:
                pass
        
        # Find suspicious patterns
        for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches[:10]:
                try:
                    value = match.decode('utf-8', errors='ignore')
                    if value not in results['suspicious']:
                        results['suspicious'].append(value)
                        results['strings'].append(ExtractedString(
                            value=value,
                            string_type=f'suspicious_{pattern_name}',
                            context=pattern_name
                        ))
                except Exception:
                    pass
        
        # Check for known malicious strings
        content_lower = content.lower()
        for sus_string in self.SUSPICIOUS_STRINGS:
            if sus_string in content_lower:
                value = sus_string.decode('utf-8')
                if value not in results['suspicious']:
                    results['suspicious'].append(value)
                    results['strings'].append(ExtractedString(
                        value=value,
                        string_type='known_malicious',
                        context='Known malware/tool reference'
                    ))
        
        # Extract printable ASCII strings (general)
        ascii_strings = self._extract_ascii_strings(content)
        interesting_ascii = self._filter_interesting_strings(ascii_strings)
        for s in interesting_ascii[:50]:
            if not any(s == es.value for es in results['strings']):
                results['strings'].append(ExtractedString(
                    value=s,
                    string_type='ascii',
                    context=None
                ))
        
        # Generate summary
        results['summary'] = {
            'urls': len(results['urls']),
            'ips': len(results['ips']),
            'emails': len(results['emails']),
            'paths': len(results['paths']),
            'registry_keys': len(results['registry_keys']),
            'suspicious': len(results['suspicious']),
            'total_strings': len(results['strings']),
        }
        
        return results
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid and not a common false positive."""
        parts = ip.split('.')
        
        # Filter out version numbers (e.g., 1.0.0.1)
        if parts[0] == '0' or parts[-1] == '0':
            return False
        
        # Filter out common non-routable
        if parts[0] == '0':
            return False
        
        # Keep private ranges as they might be C2
        # 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        
        return True
    
    def _extract_ascii_strings(self, content: bytes, min_length: int = 6) -> List[str]:
        """Extract printable ASCII strings from binary content."""
        strings = []
        current = []
        
        for byte in content:
            # Printable ASCII range
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    def _filter_interesting_strings(self, strings: List[str]) -> List[str]:
        """Filter strings to keep only interesting ones."""
        interesting = []
        
        # Keywords that make a string interesting
        interesting_keywords = {
            'http', 'https', 'ftp', 'file://',
            'password', 'login', 'user', 'admin',
            'key', 'token', 'secret', 'credential',
            'execute', 'shell', 'cmd', 'powershell',
            'download', 'upload', 'connect', 'socket',
            'error', 'failed', 'success', 'debug',
            '.exe', '.dll', '.bat', '.ps1', '.vbs',
            '.doc', '.pdf', '.zip', '.rar',
            'HKEY_', 'SOFTWARE\\', 'System32',
            'AppData', 'Temp', 'Windows',
        }
        
        for s in strings:
            s_lower = s.lower()
            
            # Skip very short or very long
            if len(s) < 6 or len(s) > 500:
                continue
            
            # Skip if mostly numbers
            digits = sum(1 for c in s if c.isdigit())
            if digits / len(s) > 0.8:
                continue
            
            # Check for interesting keywords
            if any(kw in s_lower for kw in interesting_keywords):
                interesting.append(s)
                continue
            
            # Keep strings that look like paths
            if '\\' in s or '/' in s:
                if len(s) > 10:
                    interesting.append(s)
                    continue
            
            # Keep strings with mixed case (might be function names)
            if any(c.isupper() for c in s) and any(c.islower() for c in s):
                if not ' ' in s and len(s) > 8:
                    interesting.append(s)
        
        return interesting[:100]
    
    def extract_unicode_strings(self, content: bytes, min_length: int = 6) -> List[str]:
        """Extract Unicode (UTF-16) strings from content."""
        strings = []
        
        # Try UTF-16 LE (common in Windows)
        try:
            # Look for UTF-16 LE patterns (ASCII char followed by null)
            i = 0
            current = []
            while i < len(content) - 1:
                if content[i+1] == 0 and 32 <= content[i] <= 126:
                    current.append(chr(content[i]))
                    i += 2
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
                    i += 1
            
            if len(current) >= min_length:
                strings.append(''.join(current))
                
        except Exception:
            pass
        
        return strings
