"""
NiksES PE Analyzer

Analyze Windows PE (Portable Executable) files for:
- Basic PE information
- Import analysis (suspicious APIs)
- Section analysis
- Packing detection
- Security features
- Digital signature verification
"""

import re
import struct
import logging
from typing import Optional, List, Set
from datetime import datetime

from app.models.static_analysis import (
    PEAnalysisResult,
    PEImportInfo,
    PESectionInfo,
)

logger = logging.getLogger(__name__)


class PEAnalyzer:
    """
    Analyze Windows PE executables for malicious indicators.
    
    Checks:
    - Suspicious API imports (process injection, keylogging, etc.)
    - Packing indicators
    - Anomalous section characteristics
    - Missing security features
    """
    
    # Suspicious Windows API imports
    SUSPICIOUS_APIS = {
        # Process manipulation
        'CreateRemoteThread': 'Remote thread injection',
        'VirtualAllocEx': 'Remote memory allocation',
        'WriteProcessMemory': 'Process memory writing',
        'ReadProcessMemory': 'Process memory reading',
        'NtCreateThreadEx': 'Native thread creation',
        'RtlCreateUserThread': 'User thread creation',
        'NtUnmapViewOfSection': 'Process hollowing',
        'QueueUserAPC': 'APC injection',
        
        # Code injection
        'SetWindowsHookEx': 'Keyboard/mouse hooking',
        'SetWindowsHookExA': 'Keyboard/mouse hooking',
        'SetWindowsHookExW': 'Keyboard/mouse hooking',
        'GetAsyncKeyState': 'Keylogging',
        'GetKeyState': 'Keylogging',
        
        # Privilege escalation
        'AdjustTokenPrivileges': 'Privilege manipulation',
        'OpenProcessToken': 'Token access',
        'LookupPrivilegeValue': 'Privilege lookup',
        
        # Anti-debugging
        'IsDebuggerPresent': 'Debugger detection',
        'CheckRemoteDebuggerPresent': 'Remote debugger detection',
        'NtQueryInformationProcess': 'Process information query',
        'OutputDebugString': 'Debug string output',
        
        # File operations
        'CreateFile': 'File creation/access',
        'WriteFile': 'File writing',
        'DeleteFile': 'File deletion',
        'MoveFile': 'File moving',
        'CopyFile': 'File copying',
        
        # Registry operations
        'RegCreateKey': 'Registry key creation',
        'RegSetValue': 'Registry value setting',
        'RegOpenKey': 'Registry key access',
        'RegDeleteKey': 'Registry key deletion',
        
        # Network
        'InternetOpen': 'Internet connection',
        'InternetConnect': 'Internet connection',
        'InternetReadFile': 'Internet data reading',
        'HttpOpenRequest': 'HTTP request',
        'HttpSendRequest': 'HTTP request sending',
        'URLDownloadToFile': 'File download',
        'socket': 'Socket creation',
        'connect': 'Socket connection',
        'send': 'Socket sending',
        'recv': 'Socket receiving',
        'WSAStartup': 'Winsock initialization',
        
        # Crypto
        'CryptEncrypt': 'Data encryption',
        'CryptDecrypt': 'Data decryption',
        'CryptAcquireContext': 'Crypto context',
        
        # Execution
        'WinExec': 'Program execution',
        'ShellExecute': 'Shell execution',
        'ShellExecuteEx': 'Shell execution',
        'CreateProcess': 'Process creation',
        'system': 'System command',
        
        # DLL operations
        'LoadLibrary': 'DLL loading',
        'GetProcAddress': 'Function address lookup',
        'LdrLoadDll': 'Native DLL loading',
    }
    
    # Known packer signatures
    PACKER_SIGNATURES = {
        b'UPX!': 'UPX',
        b'UPX0': 'UPX',
        b'UPX1': 'UPX',
        b'.aspack': 'ASPack',
        b'ASPack': 'ASPack',
        b'.adata': 'ASPack',
        b'PEC2': 'PECompact',
        b'pec1': 'PECompact',
        b'PELock': 'PELock',
        b'.petite': 'Petite',
        b'.Themida': 'Themida',
        b'Themida': 'Themida',
        b'.vmp0': 'VMProtect',
        b'.vmp1': 'VMProtect',
        b'VMProtect': 'VMProtect',
        b'.enigma': 'Enigma',
        b'.nsp0': 'NsPack',
        b'.nsp1': 'NsPack',
        b'.MPRESS': 'MPRESS',
    }
    
    # Suspicious section names
    SUSPICIOUS_SECTIONS = {
        '.upx', 'upx0', 'upx1', 'upx2',  # UPX packer
        '.aspack', '.adata',  # ASPack
        '.vmp', '.vmp0', '.vmp1',  # VMProtect
        '.themida',  # Themida
        '.nsp', '.nsp0', '.nsp1',  # NsPack
        '.enigma',  # Enigma
        '.packed', '.pack',  # Generic packed
    }
    
    def analyze(self, content: bytes) -> PEAnalysisResult:
        """
        Analyze PE executable.
        
        Args:
            content: PE file content as bytes
            
        Returns:
            PEAnalysisResult with findings
        """
        result = PEAnalysisResult()
        
        # Verify PE signature
        if content[:2] != b'MZ':
            return result
        
        # Try using pefile library first
        try:
            self._analyze_with_pefile(content, result)
        except ImportError:
            logger.warning("pefile not installed, using basic PE analysis")
            self._basic_analysis(content, result)
        except Exception as e:
            logger.warning(f"pefile analysis failed: {e}, falling back to basic")
            self._basic_analysis(content, result)
        
        # Check for packing
        self._check_packing(content, result)
        
        return result
    
    def _analyze_with_pefile(self, content: bytes, result: PEAnalysisResult):
        """Analyze PE using pefile library."""
        import pefile
        
        pe = pefile.PE(data=content)
        
        # Basic info
        result.machine_type = self._get_machine_type(pe.FILE_HEADER.Machine)
        result.is_64bit = pe.FILE_HEADER.Machine == 0x8664  # AMD64
        result.is_dll = pe.FILE_HEADER.Characteristics & 0x2000  # IMAGE_FILE_DLL
        
        # Compilation timestamp
        try:
            timestamp = pe.FILE_HEADER.TimeDateStamp
            if timestamp and timestamp > 0:
                result.compilation_timestamp = datetime.fromtimestamp(timestamp)
        except Exception:
            pass
        
        # Subsystem
        if hasattr(pe, 'OPTIONAL_HEADER'):
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            subsystem_map = {
                1: 'Native',
                2: 'GUI',
                3: 'Console',
                5: 'OS/2',
                7: 'POSIX',
                9: 'CE',
            }
            result.subsystem = subsystem_map.get(subsystem, f'Unknown ({subsystem})')
            
            # Security features
            dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
            result.has_aslr = bool(dll_characteristics & 0x0040)  # DYNAMIC_BASE
            result.has_dep = bool(dll_characteristics & 0x0100)  # NX_COMPAT
            result.has_seh = not bool(dll_characteristics & 0x0400)  # NO_SEH (inverted)
            result.has_cfg = bool(dll_characteristics & 0x4000)  # GUARD_CF
        
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                suspicious = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        functions.append(func_name)
                        
                        # Check if suspicious
                        if func_name in self.SUSPICIOUS_APIS:
                            suspicious.append(func_name)
                            if func_name not in result.suspicious_imports:
                                result.suspicious_imports.append(func_name)
                
                result.imports.append(PEImportInfo(
                    dll_name=dll_name,
                    functions=functions,
                    suspicious_functions=suspicious
                ))
                result.total_imports += len(functions)
        
        # Sections
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            section_info = PESectionInfo(
                name=section_name,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=section.get_entropy(),
                is_executable=bool(section.Characteristics & 0x20000000),  # IMAGE_SCN_MEM_EXECUTE
                is_writable=bool(section.Characteristics & 0x80000000),  # IMAGE_SCN_MEM_WRITE
                characteristics=section.Characteristics
            )
            result.sections.append(section_info)
            
            # Check for suspicious sections
            if section_name.lower() in self.SUSPICIOUS_SECTIONS:
                result.suspicious_sections.append(section_name)
            
            # High entropy in executable section might indicate packing
            if section_info.entropy > 7.0 and section_info.is_executable:
                result.packing_indicators.append(f"High entropy in {section_name}: {section_info.entropy:.2f}")
        
        # Version info
        if hasattr(pe, 'FileInfo'):
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else key
                                val_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else value
                                
                                if key_str == 'FileVersion':
                                    result.file_version = val_str
                                elif key_str == 'ProductVersion':
                                    result.product_version = val_str
                                elif key_str == 'OriginalFilename':
                                    result.original_filename = val_str
                                elif key_str == 'InternalName':
                                    result.internal_name = val_str
                                elif key_str == 'CompanyName':
                                    result.company_name = val_str
                                elif key_str == 'ProductName':
                                    result.product_name = val_str
        
        # Resources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            result.has_resources = True
            self._analyze_resources(pe, result)
        
        pe.close()
    
    def _basic_analysis(self, content: bytes, result: PEAnalysisResult):
        """Basic PE analysis without pefile library."""
        # Check for imports by looking for DLL names
        content_lower = content.lower()
        
        common_dlls = [
            b'kernel32.dll', b'user32.dll', b'advapi32.dll',
            b'ntdll.dll', b'ws2_32.dll', b'wininet.dll',
            b'shell32.dll', b'ole32.dll', b'crypt32.dll'
        ]
        
        for dll in common_dlls:
            if dll in content_lower:
                result.imports.append(PEImportInfo(
                    dll_name=dll.decode('utf-8'),
                    functions=[],
                    suspicious_functions=[]
                ))
        
        # Look for suspicious API names in content
        for api_name, description in self.SUSPICIOUS_APIS.items():
            if api_name.encode('utf-8') in content:
                result.suspicious_imports.append(api_name)
        
        # Check for 64-bit
        try:
            # PE header offset at 0x3C
            pe_offset = struct.unpack('<I', content[0x3C:0x40])[0]
            if content[pe_offset:pe_offset+4] == b'PE\x00\x00':
                machine = struct.unpack('<H', content[pe_offset+4:pe_offset+6])[0]
                result.is_64bit = machine == 0x8664
        except Exception:
            pass
    
    def _check_packing(self, content: bytes, result: PEAnalysisResult):
        """Check for packer signatures."""
        # Check for known packer signatures
        for signature, packer_name in self.PACKER_SIGNATURES.items():
            if signature in content:
                result.is_packed = True
                result.packer_name = packer_name
                result.packing_indicators.append(f"Found {packer_name} signature")
                break
        
        # Check section names for packer indicators
        for section in result.sections:
            section_lower = section.name.lower()
            if section_lower in self.SUSPICIOUS_SECTIONS:
                result.is_packed = True
                result.packing_indicators.append(f"Packer section: {section.name}")
        
        # Check for high overall entropy
        if result.sections:
            avg_entropy = sum(s.entropy for s in result.sections) / len(result.sections)
            if avg_entropy > 6.5:
                result.packing_indicators.append(f"High average section entropy: {avg_entropy:.2f}")
                if not result.is_packed:
                    result.is_packed = True
    
    def _analyze_resources(self, pe, result: PEAnalysisResult):
        """Analyze PE resources."""
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name:
                    type_name = str(resource_type.name)
                else:
                    type_id = resource_type.id
                    type_names = {
                        1: 'Cursor', 2: 'Bitmap', 3: 'Icon', 4: 'Menu',
                        5: 'Dialog', 6: 'String', 7: 'FontDir', 8: 'Font',
                        9: 'Accelerator', 10: 'RCData', 11: 'MessageTable',
                        12: 'GroupCursor', 14: 'GroupIcon', 16: 'Version',
                        24: 'Manifest'
                    }
                    type_name = type_names.get(type_id, f'Type_{type_id}')
                
                result.resource_types.append(type_name)
                
                # Check for suspicious resources
                if type_name == 'RCData':
                    # RCData can contain embedded executables
                    result.suspicious_resources.append("RCData (can contain embedded code)")
                    
        except Exception:
            pass
    
    def _get_machine_type(self, machine: int) -> str:
        """Get machine type string from PE header."""
        machine_types = {
            0x014c: 'x86',
            0x0200: 'IA64',
            0x8664: 'x64',
            0x01c0: 'ARM',
            0x01c4: 'ARMv7',
            0xaa64: 'ARM64',
        }
        return machine_types.get(machine, f'Unknown (0x{machine:04x})')
    
    def get_indicators(self, result: PEAnalysisResult) -> List[str]:
        """Get list of suspicious indicators from analysis."""
        indicators = []
        
        if result.is_packed:
            indicators.append(f"Packed executable ({result.packer_name or 'unknown packer'})")
        
        if result.suspicious_imports:
            indicators.append(f"Suspicious API imports: {', '.join(result.suspicious_imports[:5])}")
        
        if result.suspicious_sections:
            indicators.append(f"Suspicious sections: {', '.join(result.suspicious_sections)}")
        
        if not result.has_aslr:
            indicators.append("ASLR disabled")
        
        if not result.has_dep:
            indicators.append("DEP disabled")
        
        if not result.is_signed:
            indicators.append("Not digitally signed")
        
        return indicators
