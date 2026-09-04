import os
import re

class CryptoScanner:
    def __init__(self):
        # Cryptographic Rule Dictionary based on standard specs
        self.rules = {
            'RSA': {'pattern': r'(RSA\.generate|generate_private_key|RSA_generate_key)', 'type': 'Asymmetric Key Exchange'},
            'ECC': {'pattern': r'(ECC\.generate|EllipticCurve|ECDSA|EC_KEY_new|getInstance\("EC"\))', 'type': 'Asymmetric Key Exchange'},
            'DH': {'pattern': r'(DH_generate_parameters|DiffieHellman)', 'type': 'Asymmetric Key Exchange'},
            'AES-256': {'pattern': r'(AES\.new.*256|AES\.MODE_GCM|AES-256-GCM)', 'type': 'Symmetric Cipher'},
            'AES-128': {'pattern': r'(AES\.new.*128|AES-128)', 'type': 'Symmetric Cipher'},
            'DES': {'pattern': r'(DES_cblock|DES_set_key)', 'type': 'Symmetric Cipher'},
            'MD5': {'pattern': r'(md5\(|MD5)', 'type': 'Hash Function'},
            'SHA-1': {'pattern': r'(sha1\(|SHA-1|SHA1)', 'type': 'Hash Function'},
            'TLS 1.0': {'pattern': r'TLSv1\.0', 'type': 'Protocol'}
        }
        
    def scan_directory(self, target_dir):
        findings = []
        valid_exts = ['.py', '.java', '.c', '.cpp', '.go', '.js']
        
        for root, _, files in os.walk(target_dir):
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in valid_exts or file == 'Dockerfile':
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path))
        return findings

    def scan_file(self, file_path):
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            in_block_comment = False
            for i, line in enumerate(lines):
                # Basic context guard for comments
                stripped = line.strip()
                if stripped.startswith('/*'): in_block_comment = True
                if in_block_comment and '*/' in stripped: 
                    in_block_comment = False
                    continue
                if in_block_comment or stripped.startswith('//') or stripped.startswith('#'):
                    continue
                    
                for artefact, rule in self.rules.items():
                    if re.search(rule['pattern'], line, re.IGNORECASE):
                        findings.append({
                            "file_path": file_path,
                            "line_number": i + 1,
                            "raw_code": line.strip(),
                            "artefact": artefact,
                            "type": rule['type'],
                            "key_length": "Variable" # Simplified for this demo
                        })
        except Exception as e:
            pass # Ignore unreadable files in prototype
        return findings
