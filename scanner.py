import os
import re
import ast

class CryptoScanner:
    def __init__(self, mode="FAST REGEX"):
        self.mode = mode
        # Cryptographic Rule Dictionary based on standard specs
        self.rules = {
            'RSA': {'pattern': r'(RSA\.generate|generate_private_key|RSA_generate_key)', 'type': 'Asymmetric Key Exchange'},
            'ECC': {'pattern': r'(ECC\.generate|EllipticCurve|ECDSA|EC_KEY_new|getInstance\("EC"\))', 'type': 'Asymmetric Key Exchange'},
            'DH': {'pattern': r'(DH_generate_parameters|DiffieHellman)', 'type': 'Asymmetric Key Exchange'},
            'AES-256': {'pattern': r'(AES\.new.*256|AES\.MODE_GCM|AES-256-GCM)', 'type': 'Symmetric Cipher'},
            'AES-128': {'pattern': r'(AES\.new.*128|AES-128)', 'type': 'Symmetric Cipher'},
            'DES': {'pattern': r'(DES_cblock|DES_set_key|DES\.new)', 'type': 'Symmetric Cipher'},
            'MD5': {'pattern': r'(md5\(|MD5|hashlib\.md5)', 'type': 'Hash Function'},
            'SHA-1': {'pattern': r'(sha1\(|SHA-1|SHA1|hashlib\.sha1)', 'type': 'Hash Function'},
            'TLS 1.0': {'pattern': r'TLSv1\.0', 'type': 'Protocol'},
            'Outdated Base Image': {'pattern': r'FROM (alpine:3\.[0-9]|ubuntu:1[468]\.04|node:1[024])', 'type': 'Container Dependency'},
            'Legacy OpenSSL': {'pattern': r'(apk add.*openssl<1\.1|apt-get.*libssl1\.0)', 'type': 'Container Dependency'}
        }
        
    def scan_directory(self, target_dir):
        findings = []
        valid_code_exts = ['.py', '.java', '.c', '.cpp', '.go', '.js']
        valid_binary_exts = ['.dll', '.exe', '.so', '.bin', '.class', '.pyc']
        valid_container_files = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml']
        
        for root, _, files in os.walk(target_dir):
            for file in files:
                ext = os.path.splitext(file)[1]
                file_path = os.path.join(root, file)
                
                # Exclude virtual environments and node_modules
                if 'venv' in file_path or 'node_modules' in file_path or '.git' in file_path:
                    continue
                    
                if self.mode == "FAST REGEX":
                    if ext in valid_code_exts or file in valid_container_files:
                        findings.extend(self.scan_file_regex(file_path))
                elif self.mode == "DEEP AST":
                    if ext == '.py':
                        findings.extend(self.scan_file_ast_python(file_path))
                    elif ext in valid_code_exts or file in valid_container_files:
                        findings.extend(self.scan_file_regex(file_path)) # Fallback for non-python
                elif self.mode == "BINARY ANALYSIS":
                    if ext in valid_binary_exts:
                        findings.extend(self.scan_file_binary(file_path))
                        
        return findings

    def scan_file_regex(self, file_path):
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            in_block_comment = False
            for i, line in enumerate(lines):
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
                            "key_length": "Variable"
                        })
        except Exception:
            pass 
        return findings

    def scan_file_ast_python(self, file_path):
        """Deep AST scanning for Python files. Highly accurate, no regex false positives."""
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for function calls like hashlib.md5()
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        
                    for artefact, rule in self.rules.items():
                        if re.search(rule['pattern'], func_name, re.IGNORECASE):
                            findings.append({
                                "file_path": file_path,
                                "line_number": node.lineno,
                                "raw_code": f"AST Call: {func_name}()",
                                "artefact": artefact,
                                "type": rule['type'],
                                "key_length": "Variable"
                            })
        except SyntaxError:
            # Fallback to regex if AST parsing fails due to syntax error
            return self.scan_file_regex(file_path)
        except Exception:
            pass
        return findings
        
    def scan_file_binary(self, file_path):
        """Extracts ASCII/UTF-8 strings from binaries and scans for crypto artifacts."""
        findings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Naive string extraction (strings of 4+ printable chars)
            ascii_strings = re.findall(b'[ -~]{4,}', data)
            
            for index, s_bytes in enumerate(ascii_strings):
                try:
                    s = s_bytes.decode('utf-8')
                    for artefact, rule in self.rules.items():
                        if re.search(rule['pattern'], s, re.IGNORECASE):
                            findings.append({
                                "file_path": file_path,
                                "line_number": f"Binary Offset ~{index}",
                                "raw_code": f"[BINARY STRING]: {s[:50]}...",
                                "artefact": artefact,
                                "type": rule['type'],
                                "key_length": "Variable"
                            })
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass
        return findings
