def evaluate_finding(artefact, compliance_mode="Standard Industry Baseline"):
    """Threat Classification and NIST PQC Remediation Auto-Fix Engine"""
    mapping = {
        'RSA': {'risk': 'Critical', 'remediation': 'Implement Hybrid Key Encapsulation (X25519 + ML-KEM-768)'},
        'ECC': {'risk': 'Critical', 'remediation': 'Implement Hybrid Key Encapsulation (X25519 + ML-KEM-768)'},
        'DH': {'risk': 'High', 'remediation': 'Implement Hybrid Key Encapsulation (X25519 + ML-KEM-768)'},
        'AES-256': {'risk': 'Safe', 'remediation': 'Retain AES-256-GCM (Quantum-Resistant)'},
        'AES-128': {'risk': 'High', 'remediation': 'Upgrade to AES-256-GCM'},
        'DES': {'risk': 'Critical', 'remediation': 'Deprecate immediately, upgrade to AES-256-GCM'},
        'MD5': {'risk': 'Critical', 'remediation': 'Deprecate immediately, use SHA-256 / SHA-3'},
        'SHA-1': {'risk': 'High', 'remediation': 'Deprecate immediately, use SHA-256 / SHA-3'},
        'TLSv1.0': {'risk': 'Critical', 'remediation': 'Upgrade to TLS 1.3'},
        'TLSv1.1': {'risk': 'Critical', 'remediation': 'Upgrade to TLS 1.3'},
        'TLSv1.2': {'risk': 'Medium', 'remediation': 'Monitor for deprecation, migrate to TLS 1.3'},
        'TLSv1.3': {'risk': 'Safe', 'remediation': 'Current Standard'},
        'Outdated Base Image': {'risk': 'Critical', 'remediation': 'Update Dockerfile base image to latest LTS'},
        'Legacy OpenSSL': {'risk': 'Critical', 'remediation': 'Update container dependencies to OpenSSL 3.x'}
    }
    
    # CNSA 2.0 (Military Grade) Strict Overrides
    if compliance_mode == "NSA CNSA 2.0 (Military Grade)":
        if artefact == 'AES-128':
            mapping['AES-128'] = {'risk': 'Critical', 'remediation': 'CNSA 2.0 Violation: Immediate upgrade to AES-256 required'}
        if artefact == 'RSA' or artefact == 'ECC':
            mapping[artefact]['remediation'] = 'CNSA 2.0 Strict: Pure ML-KEM / ML-DSA required. No Hybrid allowed.'
            
    return mapping.get(artefact, {'risk': 'High', 'remediation': 'Flagged for Manual Cryptographic Review'})

def evaluate_mosca(x, y, z):
    """
    Mosca's Theorem Evaluation:
    If (X + Y) > Z, status = CRITICAL DANGER ZONE
    """
    exposure = max(0, (x + y) - z)
    is_danger = (x + y) > z
    return is_danger, exposure
