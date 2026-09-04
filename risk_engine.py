def evaluate_finding(artefact):
    """Threat Classification and NIST PQC Remediation Auto-Fix Engine"""
    mapping = {
        'RSA': {'risk': 'Critical', 'remediation': 'Migrate to ML-KEM-768 (NIST FIPS 203)'},
        'ECC': {'risk': 'Critical', 'remediation': 'Migrate to ML-DSA-65 (NIST FIPS 204)'},
        'DH': {'risk': 'High', 'remediation': 'Migrate to ML-KEM-768 (NIST FIPS 203)'},
        'AES-256': {'risk': 'Safe', 'remediation': 'Retain AES-256-GCM (Quantum-Resistant)'},
        'AES-128': {'risk': 'High', 'remediation': 'Upgrade to AES-256-GCM'},
        'DES': {'risk': 'Critical', 'remediation': 'Deprecate immediately, upgrade to AES-256-GCM'},
        'MD5': {'risk': 'Critical', 'remediation': 'Deprecate immediately, use SHA-256 / SHA-3'},
        'SHA-1': {'risk': 'High', 'remediation': 'Deprecate immediately, use SHA-256 / SHA-3'},
        'TLS 1.0': {'risk': 'Critical', 'remediation': 'Upgrade to TLS 1.3'}
    }
    return mapping.get(artefact, {'risk': 'Medium', 'remediation': 'Manual Review Required'})

def evaluate_mosca(x, y, z):
    """
    Mosca's Theorem Evaluation:
    If (X + Y) > Z, status = CRITICAL DANGER ZONE
    """
    exposure = max(0, (x + y) - z)
    is_danger = (x + y) > z
    return is_danger, exposure
