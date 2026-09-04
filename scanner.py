# scanner.py
import re
import os

# Knowledge base: algorithm, quantum risk level, and NIST replacement
CRYPTO_RULES = {
    "RSA": {
        "pattern": r"(RSA\.generate|from.*RSA|import.*rsa)",
        "type": "Asymmetric Key",
        "quantum_risk": "High",
        "recommendation": "Migrate to ML-KEM-768 (NIST FIPS 203)"
    },
    "AES-256": {
        "pattern": r"(AES\.new.*MODE|AES)",
        "type": "Symmetric Cipher",
        "quantum_risk": "Safe",
        "recommendation": "Retain AES-256 (Quantum-Resistant)"
    },
    "ECC": {
        "pattern": r"(ECC\.generate|EllipticCurve|ECDSA)",
        "type": "Digital Signature",
        "quantum_risk": "High",
        "recommendation": "Migrate to ML-DSA-65 (NIST FIPS 204)"
    },
    "MD5": {
        "pattern": r"(hashlib\.md5|md5)",
        "type": "Hash Function",
        "quantum_risk": "Critical",
        "recommendation": "Deprecate immediately"
    }
}

def scan_directory(target_dir):
    findings = []
    
    # Gracefully handle invalid directories
    if not os.path.exists(target_dir):
        return findings

    for root, _, files in os.walk(target_dir):
        for file in files:
            # Scan common source code files
            if file.endswith((".py", ".java", ".c", ".cpp", ".go", ".js")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            for algo, details in CRYPTO_RULES.items():
                                if re.search(details["pattern"], line, re.IGNORECASE):
                                    findings.append({
                                        "FILE PATH": f"{file} (Line {line_num})",
                                        "ARTEFACT": algo,
                                        "TYPE": details["type"],
                                        "RISK LEVEL": details["quantum_risk"],
                                        "REMEDIATION STRATEGY": details["recommendation"]
                                    })
                except Exception:
                    pass # Skip unreadable files
                    
    return findings
import os
import re

# ==========================================================
# STEPS 4 & 6: THREAT & NIST PQC KNOWLEDGE BASE (LOOKUP TABLE)
# ==========================================================
CRYPTO_KNOWLEDGE_BASE = {
    "RSA": {
        "pattern": r"(RSA\.generate|from.*RSA|import.*rsa|generate_private_key.*rsa)",
        "primitive_type": "Asymmetric Key Exchange / Encryption",
        "threat_vector": "Shor's Algorithm (Integer Factorization)",
        "quantum_risk": "🔴 Critical Risk",
        "pqc_standard": "NIST FIPS 203 (ML-KEM-768 / Kyber)"
    },
    "ECC": {
        "pattern": r"(ECC\.generate|EllipticCurve|ECDSA|SECP256R1)",
        "primitive_type": "Asymmetric Digital Signature",
        "threat_vector": "Shor's Algorithm (Discrete Logarithm)",
        "quantum_risk": "🔴 Critical Risk",
        "pqc_standard": "NIST FIPS 204 (ML-DSA-65 / Dilithium)"
    },
    "AES": {
        "pattern": r"(AES\.new|Cipher.*AES)",
        "primitive_type": "Symmetric Cipher",
        "threat_vector": "Grover's Algorithm (Quadratic Search)",
        "quantum_risk": "🟢 Quantum-Safe (if key >= 256-bit)",
        "pqc_standard": "Retain AES-256-GCM"
    }
}

# ==========================================================
# STEP 5: MOSCA'S THEOREM ENGINE
# ==========================================================
def calculate_mosca(shelf_life_x=10, migration_time_y=3, quantum_horizon_z=7):
    """Evaluates (X + Y) > Z condition."""
    is_danger = (shelf_life_x + migration_time_y) > quantum_horizon_z
    return "🚨 CRITICAL DANGER ZONE" if is_danger else "✅ SAFE WINDOW"

# ==========================================================
# STEPS 1, 2, 3: DETECTION & METADATA EXTRACTION
# ==========================================================
def scan_directory(target_path, x=10, y=3, z=7):
    cbom_records = []
    mosca_status = calculate_mosca(x, y, z)

    for root, _, files in os.walk(target_path):
        for file in files:
            if file.endswith((".py", ".java", ".c", ".cpp", ".js")):
                full_path = os.path.join(root, file)
                
                with open(full_path, "r", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        clean_line = line.strip()

                        # Step 2: AST / False-Positive Guard (Ignore comments)
                        if clean_line.startswith(("#", "//", "/*", "*")):
                            continue

                        # Step 1 & 3: Regex Match & Metadata Extraction
                        for algo_name, rules in CRYPTO_KNOWLEDGE_BASE.items():
                            if re.search(rules["pattern"], clean_line, re.IGNORECASE):
                                cbom_records.append({
                                    "File": file,
                                    "Line": line_num,
                                    "Detected Primitive": algo_name,
                                    "Primitive Type": rules["primitive_type"],
                                    "Threat Vector": rules["threat_vector"],
                                    "Quantum Risk": rules["quantum_risk"],
                                    "Mosca Status": mosca_status,
                                    "PQC Recommendation": rules["pqc_standard"]
                                })
    return cbom_records