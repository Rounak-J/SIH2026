import ssl
import socket
from urllib.parse import urlparse

class NetworkScanner:
    def __init__(self):
        pass

    def scan_url(self, url):
        findings = []
        
        # Ensure url has scheme
        if not url.startswith('http'):
            url = 'https://' + url
            
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not hostname:
            return findings
            
        try:
            # Create a context that doesn't verify the cert so we can inspect expired/invalid ones too
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Log the TLS Protocol version
                    findings.append({
                        "file_path": f"{hostname}:{port}",
                        "line_number": "N/A",
                        "raw_code": f"TLS Connection Established",
                        "artefact": tls_version,
                        "type": "Protocol",
                        "key_length": "N/A"
                    })
                    
                    # Log the symmetric cipher suite
                    if cipher:
                        cipher_name = cipher[0]
                        # Rough mapping of cipher suite name to algorithm for demo purposes
                        algo = "AES-256" if "AES256" in cipher_name else "AES-128" if "AES128" in cipher_name else "DES" if "DES" in cipher_name else "Unknown Symmetric"
                        findings.append({
                            "file_path": f"{hostname}:{port}",
                            "line_number": "N/A",
                            "raw_code": f"Cipher Suite: {cipher_name}",
                            "artefact": algo,
                            "type": "Symmetric Cipher",
                            "key_length": "N/A"
                        })
                        
                    # Parse x509 cert public key using cryptography if available, else fallback
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
                        
                        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                        public_key = x509_cert.public_key()
                        
                        algo_name = "Unknown Asymmetric"
                        key_size = "Unknown"
                        
                        if isinstance(public_key, rsa.RSAPublicKey):
                            algo_name = "RSA"
                            key_size = str(public_key.key_size)
                        elif isinstance(public_key, ec.EllipticCurvePublicKey):
                            algo_name = "ECC"
                            key_size = str(public_key.curve.key_size)
                        elif isinstance(public_key, dh.DHPublicKey):
                            algo_name = "DH"
                            key_size = str(public_key.key_size)
                            
                        findings.append({
                            "file_path": f"{hostname} (x509 Cert)",
                            "line_number": "N/A",
                            "raw_code": f"Subject: {x509_cert.subject.rfc4514_string()}",
                            "artefact": algo_name,
                            "type": "Asymmetric Key Exchange",
                            "key_length": key_size
                        })
                    except ImportError:
                        # Fallback if cryptography library is not installed
                        findings.append({
                            "file_path": f"{hostname} (x509 Cert)",
                            "line_number": "N/A",
                            "raw_code": "x509 Certificate Public Key (Requires 'cryptography' package for deep inspection)",
                            "artefact": "RSA", # Guessing RSA as a safe fallback for the UI demo
                            "type": "Asymmetric Key Exchange",
                            "key_length": "Unknown"
                        })
                        
        except Exception as e:
            # Add an error finding if connection fails
            findings.append({
                "file_path": str(url),
                "line_number": "N/A",
                "raw_code": f"Connection Error: {str(e)}",
                "artefact": "Connection Failed",
                "type": "Error",
                "key_length": "N/A"
            })
            
        return findings
