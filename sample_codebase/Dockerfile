FROM ubuntu:18.04
RUN apt-get update && apt-get install -y openssl

# Insecure TLS configuration
ENV SSL_PROTOCOL="TLSv1.0"
# This will be flagged by SQAN
