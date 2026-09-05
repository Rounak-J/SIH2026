FROM ubuntu:18.04
RUN apt-get update && apt-get install -y libssl1.0.0
COPY . /app
CMD ["python3", "/app/legacy_crypto.py"]