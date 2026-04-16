# ─── Stage 1: build/install deps ─────────────────────────────────────────────
FROM python:3.11-slim AS base

LABEL maintainer="you@example.com"
LABEL description="VIPER – Python Network Intrusion Detection System"

# System deps needed by Scapy for raw-socket capture
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        iproute2 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Stage 2: copy application ───────────────────────────────────────────────
COPY . .

# Create runtime directories
RUN mkdir -p logs reports captures

# ─── Runtime ─────────────────────────────────────────────────────────────────
# NET_ADMIN + NET_RAW capabilities allow Scapy to open raw sockets without root
# Pass these with:  docker run --cap-add NET_ADMIN --cap-add NET_RAW ...

EXPOSE 5000

# Default: start the NIDS on eth0 (override via --interface flag)
ENTRYPOINT ["python", "main.py"]
CMD ["--interface", "eth0"]
