# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

# Set build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies
RUN echo "Acquire::Check-Valid-Until \"false\";\nAcquire::Check-Date \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runner

# Metadata
LABEL maintainer="Ayaan-22"
LABEL description="VIPER – Production Network Intrusion Detection System"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:${PYTHONPATH}"

WORKDIR /app

# Install runtime dependencies only
# - libpcap0.8: required for Scapy context
# - iproute2: networking tools
# - tcpdump: packet analysis
# - procps: process monitoring for healthchecks
RUN echo "Acquire::Check-Valid-Until \"false\";\nAcquire::Check-Date \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until \
    && apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    tcpdump \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs reports captures

# Set up a non-root user (available for dashboard service)
RUN useradd -m -s /bin/bash viperuser && \
    chown -R viperuser:viperuser /app

# EXPOSE Dashboard port
EXPOSE 5000

# Healthcheck to ensure the main process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f "python" || exit 1

ENTRYPOINT ["python", "main.py"]
CMD ["--interface", "eth0"]
