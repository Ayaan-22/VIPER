# Official multi-platform Python image, resolved from Docker Hub on 2026-11-01.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${PYTHON_IMAGE} AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /build
COPY requirements-runtime.lock ./
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements-runtime.lock

FROM ${PYTHON_IMAGE} AS runner
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app MPLCONFIGDIR=/tmp/matplotlib
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin viperuser
COPY --from=builder /install /usr/local
# Explicit allow-list: private configuration and runtime evidence cannot be copied.
COPY main.py ./
COPY src ./src
COPY dashboard ./dashboard
COPY tools/healthcheck.py ./tools/healthcheck.py
COPY config/config.example.yaml ./config/config.example.yaml
RUN mkdir -p logs reports captures && chown -R viperuser:viperuser reports
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "tools/healthcheck.py", "--log", "logs/nids.log"]
ENTRYPOINT ["python", "main.py"]
CMD ["--interface", "eth0"]
