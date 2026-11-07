# ==============================================================================
# VulnScanner — Industry-Grade Production Dockerfile
# ==============================================================================
FROM python:3.12-slim AS runner

# Set environment variables for clean container execution
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install necessary runtime dependencies (libpcap for raw socket / SYN scan support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application files
COPY . .

# Setup non-privileged security user and output directory
RUN useradd -m -u 1000 scanneruser && \
    mkdir -p /app/output && \
    chown -R scanneruser:scanneruser /app

USER scanneruser

# Expose output directory as volume for reports
VOLUME ["/app/output"]

# Default entrypoint
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

