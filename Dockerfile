FROM python:3.11-slim

LABEL maintainer="AntiSyntax.protocol CREW"
LABEL description="GRAVITAS — Inference-Based Reconnaissance & Predictive Intelligence Platform"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/

# Install
RUN pip install --no-cache-dir -e .

# Default command
CMD ["python", "-m", "gravitas", "status"]
