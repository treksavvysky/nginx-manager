# NGINX Manager API Dockerfile
FROM python:3.14-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/api" \
    API_PORT=8000

# Set work directory  
WORKDIR /app/api

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code  
COPY api/ ./

# Create directory for logs and backups
RUN mkdir -p /var/log/nginx-manager /var/backups/nginx

# Expose port (actual port set via API_PORT env var)
EXPOSE ${API_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${API_PORT}/health || exit 1

# Run the application (shell form to expand env var)
CMD uvicorn main:app --host 0.0.0.0 --port ${API_PORT}
