#!/bin/bash
# Development deployment script

set -e

echo "🚀 Starting NGINX Manager in development mode..."

# Change to project root
cd "$(dirname "$0")/.."

# Load API_PORT from .env (default 8000)
API_PORT=${API_PORT:-$(grep -E '^API_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 8000)}

# Stop existing containers
echo "📦 Stopping existing containers..."
docker compose -f docker/compose/dev.yml --env-file .env down

# Build and start services
echo "🔨 Building and starting services..."
docker compose -f docker/compose/dev.yml --env-file .env up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Health checks
echo "🔍 Checking service health..."

# Check API health
if curl -f http://localhost:${API_PORT}/health > /dev/null 2>&1; then
    echo "✅ API is healthy"
else
    echo "❌ API health check failed"
    exit 1
fi

# Check NGINX health
if curl -f http://localhost/health > /dev/null 2>&1; then
    echo "✅ NGINX is healthy"
else
    echo "❌ NGINX health check failed"
    exit 1
fi

echo ""
echo "🎉 NGINX Manager is running!"
echo ""
echo "📊 Services:"
echo "  - API:          http://localhost:${API_PORT}"
echo "  - API Docs:     http://localhost:${API_PORT}/docs"
echo "  - Dashboard:    http://localhost:${API_PORT}/dashboard/"
echo "  - NGINX:        http://localhost"
echo "  - NGINX Health: http://localhost/health"
echo ""
echo "📝 Useful commands:"
echo "  - View logs:    docker compose -f docker/compose/dev.yml --env-file .env logs -f"
echo "  - Stop:         docker compose -f docker/compose/dev.yml --env-file .env down"
echo "  - Restart:      ./scripts/dev-deploy.sh"
echo ""
