#!/bin/bash
# Development deployment script

set -e

echo "🚀 Starting NGINX Manager in development mode..."

# Change to project root
cd "$(dirname "$0")/.."

# Stop existing containers
echo "📦 Stopping existing containers..."
docker compose -f docker/compose/dev.yml down

# Build and start services
echo "🔨 Building and starting services..."
docker compose -f docker/compose/dev.yml up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Health checks
echo "🔍 Checking service health..."

# Check API health
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
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
echo "  - API:          http://localhost:8000"
echo "  - API Docs:     http://localhost:8000/docs"
echo "  - NGINX:        http://localhost"
echo "  - NGINX Health: http://localhost/health"
echo ""
echo "📝 Useful commands:"
echo "  - View logs:    docker compose -f docker/compose/dev.yml logs -f"
echo "  - Stop:         docker compose -f docker/compose/dev.yml down"
echo "  - Restart:      ./scripts/dev-deploy.sh"
echo ""
