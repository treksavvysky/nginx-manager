#!/bin/bash
# Production deployment script for VPS

set -e

echo "🚀 Deploying NGINX Manager to production..."

# Change to project root
cd "$(dirname "$0")/.."

# Create necessary directories
echo "📁 Creating system directories..."
sudo mkdir -p /var/log/nginx-manager
sudo mkdir -p /var/backups/nginx
sudo chown -R $USER:$USER /var/log/nginx-manager /var/backups/nginx

# Backup existing configurations
echo "💾 Backing up existing configurations..."
if [ -d "/etc/nginx/conf.d" ]; then
    sudo cp -r /etc/nginx/conf.d /var/backups/nginx/conf.d.$(date +%Y%m%d-%H%M%S)
fi

# Stop existing containers
echo "📦 Stopping existing containers..."
docker compose -f docker/compose/prod.yml down

# Build and start services
echo "🔨 Building and starting production services..."
docker compose -f docker/compose/prod.yml up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 15

# Health checks
echo "🔍 Checking service health..."

# Check API health
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ API is healthy"
else
    echo "❌ API health check failed"
    echo "📋 Checking logs..."
    docker compose -f docker/compose/prod.yml logs nginx-manager-api
    exit 1
fi

# Check NGINX health
if curl -f http://localhost/health > /dev/null 2>&1; then
    echo "✅ NGINX is healthy"
else
    echo "❌ NGINX health check failed"
    echo "📋 Checking logs..."
    docker compose -f docker/compose/prod.yml logs nginx-manager-nginx
    exit 1
fi

echo ""
echo "🎉 NGINX Manager deployed successfully!"
echo ""
echo "📊 Production Services:"
echo "  - API:          http://localhost:8000 (localhost only)"
echo "  - API Docs:     http://localhost:8000/docs"
echo "  - NGINX:        http://$(hostname -I | awk '{print $1}')"
echo ""
echo "📝 Management commands:"
echo "  - View logs:    docker compose -f docker/compose/prod.yml logs -f"
echo "  - Stop:         docker compose -f docker/compose/prod.yml down"
echo "  - Update:       git pull && ./scripts/prod-deploy.sh"
echo ""
echo "🛡️  Security notes:"
echo "  - API is only accessible from localhost"
echo "  - Configure firewall for ports 80/443"
echo "  - Set up SSL certificates with Let's Encrypt"
echo ""
