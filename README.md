# NGINX Manager API

> A modular, AI-agent-first API for managing NGINX configurations, SSL certificates, and reverse proxy setups on VPS environments.

## 🎯 Project Vision

This project aims to create an intelligent NGINX management system that serves as an operational assistant, automating the tedious aspects of web server management while maintaining the flexibility for manual configuration when needed.

**Primary User**: AI agents (Custom GPTs, Claude with MCP) that can perform actions via REST API endpoints.

## 🏗️ Architecture Philosophy

- **API-First Design**: FastAPI backend with clean REST endpoints
- **AI-Native Responses**: Rich context in every response (locations, upstreams, SSL details)
- **Modular Components**: Each feature as an independent, testable module
- **Gradual Development**: Continuous iteration rather than all-at-once approach
- **Docker Native**: Built for containerized NGINX deployments
- **Safety First**: Config validation, backups, and rollback capabilities

## 🔍 Parser Capabilities

The API uses [crossplane](https://github.com/nginxinc/crossplane) for reliable NGINX config parsing:

- **Full directive support**: server blocks, location blocks, upstreams
- **Nested block parsing**: location modifiers (=, ~, ~*, ^~), nested directives
- **SSL configuration**: certificate paths, protocols, ciphers
- **Rich metadata**: line numbers for error reporting, header extraction
- **Backward compatible**: legacy flat fields + optional rich fields in responses

## 🎯 Initial Feature Focus

### Phase 1: Core Foundation
1. **Configuration Management**
   - Server block creation and editing
   - Config validation and testing
   - Safe deployment with rollback

2. **SSL Certificate Lifecycle**
   - Let's Encrypt integration
   - Automated renewal with alerts
   - Expiry monitoring and notifications

3. **Reverse Proxy Management**
   - Upstream server configuration
   - Health checking and failover
   - Load balancer setup (future)
## 📁 Project Structure

```
nginx-manager/
├── api/                    # FastAPI application
│   ├── core/              # Core business logic
│   │   └── config_manager/     # NGINX config parsing (crossplane-based)
│   ├── endpoints/         # REST API routes
│   └── models/           # Pydantic data models (nginx.py, config.py)
├── docker/               # Docker configurations
│   ├── api/             # API container Dockerfile
│   ├── nginx/           # NGINX container setup
│   └── compose/         # Docker Compose files (dev.yml, prod.yml)
├── tests/               # Test suites
│   ├── unit/            # Unit tests (parser, adapter)
│   └── fixtures/        # Test NGINX config files
├── docs/                # API documentation
└── scripts/             # Deployment and utility scripts
```

## 🚀 Development Approach

### Current Phase: AI-Native Core (Phase 2)
- **Completed**: Parser upgrade (crossplane), NGINX control endpoints, Transaction & Event model, Site CRUD, Dry-run mode, Auto-rollback
- **In Progress**: Rich context responses, MCP interface design
- **Next Phase**: SSL management (Phase 3)
- **Strategy**: Build foundational AI-agent patterns before adding features

### Key Design Decisions
- **Config Storage**: Hybrid approach - files as source of truth, database for metadata
- **NGINX Interaction**: Direct file manipulation + Docker container reload
- **Validation**: `nginx -t` testing before any config deployment
- **Safety**: Automatic backups before any configuration changes

## 🔧 Technology Stack

- **Backend**: FastAPI (Python)
- **Container**: Docker + Docker Compose
- **SSL**: Let's Encrypt (certbot integration)
- **Config**: NGINX file-based configuration
- **Database**: SQLite for metadata (simple start)
- **Validation**: NGINX built-in config testing

## 🎪 Getting Started

### Prerequisites
- Docker 28.x+ and Docker Compose 2.38+
- Python 3.12+ (for local development without Docker)
- VPS with root access (for production deployment)

### Development Setup
```bash
# Clone the repository
git clone <repository>
cd nginx-manager

# Start development environment (recommended)
./scripts/dev-deploy.sh

# Verify services are running
curl http://localhost:8000/health
curl http://localhost/health

# View logs
docker compose -f docker/compose/dev.yml logs -f

# Stop services
docker compose -f docker/compose/dev.yml down
```

### Local Python Development (without Docker)
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run API locally
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
## 🎯 API Endpoints (Planned)

### Configuration Management (Implemented)
```
GET    /sites/                # List all sites (including disabled)
GET    /sites/{name}          # Get specific site config
POST   /sites/                # Create new site (static or reverse_proxy)
PUT    /sites/{name}          # Update existing site
DELETE /sites/{name}          # Remove site
POST   /sites/{name}/enable   # Enable a disabled site
POST   /sites/{name}/disable  # Disable site without deleting
```
All mutation endpoints support `?dry_run=true` to preview changes without applying them.

### SSL Management
```
GET    /ssl/certificates     # List all certificates with expiry
GET    /ssl/status          # SSL health overview
POST   /ssl/renew/{domain}  # Force certificate renewal
GET    /ssl/alerts          # Certificates needing attention
POST   /ssl/setup/{domain}  # Initial SSL setup for domain
```

### NGINX Operations (Implemented)
```
POST   /nginx/reload        # Graceful reload with health verification
POST   /nginx/restart       # Full restart with health verification
GET    /nginx/status        # Container status, uptime, health
POST   /nginx/test          # Validate config with nginx -t
```
Reload and restart support `?dry_run=true` to validate config and preview impact without executing.

### Transactions & Rollback (Implemented)
```
GET    /transactions/              # List transactions with filtering
GET    /transactions/{id}          # Get transaction details with diff
POST   /transactions/{id}/rollback # Rollback to previous state
GET    /transactions/{id}/can-rollback # Check rollback eligibility
```

### Event Audit Log (Implemented)
```
GET    /events/              # List events with filtering
GET    /events/counts        # Event counts by severity
GET    /events/{id}          # Get event details
```

### NGINX Operations (Planned)
```
POST   /nginx/backup        # Create configuration backup
POST   /nginx/restore       # Restore from backup
GET    /nginx/logs          # Access recent logs
```

### System Management
```
GET    /system/health       # Overall system health check
GET    /system/docker       # Docker container status
POST   /system/deploy       # Deploy configuration changes
```

## 🛡️ Safety Features

- **Config Validation**: Every change tested with `nginx -t` before deployment
- **Automatic Backups**: Configuration backed up before any modification
- **Transaction System**: All changes wrapped in transactions with full audit trail
- **Rollback Capability**: Quick restoration to any previous configuration state
- **Auto-Rollback**: Configuration automatically restored if health check fails after reload
- **Dry Run Mode**: Preview any operation with `?dry_run=true` - see generated configs, diffs, and validation results
- **Health Checks**: Monitor NGINX and upstream services
- **Alert System**: Proactive notifications for SSL expiry, errors, etc.

## 📈 Future Enhancements

- **Multi-Server Management**: Manage multiple VPS instances
- **Load Balancing**: Advanced upstream configuration
- **Monitoring Dashboard**: Web interface for visual management
- **Custom GPT Integration**: Specialized AI assistant interface
- **MCP Server**: Native Claude integration capabilities
- **Domain Monitoring**: Track domain name expiry dates
- **Security Scanning**: Configuration security best practices

## 🤝 Contributing

This project follows a modular development approach. Each component should be:
- **Independently testable**
- **Well documented**
- **Safe by default**
- **AI-agent friendly**

---

*Built with ❤️ for automated infrastructure management*