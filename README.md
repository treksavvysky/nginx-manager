# NGINX Manager API

> A modular, AI-agent-first API for managing NGINX configurations, SSL certificates, and reverse proxy setups on VPS environments.

## 🎯 Project Vision

This project aims to create an intelligent NGINX management system that serves as an operational assistant, automating the tedious aspects of web server management while maintaining the flexibility for manual configuration when needed.

**Primary User**: AI agents (Custom GPTs, Claude with MCP) that can perform actions via REST API endpoints.

## 🏗️ Architecture Philosophy

- **API-First Design**: FastAPI backend with clean REST endpoints
- **Modular Components**: Each feature as an independent, testable module
- **Gradual Development**: Continuous iteration rather than all-at-once approach
- **Docker Native**: Built for containerized NGINX deployments
- **Safety First**: Config validation, backups, and rollback capabilities

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
│   │   ├── config_manager/     # NGINX config operations
│   │   ├── ssl_manager/        # SSL certificate lifecycle
│   │   └── proxy_manager/      # Reverse proxy management
│   ├── endpoints/         # REST API routes
│   ├── models/           # Pydantic data models
│   └── utils/            # Shared utilities
├── docker/               # Docker configurations
│   ├── nginx/           # NGINX container setup
│   └── compose/         # Docker Compose files
├── tests/               # Test suites
├── docs/                # API documentation
└── scripts/             # Deployment and utility scripts
```

## 🚀 Development Approach

### Current Phase: Playground VPS Setup
- **Target**: Fresh VPS environment for safe experimentation
- **Goal**: Establish best practices and error-free deployment patterns
- **Strategy**: Build, break, learn, improve

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
- Docker and Docker Compose
- Python 3.8+
- VPS with root access

### Development Setup
```bash
# Clone and setup
git clone <repository>
cd nginx-manager
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start development environment
docker-compose -f docker/compose/dev.yml up -d
```
## 🎯 API Endpoints (Planned)

### Configuration Management
```
GET    /sites/              # List all server blocks
GET    /sites/{name}         # Get specific site config
POST   /sites/              # Create new site
PUT    /sites/{name}         # Update existing site
DELETE /sites/{name}         # Remove site
POST   /sites/{name}/test    # Test config without deploying
```

### SSL Management
```
GET    /ssl/certificates     # List all certificates with expiry
GET    /ssl/status          # SSL health overview
POST   /ssl/renew/{domain}  # Force certificate renewal
GET    /ssl/alerts          # Certificates needing attention
POST   /ssl/setup/{domain}  # Initial SSL setup for domain
```

### NGINX Operations
```
POST   /nginx/reload        # Test and reload configuration
GET    /nginx/status        # NGINX service status
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
- **Rollback Capability**: Quick restoration to last known good config
- **Dry Run Mode**: Test changes without applying them
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