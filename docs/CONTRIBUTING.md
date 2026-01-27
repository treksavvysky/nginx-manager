# Contributing to NGINX Manager

Thank you for your interest in contributing to NGINX Manager!

## Development Setup

### Prerequisites

- Docker 28.x+
- Docker Compose 2.38+
- Python 3.12+ (for local development; project targets 3.13 per `pyproject.toml`)
- Git

### Quick Start

```bash
# Clone the repository
git clone <repo-url>
cd nginx-manager

# Start development environment
./scripts/dev-deploy.sh

# Verify services are running
curl http://localhost:8000/health
curl http://localhost/health
```

### Local Python Development

For faster iteration without Docker rebuilds:

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run API locally (requires NGINX container or mock)
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Project Structure

```
nginx-manager/
├── api/                    # FastAPI application
│   ├── main.py            # App entry point
│   ├── config.py          # Settings management
│   ├── endpoints/         # Route handlers
│   ├── models/            # Pydantic schemas
│   └── core/              # Business logic
├── docker/                # Container definitions
│   ├── api/               # API Dockerfile
│   ├── nginx/             # NGINX Dockerfile
│   └── compose/           # Compose files
├── scripts/               # Deployment scripts
├── test-configs/          # Sample NGINX configs for development
├── tests/                 # Test suite (TBD - framework configured)
└── docs/                  # Documentation
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Changes

- Follow existing code style
- Add type hints to all functions
- Update documentation if needed
- Add tests for new functionality

### 3. Test Your Changes

```bash
# Run tests (when implemented)
pytest

# Test with Docker
./scripts/dev-deploy.sh
curl http://localhost:8000/sites/
```

### 4. Commit

Follow conventional commits:

```bash
git commit -m "feat: add certificate renewal endpoint"
git commit -m "fix: handle empty config files gracefully"
git commit -m "docs: update API reference for new endpoints"
```

### 5. Submit Pull Request

- Describe what changes you made and why
- Reference any related issues
- Ensure CI passes (when implemented)

## Code Style

### Python

- Use type hints for all function parameters and returns
- Follow PEP 8 with 100 character line limit
- Use `async def` for endpoint handlers
- Prefer Pydantic models over raw dicts

```python
# Good
async def get_site(site_name: str) -> SiteConfigResponse:
    """Retrieve a site configuration by name."""
    config = await config_manager.get_site(site_name)
    return SiteConfigResponse(**config)

# Avoid
def get_site(name):
    return config_manager.get_site(name)
```

### API Design

- Use RESTful conventions
- Return appropriate HTTP status codes
- Include descriptive error messages
- Document all endpoints with docstrings

### Docker

- Keep images minimal (alpine/slim bases)
- Don't run as root in production
- Use multi-stage builds when beneficial

## Testing Guidelines

### Unit Tests

Test individual functions and classes:

```python
def test_parser_extracts_server_name():
    content = "server { server_name example.com; }"
    parser = NginxConfigParser()
    result = parser.parse_config_content(content)
    assert result["server_name"] == "example.com"
```

### Integration Tests

Test API endpoints with test client:

```python
async def test_list_sites_returns_configs(client):
    response = await client.get("/sites/")
    assert response.status_code == 200
    assert "sites" in response.json()
```

### E2E Tests

Test full flow with real NGINX container:

```python
async def test_create_and_reload_site(docker_compose):
    # Create site via API
    # Verify NGINX serves the site
    # Cleanup
```

## Documentation

- Update `docs/API.md` for endpoint changes
- Update `docs/ARCHITECTURE.md` for structural changes
- Update `CLAUDE.md` for AI-relevant changes
- Add inline comments for complex logic only

## Getting Help

- Check existing issues and documentation
- Open a GitHub issue for bugs or feature requests
- Tag issues appropriately: `bug`, `enhancement`, `documentation`

## Roadmap

See [docs/ROADMAP.md](./ROADMAP.md) for planned features and current priorities.
