"""
Unit tests for NGINX configuration generator.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.config_generator import ConfigGenerator, ConfigGeneratorError, get_config_generator
from core.config_generator.generator import TemplateNotFoundError
from models.site_requests import SiteCreateRequest, SiteType


class TestConfigGenerator:
    """Tests for ConfigGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a ConfigGenerator instance."""
        return ConfigGenerator()

    def test_init_with_default_template_dir(self, generator):
        """Test initialization with default template directory."""
        assert generator.template_dir.exists()
        assert generator.env is not None

    def test_init_with_invalid_template_dir(self):
        """Test initialization fails with invalid template directory."""
        with pytest.raises(ConfigGeneratorError) as exc_info:
            ConfigGenerator(template_dir=Path("/nonexistent/path"))
        assert "Template directory not found" in str(exc_info.value)

    def test_generate_static_site(self, generator):
        """Test generating a static site configuration."""
        request = SiteCreateRequest(
            name="example.com",
            server_names=["example.com", "www.example.com"],
            site_type=SiteType.STATIC,
            listen_port=80,
            root_path="/var/www/example",
            index_files=["index.html", "index.htm"]
        )

        config = generator.generate(request)

        assert "listen 80;" in config
        assert "server_name example.com www.example.com;" in config
        assert "root /var/www/example;" in config
        assert "index index.html index.htm;" in config
        assert "try_files $uri $uri/ =404;" in config

    def test_generate_reverse_proxy(self, generator):
        """Test generating a reverse proxy configuration."""
        request = SiteCreateRequest(
            name="api.example.com",
            server_names=["api.example.com"],
            site_type=SiteType.REVERSE_PROXY,
            listen_port=80,
            proxy_pass="http://localhost:3000"
        )

        config = generator.generate(request)

        assert "listen 80;" in config
        assert "server_name api.example.com;" in config
        assert "proxy_pass http://localhost:3000;" in config
        assert "proxy_set_header Host $host;" in config
        assert "proxy_set_header X-Real-IP $remote_addr;" in config
        assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" in config
        assert "proxy_set_header X-Forwarded-Proto $scheme;" in config

    def test_generate_static_site_custom_port(self, generator):
        """Test static site with custom port."""
        request = SiteCreateRequest(
            name="dev.example.com",
            server_names=["dev.example.com"],
            site_type=SiteType.STATIC,
            listen_port=8080,
            root_path="/var/www/dev"
        )

        config = generator.generate(request)

        assert "listen 8080;" in config

    def test_generate_reverse_proxy_different_backend(self, generator):
        """Test reverse proxy with different backend URL."""
        request = SiteCreateRequest(
            name="app.example.com",
            server_names=["app.example.com"],
            site_type=SiteType.REVERSE_PROXY,
            listen_port=443,
            proxy_pass="http://backend:8080"
        )

        config = generator.generate(request)

        assert "listen 443;" in config
        assert "proxy_pass http://backend:8080;" in config

    def test_generate_multiple_server_names(self, generator):
        """Test configuration with multiple server names."""
        request = SiteCreateRequest(
            name="multi.example.com",
            server_names=["multi.example.com", "alias1.com", "alias2.com"],
            site_type=SiteType.STATIC,
            listen_port=80,
            root_path="/var/www/multi"
        )

        config = generator.generate(request)

        assert "server_name multi.example.com alias1.com alias2.com;" in config

    def test_validate_template_exists(self, generator):
        """Test template validation for existing templates."""
        assert generator.validate_template("static_site.conf.j2") is True
        assert generator.validate_template("reverse_proxy.conf.j2") is True

    def test_validate_template_not_found(self, generator):
        """Test template validation for non-existent templates."""
        assert generator.validate_template("nonexistent.conf.j2") is False


class TestGetConfigGenerator:
    """Tests for get_config_generator singleton function."""

    def test_returns_config_generator(self):
        """Test that get_config_generator returns a ConfigGenerator instance."""
        generator = get_config_generator()
        assert isinstance(generator, ConfigGenerator)

    def test_returns_same_instance(self):
        """Test that get_config_generator returns the same singleton instance."""
        generator1 = get_config_generator()
        generator2 = get_config_generator()
        assert generator1 is generator2


class TestConfigGeneratorError:
    """Tests for ConfigGeneratorError exceptions."""

    def test_error_with_message(self):
        """Test creating error with message only."""
        error = ConfigGeneratorError("Test error message")
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.site_name is None

    def test_error_with_site_name(self):
        """Test creating error with site name."""
        error = ConfigGeneratorError("Test error", site_name="example.com")
        assert error.message == "Test error"
        assert error.site_name == "example.com"

    def test_template_not_found_error(self):
        """Test TemplateNotFoundError is a subclass of ConfigGeneratorError."""
        error = TemplateNotFoundError("Template missing", site_name="test.com")
        assert isinstance(error, ConfigGeneratorError)
        assert error.site_name == "test.com"
