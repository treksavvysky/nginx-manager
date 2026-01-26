"""
Unit tests for the crossplane-based NGINX configuration parser.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from core.config_manager.crossplane_parser import CrossplaneParser
from core.config_manager.adapter import ConfigAdapter


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nginx_configs"


class TestCrossplaneParser:
    """Tests for CrossplaneParser class."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_parse_simple_static_site(self, parser):
        """Test parsing a simple static site configuration."""
        config_file = FIXTURES_DIR / "simple_static.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.server_blocks) == 1

        server = result.server_blocks[0]
        assert "example.com" in server.server_names
        assert "www.example.com" in server.server_names
        assert server.root == "/var/www/example"

        # Check listen directive
        assert len(server.listen) == 1
        assert server.listen[0].port == 80
        assert server.listen[0].ssl is False

        # Check location
        assert len(server.locations) == 1
        assert server.locations[0].path == "/"

    def test_parse_reverse_proxy(self, parser):
        """Test parsing a reverse proxy configuration."""
        config_file = FIXTURES_DIR / "reverse_proxy.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.server_blocks) == 1

        server = result.server_blocks[0]
        assert "api.example.com" in server.server_names

        # Check locations
        assert len(server.locations) == 2

        # Find the proxy location
        proxy_loc = next(loc for loc in server.locations if loc.path == "/")
        assert proxy_loc.proxy_pass == "http://localhost:3000"
        assert "Host" in proxy_loc.headers

        # Find the health location
        health_loc = next(loc for loc in server.locations if loc.path == "/health")
        assert health_loc.return_code == 200

    def test_parse_ssl_site(self, parser):
        """Test parsing an SSL-enabled site configuration."""
        config_file = FIXTURES_DIR / "ssl_site.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.server_blocks) == 2

        # Find the SSL server block
        ssl_server = next(s for s in result.server_blocks if s.ssl.enabled)

        assert ssl_server.ssl.certificate == "/etc/ssl/certs/secure.example.com.crt"
        assert ssl_server.ssl.certificate_key == "/etc/ssl/private/secure.example.com.key"
        assert "TLSv1.2" in ssl_server.ssl.protocols
        assert "TLSv1.3" in ssl_server.ssl.protocols

        # Check listen directive has SSL flag
        ssl_listen = next(l for l in ssl_server.listen if l.ssl)
        assert ssl_listen.port == 443
        assert ssl_listen.http2 is True

    def test_parse_load_balancer(self, parser):
        """Test parsing upstream and load balancer configuration."""
        config_file = FIXTURES_DIR / "load_balancer.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.upstreams) == 1

        upstream = result.upstreams[0]
        assert upstream.name == "backend"
        assert upstream.load_balancing == "least_conn"
        assert upstream.keepalive == 32
        assert len(upstream.servers) == 3

        # Check server weights
        weighted_server = next(s for s in upstream.servers if s.weight == 3)
        assert weighted_server.address == "127.0.0.1:8001"

        # Check backup server
        backup_server = next(s for s in upstream.servers if s.backup)
        assert backup_server.address == "127.0.0.1:8003"

    def test_parse_complex_locations(self, parser):
        """Test parsing complex location blocks with modifiers."""
        config_file = FIXTURES_DIR / "complex_locations.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.server_blocks) == 1

        server = result.server_blocks[0]

        # Check IPv6 listener
        ipv6_listen = next((l for l in server.listen if l.address), None)
        assert ipv6_listen is not None

        # Check location modifiers
        locations = {loc.path: loc for loc in server.locations}

        # Exact match
        assert "/exact" in locations
        assert locations["/exact"].modifier == "="

        # Prefix priority
        assert "/images/" in locations
        assert locations["/images/"].modifier == "^~"

        # Case-sensitive regex
        php_loc = next((l for l in server.locations if l.modifier == "~"), None)
        assert php_loc is not None

        # Case-insensitive regex
        img_loc = next((l for l in server.locations if l.modifier == "~*"), None)
        assert img_loc is not None

        # Check error pages
        assert 404 in server.error_pages
        assert 500 in server.error_pages

    def test_parse_nonexistent_file(self, parser):
        """Test that parser returns None for nonexistent files."""
        config_file = FIXTURES_DIR / "nonexistent.conf"
        result = parser.parse_config_file(config_file)

        assert result is None

    def test_file_metadata(self, parser):
        """Test that file metadata is correctly extracted."""
        config_file = FIXTURES_DIR / "simple_static.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.file_path == str(config_file)
        assert result.file_size > 0
        assert result.created_at is not None
        assert result.updated_at is not None


class TestListenDirectiveParsing:
    """Tests for listen directive parsing edge cases."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_simple_port(self, parser):
        """Test parsing simple port number."""
        listen = parser._parse_listen_directive(["80"])
        assert listen.port == 80
        assert listen.address is None
        assert listen.ssl is False

    def test_port_with_ssl(self, parser):
        """Test parsing port with SSL flag."""
        listen = parser._parse_listen_directive(["443", "ssl"])
        assert listen.port == 443
        assert listen.ssl is True

    def test_port_with_http2(self, parser):
        """Test parsing port with HTTP/2 flag."""
        listen = parser._parse_listen_directive(["443", "ssl", "http2"])
        assert listen.port == 443
        assert listen.ssl is True
        assert listen.http2 is True

    def test_ipv6_address(self, parser):
        """Test parsing IPv6 address."""
        listen = parser._parse_listen_directive(["[::]:80"])
        assert listen.port == 80
        assert listen.address == "[::]"

    def test_ipv4_with_port(self, parser):
        """Test parsing IPv4 address with port."""
        listen = parser._parse_listen_directive(["127.0.0.1:8080"])
        assert listen.port == 8080
        assert listen.address == "127.0.0.1"

    def test_default_server(self, parser):
        """Test parsing default_server flag."""
        listen = parser._parse_listen_directive(["80", "default_server"])
        assert listen.port == 80
        assert listen.default_server is True


class TestConfigAdapter:
    """Tests for ConfigAdapter class."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_to_legacy_dict_simple(self, parser):
        """Test legacy dict conversion for simple site."""
        config_file = FIXTURES_DIR / "simple_static.conf"
        parsed = parser.parse_config_file(config_file)
        legacy = ConfigAdapter.to_legacy_dict(parsed)

        assert legacy["name"] == "simple_static"
        assert "example.com" in legacy["server_name"]
        assert 80 in legacy["listen_ports"]
        assert legacy["ssl_enabled"] is False
        assert legacy["root_path"] == "/var/www/example"
        assert legacy["proxy_pass"] is None

    def test_to_legacy_dict_proxy(self, parser):
        """Test legacy dict conversion for proxy site."""
        config_file = FIXTURES_DIR / "reverse_proxy.conf"
        parsed = parser.parse_config_file(config_file)
        legacy = ConfigAdapter.to_legacy_dict(parsed)

        assert legacy["proxy_pass"] == "http://localhost:3000"
        assert legacy["root_path"] is None

    def test_to_legacy_dict_ssl(self, parser):
        """Test legacy dict conversion for SSL site."""
        config_file = FIXTURES_DIR / "ssl_site.conf"
        parsed = parser.parse_config_file(config_file)
        legacy = ConfigAdapter.to_legacy_dict(parsed)

        # First server block is the HTTP redirect
        # The adapter should still work
        assert legacy["name"] == "ssl_site"

    def test_to_rich_dict(self, parser):
        """Test rich dict conversion includes extra fields."""
        config_file = FIXTURES_DIR / "reverse_proxy.conf"
        parsed = parser.parse_config_file(config_file)
        rich = ConfigAdapter.to_rich_dict(parsed)

        # Has legacy fields
        assert "name" in rich
        assert "server_name" in rich

        # Has rich fields
        assert "server_names" in rich
        assert "locations" in rich
        assert isinstance(rich["locations"], list)
        assert len(rich["locations"]) > 0

    def test_to_rich_dict_upstreams(self, parser):
        """Test rich dict includes upstream information."""
        config_file = FIXTURES_DIR / "load_balancer.conf"
        parsed = parser.parse_config_file(config_file)
        rich = ConfigAdapter.to_rich_dict(parsed)

        assert "upstreams" in rich
        assert len(rich["upstreams"]) == 1
        assert rich["upstreams"][0]["name"] == "backend"
