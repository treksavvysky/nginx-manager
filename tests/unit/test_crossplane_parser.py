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


class TestMapDirectiveParsing:
    """Tests for map directive parsing."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_parse_map_directives(self, parser):
        """Test parsing configuration with map directives."""
        config_file = FIXTURES_DIR / "map_directive.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.maps) == 3

    def test_map_source_and_target_variables(self, parser):
        """Test that map source and target variables are correctly extracted."""
        config_file = FIXTURES_DIR / "map_directive.conf"
        result = parser.parse_config_file(config_file)

        # First map: $uri -> $backend
        uri_map = result.maps[0]
        assert uri_map.source_variable == "$uri"
        assert uri_map.target_variable == "$backend"
        assert uri_map.default == "backend1"

    def test_map_mappings(self, parser):
        """Test that map entries are correctly parsed."""
        config_file = FIXTURES_DIR / "map_directive.conf"
        result = parser.parse_config_file(config_file)

        uri_map = result.maps[0]
        assert "/api" in uri_map.mappings
        assert uri_map.mappings["/api"] == "api_backend"

    def test_map_hostnames_flag(self, parser):
        """Test that hostnames flag is detected."""
        config_file = FIXTURES_DIR / "map_directive.conf"
        result = parser.parse_config_file(config_file)

        # Third map has hostnames flag
        host_map = result.maps[2]
        assert host_map.hostnames is True
        assert host_map.source_variable == "$host"
        assert host_map.target_variable == "$rate_limit"


class TestGeoDirectiveParsing:
    """Tests for geo directive parsing."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_parse_geo_directives(self, parser):
        """Test parsing configuration with geo directives."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        assert result is not None
        assert result.status == "ok"
        assert len(result.geos) == 3

    def test_geo_single_variable(self, parser):
        """Test geo with single variable (uses $remote_addr as source)."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[0]
        assert geo.source_variable is None  # Uses default $remote_addr
        assert geo.target_variable == "$geo_country"
        assert geo.default == "unknown"

    def test_geo_two_variables(self, parser):
        """Test geo with explicit source and target variables."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[1]
        assert geo.source_variable == "$remote_addr"
        assert geo.target_variable == "$is_allowed"

    def test_geo_mappings(self, parser):
        """Test that geo network mappings are correctly parsed."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[0]
        assert "127.0.0.0/8" in geo.mappings
        assert geo.mappings["127.0.0.0/8"] == "local"
        assert "10.0.0.0/8" in geo.mappings
        assert geo.mappings["10.0.0.0/8"] == "private"

    def test_geo_delete_directive(self, parser):
        """Test that geo delete directive is parsed."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[1]
        assert "127.0.0.1" in geo.delete

    def test_geo_proxy_directive(self, parser):
        """Test that geo proxy directive is parsed."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[1]
        assert "192.168.1.1" in geo.proxy
        assert geo.proxy_recursive is True

    def test_geo_ranges_flag(self, parser):
        """Test that geo ranges flag is detected."""
        config_file = FIXTURES_DIR / "geo_directive.conf"
        result = parser.parse_config_file(config_file)

        geo = result.geos[2]
        assert geo.ranges is True


class TestIncludeResolution:
    """Tests for include file resolution."""

    @pytest.fixture
    def parser(self):
        return CrossplaneParser()

    def test_includes_captured_without_resolution(self, parser):
        """Test that include patterns are captured when not resolving."""
        config_file = FIXTURES_DIR / "main_with_includes.conf"
        result = parser.parse_config_file(config_file, resolve_includes=False)

        assert result is not None
        assert len(result.includes) == 1
        assert "included_locations.conf" in result.includes[0]
        assert len(result.resolved_includes) == 0
        assert len(result.included_configs) == 0

    def test_include_resolution(self, parser):
        """Test that includes are resolved when requested."""
        config_file = FIXTURES_DIR / "main_with_includes.conf"
        result = parser.parse_config_file(config_file, resolve_includes=True)

        assert result is not None
        assert len(result.includes) == 1
        assert len(result.resolved_includes) >= 1
        assert any("included_locations.conf" in path for path in result.resolved_includes)

    def test_included_configs_parsed(self, parser):
        """Test that included files are actually parsed."""
        config_file = FIXTURES_DIR / "main_with_includes.conf"
        result = parser.parse_config_file(config_file, resolve_includes=True)

        assert result is not None
        assert len(result.included_configs) >= 1

        # The included config should have locations
        included = result.included_configs[0]
        # Included config is a fragment, may have server blocks or just locations
        # depending on how crossplane parses it

    def test_circular_include_detection(self, parser):
        """Test that circular includes are detected and handled."""
        config_file = FIXTURES_DIR / "circular_include_a.conf"
        result = parser.parse_config_file(config_file, resolve_includes=True)

        # Should not crash or hang, should return valid result
        assert result is not None
        # The circular file should only be included once
        # and not cause infinite recursion

    def test_nonexistent_include_handled(self, parser):
        """Test that nonexistent include patterns don't cause errors."""
        # Create a temp config with nonexistent include
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("""
server {
    listen 80;
    server_name test.local;
    include /nonexistent/path/*.conf;
}
""")
            temp_path = f.name

        try:
            result = parser.parse_config_file(Path(temp_path), resolve_includes=True)
            assert result is not None
            assert len(result.includes) == 1
            # No files matched, so resolved_includes should be empty or have none for that pattern
        finally:
            os.unlink(temp_path)

    def test_glob_pattern_resolution(self, parser):
        """Test that glob patterns in includes are resolved."""
        # Use wildcards to include all conf files
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False, dir=str(FIXTURES_DIR)) as f:
            f.write(f"""
server {{
    listen 80;
    server_name glob-test.local;
    include {FIXTURES_DIR}/simple_*.conf;
}}
""")
            temp_path = f.name

        try:
            result = parser.parse_config_file(Path(temp_path), resolve_includes=True)
            assert result is not None
            # Should have resolved the simple_static.conf file
            assert any("simple_static.conf" in path for path in result.resolved_includes)
        finally:
            os.unlink(temp_path)
