"""
Unit tests for input sanitization.

Tests NGINX directive injection prevention and proxy_pass URL validation.
"""

import pytest
from pydantic import ValidationError

from core.config_generator.generator import sanitize_nginx_value, ConfigGeneratorError
from models.site_requests import SiteCreateRequest, SiteUpdateRequest, SiteType


class TestSanitizeNginxValue:
    """Test sanitize_nginx_value rejects dangerous characters."""

    def test_safe_value_passes(self):
        """Normal values pass through unchanged."""
        assert sanitize_nginx_value("example.com", "test") == "example.com"

    def test_safe_value_with_dots_dashes(self):
        """Domain-like values with dots and dashes pass."""
        assert sanitize_nginx_value("my-site.example.com", "test") == "my-site.example.com"

    def test_safe_path(self):
        """Normal filesystem paths pass."""
        assert sanitize_nginx_value("/var/www/html", "test") == "/var/www/html"

    def test_safe_url(self):
        """Normal URLs pass (no special nginx chars)."""
        assert sanitize_nginx_value("http://localhost:3000/api", "test") == "http://localhost:3000/api"

    def test_rejects_semicolon(self):
        """Semicolons are rejected (could end directive)."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value; malicious_directive", "test")

    def test_rejects_open_brace(self):
        """Opening braces are rejected (could start block)."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value { location /", "test")

    def test_rejects_close_brace(self):
        """Closing braces are rejected."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value }", "test")

    def test_rejects_backslash(self):
        """Backslashes are rejected."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value\\n", "test")

    def test_rejects_backtick(self):
        """Backticks are rejected (shell escape)."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value`cmd`", "test")

    def test_rejects_dollar_sign(self):
        """Dollar signs are rejected (variable interpolation)."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("$uri", "test")

    def test_rejects_newline(self):
        """Newlines are rejected (directive splitting)."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value\nnew_directive", "test")

    def test_rejects_carriage_return(self):
        """Carriage returns are rejected."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value\rinjection", "test")

    def test_rejects_null_byte(self):
        """Null bytes are rejected."""
        with pytest.raises(ConfigGeneratorError, match="Invalid character"):
            sanitize_nginx_value("value\x00", "test")

    def test_field_name_in_error(self):
        """Error message includes the field name."""
        with pytest.raises(ConfigGeneratorError, match="server_names"):
            sanitize_nginx_value("bad;value", "server_names")

    def test_empty_string_passes(self):
        """Empty string is valid (no dangerous chars)."""
        assert sanitize_nginx_value("", "test") == ""


class TestProxyPassValidation:
    """Test strengthened proxy_pass URL validation."""

    def test_valid_http_url(self):
        """Standard HTTP URL accepted."""
        req = SiteCreateRequest(
            name="test", server_names=["test.com"],
            site_type=SiteType.REVERSE_PROXY,
            proxy_pass="http://localhost:3000"
        )
        assert req.proxy_pass == "http://localhost:3000"

    def test_valid_https_url(self):
        """HTTPS URL accepted."""
        req = SiteCreateRequest(
            name="test", server_names=["test.com"],
            site_type=SiteType.REVERSE_PROXY,
            proxy_pass="https://backend.internal:8443"
        )
        assert req.proxy_pass == "https://backend.internal:8443"

    def test_valid_url_with_path(self):
        """URL with path accepted."""
        req = SiteCreateRequest(
            name="test", server_names=["test.com"],
            site_type=SiteType.REVERSE_PROXY,
            proxy_pass="http://localhost:3000/api/v1"
        )
        assert req.proxy_pass == "http://localhost:3000/api/v1"

    def test_rejects_non_http_scheme(self):
        """Non-HTTP schemes rejected."""
        with pytest.raises(ValidationError, match="HTTP or HTTPS"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="ftp://files.internal"
            )

    def test_rejects_no_hostname(self):
        """URL without hostname rejected."""
        with pytest.raises(ValidationError, match="hostname"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://"
            )

    def test_rejects_credentials_in_url(self):
        """URL with embedded credentials rejected."""
        with pytest.raises(ValidationError, match="credentials"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://admin:secret@backend:3000"
            )

    def test_rejects_query_string(self):
        """URL with query string rejected."""
        with pytest.raises(ValidationError, match="query"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://localhost:3000?key=value"
            )

    def test_rejects_fragment(self):
        """URL with fragment rejected."""
        with pytest.raises(ValidationError, match="fragment"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://localhost:3000#section"
            )

    def test_rejects_aws_metadata_endpoint(self):
        """AWS metadata endpoint rejected (SSRF prevention)."""
        with pytest.raises(ValidationError, match="metadata"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://169.254.169.254/latest/meta-data"
            )

    def test_rejects_gcp_metadata_endpoint(self):
        """GCP metadata endpoint rejected (SSRF prevention)."""
        with pytest.raises(ValidationError, match="metadata"):
            SiteCreateRequest(
                name="test", server_names=["test.com"],
                site_type=SiteType.REVERSE_PROXY,
                proxy_pass="http://metadata.google.internal/computeMetadata/v1"
            )

    def test_update_rejects_credentials(self):
        """SiteUpdateRequest also validates proxy_pass."""
        with pytest.raises(ValidationError, match="credentials"):
            SiteUpdateRequest(proxy_pass="http://user:pass@host:80")

    def test_update_rejects_metadata(self):
        """SiteUpdateRequest also blocks metadata endpoints."""
        with pytest.raises(ValidationError, match="metadata"):
            SiteUpdateRequest(proxy_pass="http://169.254.169.254")
