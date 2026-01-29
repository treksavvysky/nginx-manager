"""
Unit tests for GPT schema generation.
"""

import pytest

from core.gpt_schema import generate_gpt_schema, _ensure_operation_ids, _truncate_descriptions


def _make_sample_schema():
    """Create a minimal OpenAPI schema for testing."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "NGINX Manager API",
            "description": "A" * 600,
            "version": "0.1.0"
        },
        "paths": {
            "/sites/": {
                "get": {
                    "summary": "List Sites",
                    "description": "List all sites" + " with details" * 50,
                    "operationId": "list_sites",
                    "tags": ["Site Configuration"],
                    "responses": {"200": {"description": "OK"}}
                },
                "post": {
                    "summary": "Create Site",
                    "description": "Create a new site",
                    "operationId": "create_site",
                    "tags": ["Site Configuration"],
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/nginx/reload": {
                "post": {
                    "summary": "Reload NGINX",
                    "description": "Gracefully reload",
                    "operationId": "reload_nginx",
                    "tags": ["NGINX Control"],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/events/": {
                "get": {
                    "summary": "List Events",
                    "description": "List audit events",
                    "operationId": "list_events",
                    "tags": ["Events"],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/docs": {
                "get": {
                    "summary": "Swagger Docs",
                    "tags": ["Docs"],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/workflows/setup-site": {
                "post": {
                    "summary": "Setup Site Workflow",
                    "description": "Compound workflow",
                    "operationId": "setup_site_workflow",
                    "tags": ["Agent Workflows"],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        },
        "components": {
            "schemas": {
                "SiteConfig": {"type": "object"}
            }
        }
    }


class TestGenerateGptSchema:
    """Tests for generate_gpt_schema function."""

    def test_servers_array_set(self):
        schema = generate_gpt_schema(
            _make_sample_schema(),
            server_url="https://myserver.com:8000"
        )
        assert schema["servers"] == [{"url": "https://myserver.com:8000"}]

    def test_security_scheme_added(self):
        schema = generate_gpt_schema(_make_sample_schema())
        assert "securitySchemes" in schema["components"]
        assert "apiKey" in schema["components"]["securitySchemes"]
        sec = schema["components"]["securitySchemes"]["apiKey"]
        assert sec["type"] == "apiKey"
        assert sec["in"] == "header"
        assert sec["name"] == "X-API-Key"

    def test_default_paths_excluded(self):
        schema = generate_gpt_schema(_make_sample_schema())
        assert "/docs" not in schema["paths"]

    def test_custom_paths_excluded(self):
        schema = generate_gpt_schema(
            _make_sample_schema(),
            exclude_paths=["/events/"]
        )
        assert "/events/" not in schema["paths"]
        assert "/docs" not in schema["paths"]

    def test_tag_filtering(self):
        schema = generate_gpt_schema(
            _make_sample_schema(),
            include_tags=["Site Configuration", "Agent Workflows"]
        )
        assert "/sites/" in schema["paths"]
        assert "/workflows/setup-site" in schema["paths"]
        assert "/nginx/reload" not in schema["paths"]
        assert "/events/" not in schema["paths"]

    def test_tag_filtering_includes_matching_methods_only(self):
        # Schema where a path has methods with different tags
        test_schema = {
            "openapi": "3.1.0",
            "info": {"title": "Test", "version": "0.1.0"},
            "paths": {
                "/mixed": {
                    "get": {
                        "summary": "Get",
                        "operationId": "get_mixed",
                        "tags": ["Included"],
                        "responses": {"200": {"description": "OK"}}
                    },
                    "post": {
                        "summary": "Post",
                        "operationId": "post_mixed",
                        "tags": ["Excluded"],
                        "responses": {"201": {"description": "Created"}}
                    }
                }
            }
        }
        schema = generate_gpt_schema(test_schema, include_tags=["Included"])
        assert "/mixed" in schema["paths"]
        assert "get" in schema["paths"]["/mixed"]
        assert "post" not in schema["paths"]["/mixed"]

    def test_all_operations_have_operation_id(self):
        # Remove operationId from one endpoint
        source = _make_sample_schema()
        del source["paths"]["/sites/"]["get"]["operationId"]

        schema = generate_gpt_schema(source)
        for path, methods in schema["paths"].items():
            for method, operation in methods.items():
                if method in ("get", "post", "put", "delete", "patch"):
                    assert "operationId" in operation, f"Missing operationId for {method.upper()} {path}"

    def test_descriptions_truncated(self):
        schema = generate_gpt_schema(
            _make_sample_schema(),
            max_description_length=100
        )
        for path, methods in schema["paths"].items():
            for method, operation in methods.items():
                if method in ("get", "post", "put", "delete", "patch"):
                    desc = operation.get("description", "")
                    assert len(desc) <= 100, f"Description too long for {method.upper()} {path}: {len(desc)}"

    def test_default_description_limit_is_300(self):
        schema = generate_gpt_schema(_make_sample_schema())
        for path, methods in schema["paths"].items():
            for method, operation in methods.items():
                if method in ("get", "post", "put", "delete", "patch"):
                    desc = operation.get("description", "")
                    assert len(desc) <= 300, f"Description too long for {method.upper()} {path}: {len(desc)}"

    def test_top_level_description_truncated(self):
        schema = generate_gpt_schema(
            _make_sample_schema(),
            max_description_length=100
        )
        info_desc = schema["info"].get("description", "")
        assert len(info_desc) <= 100

    def test_existing_schemas_preserved(self):
        schema = generate_gpt_schema(_make_sample_schema())
        assert "SiteConfig" in schema["components"]["schemas"]

    def test_original_schema_not_mutated(self):
        original = _make_sample_schema()
        original_paths = set(original["paths"].keys())

        generate_gpt_schema(original, include_tags=["Site Configuration"])

        # Original should be unchanged
        assert set(original["paths"].keys()) == original_paths


class TestEnsureOperationIds:
    """Tests for _ensure_operation_ids helper."""

    def test_generates_ids_from_path(self):
        schema = {
            "paths": {
                "/sites/{name}": {
                    "get": {"summary": "Get site"},
                    "delete": {"summary": "Delete site"}
                }
            }
        }
        _ensure_operation_ids(schema)
        assert schema["paths"]["/sites/{name}"]["get"]["operationId"] == "get_sites_name"
        assert schema["paths"]["/sites/{name}"]["delete"]["operationId"] == "delete_sites_name"

    def test_preserves_existing_ids(self):
        schema = {
            "paths": {
                "/sites/": {
                    "get": {"summary": "List", "operationId": "custom_list_id"}
                }
            }
        }
        _ensure_operation_ids(schema)
        assert schema["paths"]["/sites/"]["get"]["operationId"] == "custom_list_id"

    def test_handles_duplicate_generated_ids(self):
        schema = {
            "paths": {
                "/foo": {
                    "get": {"summary": "A"}
                },
                "/foo/": {
                    "get": {"summary": "B"}
                }
            }
        }
        _ensure_operation_ids(schema)
        ids = [
            schema["paths"]["/foo"]["get"]["operationId"],
            schema["paths"]["/foo/"]["get"]["operationId"]
        ]
        # All IDs should be unique
        assert len(set(ids)) == 2


class TestTruncateDescriptions:
    """Tests for _truncate_descriptions helper."""

    def test_short_descriptions_unchanged(self):
        schema = {
            "paths": {
                "/test": {
                    "get": {"description": "Short desc"}
                }
            }
        }
        _truncate_descriptions(schema, max_length=500)
        assert schema["paths"]["/test"]["get"]["description"] == "Short desc"

    def test_long_descriptions_truncated(self):
        long_desc = "A" * 600
        schema = {
            "paths": {
                "/test": {
                    "get": {"description": long_desc}
                }
            }
        }
        _truncate_descriptions(schema, max_length=100)
        desc = schema["paths"]["/test"]["get"]["description"]
        assert len(desc) == 100
        assert desc.endswith("...")

    def test_missing_description_ok(self):
        schema = {
            "paths": {
                "/test": {
                    "get": {"summary": "No description"}
                }
            }
        }
        _truncate_descriptions(schema, max_length=100)
        assert "description" not in schema["paths"]["/test"]["get"]
