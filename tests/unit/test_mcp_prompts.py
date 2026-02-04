"""
Unit tests for MCP prompt generators.

Tests all 5 prompt generator functions and the AVAILABLE_PROMPTS registry.
"""

from mcp_server.prompts import (
    AVAILABLE_PROMPTS,
    get_add_ssl_prompt,
    get_check_expiring_certs_prompt,
    get_diagnose_connectivity_prompt,
    get_rollback_changes_prompt,
    get_setup_new_site_prompt,
)


class TestSetupNewSitePrompt:
    """Tests for setup_new_site prompt generator."""

    def test_prompt_includes_domain(self):
        result = get_setup_new_site_prompt("example.com", "static")
        assert "example.com" in result

    def test_prompt_includes_site_type(self):
        result = get_setup_new_site_prompt("example.com", "reverse_proxy")
        assert "reverse_proxy" in result

    def test_prompt_with_ssl_includes_ssl_steps(self):
        result = get_setup_new_site_prompt("example.com", "static", with_ssl=True)
        assert "diagnose_ssl" in result
        assert "request_certificate" in result
        assert "Verify SSL" in result

    def test_prompt_without_ssl_omits_ssl_steps(self):
        result = get_setup_new_site_prompt("example.com", "static", with_ssl=False)
        assert "diagnose_ssl" not in result
        assert "request_certificate" not in result

    def test_prompt_static_site_type(self):
        result = get_setup_new_site_prompt("example.com", "static")
        assert "Document root" in result
        assert "static sites" in result

    def test_prompt_reverse_proxy_type(self):
        result = get_setup_new_site_prompt("example.com", "reverse_proxy")
        assert "Backend URL" in result
        assert "reverse proxy sites" in result

    def test_prompt_returns_string(self):
        result = get_setup_new_site_prompt("example.com", "static")
        assert isinstance(result, str)
        assert len(result) > 100

    def test_prompt_includes_common_issues_table(self):
        result = get_setup_new_site_prompt("example.com", "static")
        assert "| Issue | Solution |" in result


class TestAddSslPrompt:
    """Tests for add_ssl_to_site prompt generator."""

    def test_letsencrypt_prompt(self):
        result = get_add_ssl_prompt("example.com", "letsencrypt")
        assert "Let's Encrypt" in result
        assert "request_certificate" in result

    def test_custom_cert_prompt(self):
        result = get_add_ssl_prompt("example.com", "custom")
        assert "Upload Custom Certificate" in result
        assert "upload_certificate" in result

    def test_prompt_includes_domain(self):
        result = get_add_ssl_prompt("secure.example.com")
        assert "secure.example.com" in result

    def test_prompt_includes_troubleshooting_table(self):
        result = get_add_ssl_prompt("example.com")
        assert "| Issue | Cause | Solution |" in result

    def test_prompt_includes_rate_limits(self):
        result = get_add_ssl_prompt("example.com", "letsencrypt")
        assert "Rate Limit" in result


class TestCheckExpiringCertsPrompt:
    """Tests for check_expiring_certs prompt generator."""

    def test_prompt_includes_threshold(self):
        result = get_check_expiring_certs_prompt(14)
        assert "14" in result

    def test_default_threshold(self):
        result = get_check_expiring_certs_prompt()
        assert "30" in result

    def test_prompt_contains_priority_matrix(self):
        result = get_check_expiring_certs_prompt()
        assert "Priority Matrix" in result
        assert "CRITICAL" in result
        assert "HIGH" in result

    def test_prompt_contains_renewal_issues_table(self):
        result = get_check_expiring_certs_prompt()
        assert "Common Renewal Issues" in result


class TestDiagnoseConnectivityPrompt:
    """Tests for diagnose_connectivity prompt generator."""

    def test_prompt_includes_domain(self):
        result = get_diagnose_connectivity_prompt("broken.example.com")
        assert "broken.example.com" in result

    def test_prompt_includes_diagnostic_steps(self):
        result = get_diagnose_connectivity_prompt("example.com")
        assert "Step 1" in result
        assert "Step 2" in result
        assert "Step 3" in result
        assert "Step 4" in result
        assert "Step 5" in result

    def test_prompt_includes_decision_tree(self):
        result = get_diagnose_connectivity_prompt("example.com")
        assert "Decision Tree" in result

    def test_prompt_includes_common_solutions_table(self):
        result = get_diagnose_connectivity_prompt("example.com")
        assert "| Symptom | Likely Cause | Solution |" in result


class TestRollbackChangesPrompt:
    """Tests for rollback_changes prompt generator."""

    def test_prompt_without_resource(self):
        result = get_rollback_changes_prompt()
        assert "Rolling Back Changes" in result
        # Without a resource, there should be no filter-by-resource instruction
        assert "Filter by resource" not in result

    def test_prompt_with_resource(self):
        result = get_rollback_changes_prompt("example.com")
        assert "example.com" in result
        assert "resource_id" in result

    def test_prompt_includes_status_table(self):
        result = get_rollback_changes_prompt()
        assert "| Status | Can Rollback? | Notes |" in result
        assert "COMPLETED" in result
        assert "ROLLED_BACK" in result

    def test_prompt_includes_example_scenarios(self):
        result = get_rollback_changes_prompt()
        assert "Scenario" in result


class TestAvailablePromptsRegistry:
    """Tests for the AVAILABLE_PROMPTS dictionary."""

    def test_registry_has_all_five_prompts(self):
        assert len(AVAILABLE_PROMPTS) == 5

    def test_registry_keys(self):
        expected = {
            "setup_new_site",
            "add_ssl_to_site",
            "check_expiring_certs",
            "diagnose_connectivity",
            "rollback_changes",
        }
        assert set(AVAILABLE_PROMPTS.keys()) == expected

    def test_registry_keys_match_prompt_names(self):
        for key, entry in AVAILABLE_PROMPTS.items():
            assert entry["name"] == key

    def test_all_entries_have_required_fields(self):
        for key, entry in AVAILABLE_PROMPTS.items():
            assert "name" in entry, f"{key} missing 'name'"
            assert "description" in entry, f"{key} missing 'description'"
            assert "arguments" in entry, f"{key} missing 'arguments'"
            assert "generator" in entry, f"{key} missing 'generator'"

    def test_all_generators_are_callable(self):
        for key, entry in AVAILABLE_PROMPTS.items():
            assert callable(entry["generator"]), f"{key} generator is not callable"

    def test_required_arguments_marked_correctly(self):
        setup = AVAILABLE_PROMPTS["setup_new_site"]
        arg_names = {a["name"]: a["required"] for a in setup["arguments"]}
        assert arg_names["domain"] is True
        assert arg_names["site_type"] is True
        assert arg_names["with_ssl"] is False
