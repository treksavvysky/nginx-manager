"""
MCP Prompts for NGINX Manager.

Prompts provide reusable templates for common workflows, helping AI models
understand context and execute multi-step operations effectively.
"""


def get_setup_new_site_prompt(domain: str, site_type: str, with_ssl: bool = True) -> str:
    """
    Generate a prompt for setting up a new website.

    Args:
        domain: Primary domain name
        site_type: Type of site ("static" or "reverse_proxy")
        with_ssl: Whether to request SSL certificate

    Returns:
        str: Detailed prompt for the workflow
    """
    ssl_steps = ""
    if with_ssl:
        ssl_steps = """
4. **Add SSL Certificate**:
   - First, run `diagnose_ssl(domain='{domain}')` to check prerequisites:
     - DNS must resolve to this server
     - Port 80 must be accessible for HTTP-01 challenge
   - If ready, request certificate: `request_certificate(domain='{domain}')`
   - Update site configuration to use SSL if needed

5. **Verify SSL**:
   - Check certificate status: `nginx://certificates/{domain}`
   - Ensure HTTPS access is working
"""

    backend_config = ""
    if site_type == "reverse_proxy":
        backend_config = """
**For reverse proxy sites**, you'll need:
- Backend URL (e.g., http://localhost:3000)
- Ensure backend service is running before creating the site
"""
    else:
        backend_config = """
**For static sites**, you'll need:
- Document root path (e.g., /var/www/{domain})
- Ensure the directory exists and has proper permissions
"""

    return f"""# Setting Up New Site: {domain}

You are setting up a new website for domain: **{domain}**

- **Site type**: {site_type}
- **SSL enabled**: {with_ssl}

{backend_config}

## Workflow Steps

1. **Check System Health**:
   - Fetch `nginx://health` to verify NGINX is running
   - Ensure no critical errors exist

2. **Preview Site Creation**:
   - Use `create_site` with `dry_run=true` to preview:
     ```
     create_site(
         name='{domain}',
         server_names=['{domain}'],
         site_type='{site_type}',
         dry_run=true
     )
     ```
   - Review generated configuration
   - Check for validation warnings

3. **Create the Site**:
   - If preview looks correct, create with `dry_run=false`
   - Verify site appears in `nginx://sites`
   - Test basic accessibility
{ssl_steps}

## Important Considerations

- **Always use dry-run first** to preview changes before applying
- **Keep track of transaction IDs** for potential rollback
- **DNS propagation**: If SSL fails, DNS may not have propagated yet
- **Rollback**: If something goes wrong, use `rollback_transaction(transaction_id='...')`

## Common Issues

| Issue | Solution |
|-------|----------|
| Site already exists | Update existing or delete first |
| Config validation fails | Check syntax errors in dry-run output |
| SSL request fails | Verify DNS points to this server |
| Backend not responding | Check upstream service is running |
"""


def get_add_ssl_prompt(domain: str, certificate_type: str = "letsencrypt") -> str:
    """
    Generate a prompt for adding SSL to an existing site.

    Args:
        domain: Domain to add SSL to
        certificate_type: Type of certificate ("letsencrypt" or "custom")

    Returns:
        str: Detailed prompt for the workflow
    """
    cert_steps = ""
    if certificate_type == "letsencrypt":
        cert_steps = """
3. **Request Let's Encrypt Certificate**:
   - Preview: `request_certificate(domain='{domain}', dry_run=true)`
   - If checks pass: `request_certificate(domain='{domain}')`
   - Certificate is automatically installed and NGINX reloaded
"""
    else:
        cert_steps = """
3. **Upload Custom Certificate**:
   - Prepare your certificate files (PEM format)
   - Preview: `upload_certificate(domain='{domain}', certificate_pem='...', private_key_pem='...', dry_run=true)`
   - If validation passes, upload without dry_run
"""

    return f"""# Adding SSL to: {domain}

You are adding SSL certificate to an existing site.

- **Domain**: {domain}
- **Certificate type**: {certificate_type}

## Workflow Steps

1. **Verify Site Exists**:
   - Check `nginx://sites/{domain}`
   - Ensure site is enabled and serving HTTP

2. **Run SSL Diagnostic**:
   - Execute `diagnose_ssl(domain='{domain}')`
   - Verify these requirements:
     - ✓ DNS resolves to this server
     - ✓ Port 80 is accessible (for HTTP-01 challenge)
     - ✓ Site is configured correctly
{cert_steps}

4. **Verify Certificate Installation**:
   - Check `nginx://certificates/{domain}`
   - Verify status is "valid"
   - Test HTTPS access to the site

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| DNS doesn't resolve | DNS not configured | Add A/AAAA records pointing to server IP |
| DNS points elsewhere | Wrong DNS config | Update DNS records, wait for propagation |
| Port 80 blocked | Firewall rules | Allow HTTP traffic through firewall |
| Rate limit exceeded | Too many requests | Use staging environment or wait |
| Cert chain invalid | Incomplete chain | Include intermediate certificates |

## Let's Encrypt Rate Limits

- 50 certificates per domain per week
- 5 duplicate certificates per week
- Use `ACME_USE_STAGING=true` for testing

## After SSL is Installed

1. Update site to redirect HTTP to HTTPS (optional)
2. Set up auto-renewal (enabled by default)
3. Monitor certificate expiry via `nginx://certificates`
"""


def get_check_expiring_certs_prompt(days_threshold: int = 30) -> str:
    """
    Generate a prompt for managing certificate renewals.

    Args:
        days_threshold: Days until expiry to consider "expiring soon"

    Returns:
        str: Detailed prompt for the workflow
    """
    return f"""# Certificate Expiry Check

Checking for certificates expiring within **{days_threshold} days**.

## Workflow Steps

1. **Fetch All Certificates**:
   - Get `nginx://certificates`
   - Review the summary counts:
     - `valid_count`: Healthy certificates
     - `expiring_soon_count`: Need renewal soon
     - `expired_count`: Urgent action required

2. **Review Expiring Certificates**:
   - Filter: `nginx://certificates?status=expiring_soon`
   - For each certificate, note:
     - Domain name
     - Days until expiry
     - Auto-renew status

3. **Handle Each Certificate**:

   **If auto_renew is enabled**:
   - Check recent events for renewal failures
   - If failing, investigate with `diagnose_ssl(domain='...')`
   - Manual renewal: `renew_certificate(domain='...', force=true)`

   **If auto_renew is disabled**:
   - Recommend enabling: Update certificate settings
   - Or manually renew: `renew_certificate(domain='...')`

4. **Dry-Run Renewal Test**:
   - For each expiring cert: `renew_certificate(domain='...', dry_run=true)`
   - Verify renewal would succeed
   - Address any issues found

## Priority Matrix

| Status | Days Left | Priority | Action |
|--------|-----------|----------|--------|
| EXPIRED | 0 or less | CRITICAL | Renew immediately |
| EXPIRING_SOON | 1-14 | HIGH | Renew within 24 hours |
| EXPIRING_SOON | 15-30 | MEDIUM | Schedule renewal |
| VALID | 30+ | LOW | Monitor |

## Auto-Renewal

The system runs automatic renewal for certificates with `auto_renew=true`:
- Checks daily for certificates within {days_threshold} days of expiry
- Attempts renewal automatically
- Creates events on success/failure

Check recent renewal events: `nginx://events?category=ssl`

## Common Renewal Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| DNS changed | Records no longer point here | Update DNS or use DNS-01 challenge |
| Port 80 blocked | Firewall changed | Allow HTTP traffic |
| Rate limited | Too many renewals | Wait or request rate limit increase |
| Domain expired | Domain registration lapsed | Renew domain registration |
"""


def get_diagnose_connectivity_prompt(domain: str) -> str:
    """
    Generate a prompt for troubleshooting site connectivity issues.

    Args:
        domain: Domain experiencing issues

    Returns:
        str: Detailed prompt for the workflow
    """
    return f"""# Diagnosing Connectivity Issues: {domain}

Troubleshooting connectivity problems for **{domain}**.

## Diagnostic Workflow

### Step 1: Check System Health
```
Fetch: nginx://health
```
- Is NGINX running? (status should be "running")
- Is configuration valid? (config_valid should be true)
- Any recent errors? (check recent_events)

### Step 2: Check Site Configuration
```
Fetch: nginx://sites/{domain}
```
- Is the site enabled?
- Are server_names correct?
- For reverse_proxy: Is proxy_pass configured correctly?
- For static: Does root_path exist?

### Step 3: Run SSL Diagnostic
```
Execute: diagnose_ssl(domain='{domain}')
```
This checks:
- DNS resolution
- Port accessibility (80, 443)
- Certificate validity
- Certificate chain

### Step 4: Check Recent Events
```
Fetch: nginx://events?severity=error
```
- Any recent errors for this site?
- Any failed operations?
- Any certificate issues?

### Step 5: Test NGINX Configuration
```
Execute: nginx_test()
```
- Are there syntax errors?
- Which files have issues?

## Decision Tree

```
Site not accessible
├── NGINX not running
│   └── Check docker container status, restart if needed
├── Site not enabled
│   └── enable_site(name='{domain}')
├── Config has errors
│   └── Review nginx_test() output, fix and reload
├── DNS not resolving
│   └── Check DNS records, wait for propagation
├── Certificate expired
│   └── renew_certificate(domain='{domain}', force=true)
├── Backend not responding (proxy sites)
│   └── Check upstream service, update proxy_pass if needed
└── Firewall blocking
    └── Check firewall rules for ports 80/443
```

## Common Solutions

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Connection refused | NGINX not running | Restart NGINX |
| 502 Bad Gateway | Backend down | Check upstream service |
| 503 Service Unavailable | Overloaded/maintenance | Check backend health |
| SSL error | Cert expired/invalid | Renew or replace certificate |
| DNS lookup failed | DNS misconfigured | Update DNS records |
| Timeout | Network/firewall | Check connectivity |

## If All Else Fails

1. **View raw configuration**:
   - `nginx://sites/{domain}` shows parsed config

2. **Check NGINX error logs**:
   - Events may contain relevant errors

3. **Try rollback**:
   - `nginx://transactions` - find recent changes
   - `rollback_transaction(transaction_id='...')` if changes caused issue

4. **Recreate site**:
   - Delete: `delete_site(name='{domain}')`
   - Create fresh: `create_site(...)`
"""


def get_rollback_changes_prompt(resource: str = None) -> str:
    """
    Generate a prompt for safely rolling back problematic changes.

    Args:
        resource: Optional resource name that has issues

    Returns:
        str: Detailed prompt for the workflow
    """
    resource_filter = ""
    if resource:
        resource_filter = f"\n   - Filter by resource: Look for `resource_id: '{resource}'`"

    return f"""# Rolling Back Changes{" for " + resource if resource else ""}

Safely reverting recent changes to restore working state.

## Workflow Steps

### Step 1: Review Recent Transactions
```
Fetch: nginx://transactions
```
- Find transactions related to the issue{resource_filter}
- Note transaction IDs
- Check timestamps to identify problematic changes

### Step 2: Examine Transaction Details

For each candidate transaction:
```
Fetch: nginx://transactions/{{transaction_id}}
```

Review:
- `operation`: What was done
- `resource_type` and `resource_id`: What was affected
- `can_rollback`: Whether rollback is possible
- `diff`: What changed

### Step 3: Verify Rollback is Safe

Before rolling back, consider:
- Will rollback break other dependent changes?
- Has the resource been modified since?
- Are there newer transactions that depend on this one?

### Step 4: Execute Rollback
```
Execute: rollback_transaction(
    transaction_id='...',
    reason='Describe why rolling back'
)
```

The rollback will:
- Create a new transaction (rollback is also tracked)
- Restore files from snapshot
- Reload NGINX if needed

### Step 5: Verify Recovery

After rollback:
1. Check system health: `nginx://health`
2. Verify affected resource: `nginx://sites/{{name}}` or `nginx://certificates/{{domain}}`
3. Test functionality

## Understanding Transaction Status

| Status | Can Rollback? | Notes |
|--------|---------------|-------|
| COMPLETED | Usually yes | If snapshot exists |
| FAILED | Usually yes | May have partial changes |
| ROLLED_BACK | No | Already rolled back |
| PENDING | No | Still in progress |

## Rollback Limitations

Rollbacks may NOT be available when:
- Snapshot was cleaned up (retention policy)
- Transaction too old
- Resource was deleted after the transaction
- Dependent transactions exist

## Important Notes

1. **Rollbacks create new transactions**:
   - The rollback itself can be rolled back
   - Full audit trail is maintained

2. **Cascading effects**:
   - If Transaction A changed File X
   - And Transaction B also changed File X
   - Rolling back A may affect B's changes

3. **SSL certificates**:
   - Certificate files are backed up
   - But ACME state may not be recoverable
   - May need to re-request certificates

## Example Scenarios

**Scenario**: Site update broke configuration
```
1. nginx://transactions → Find update transaction
2. nginx://transactions/txn_abc → Verify can_rollback=true
3. rollback_transaction(transaction_id='txn_abc', reason='Config broke NGINX')
4. nginx://health → Verify system recovered
```

**Scenario**: Wrong site deleted
```
1. nginx://transactions?status=completed → Find delete transaction
2. rollback_transaction(transaction_id='...', reason='Accidental deletion')
3. nginx://sites/{{name}} → Verify site restored
```
"""


# Dictionary of available prompts for MCP registration
AVAILABLE_PROMPTS = {
    "setup_new_site": {
        "name": "setup_new_site",
        "description": "Guide for setting up a new website with optional SSL",
        "arguments": [
            {"name": "domain", "description": "Primary domain name", "required": True},
            {"name": "site_type", "description": "Type of site: 'static' or 'reverse_proxy'", "required": True},
            {"name": "with_ssl", "description": "Request SSL certificate (default: true)", "required": False},
        ],
        "generator": get_setup_new_site_prompt,
    },
    "add_ssl_to_site": {
        "name": "add_ssl_to_site",
        "description": "Guide for adding SSL certificate to an existing site",
        "arguments": [
            {"name": "domain", "description": "Domain to add SSL to", "required": True},
            {
                "name": "certificate_type",
                "description": "Type: 'letsencrypt' or 'custom' (default: letsencrypt)",
                "required": False,
            },
        ],
        "generator": get_add_ssl_prompt,
    },
    "check_expiring_certs": {
        "name": "check_expiring_certs",
        "description": "Guide for managing certificate renewals",
        "arguments": [
            {"name": "days_threshold", "description": "Days until expiry threshold (default: 30)", "required": False}
        ],
        "generator": get_check_expiring_certs_prompt,
    },
    "diagnose_connectivity": {
        "name": "diagnose_connectivity",
        "description": "Guide for troubleshooting site connectivity issues",
        "arguments": [{"name": "domain", "description": "Domain experiencing issues", "required": True}],
        "generator": get_diagnose_connectivity_prompt,
    },
    "rollback_changes": {
        "name": "rollback_changes",
        "description": "Guide for safely rolling back problematic changes",
        "arguments": [{"name": "resource", "description": "Optional resource name that has issues", "required": False}],
        "generator": get_rollback_changes_prompt,
    },
}
