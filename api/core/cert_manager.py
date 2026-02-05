"""
Certificate manager for SSL certificate lifecycle management.

Provides high-level operations for requesting, installing, renewing,
and revoking SSL certificates using the ACME service.
"""

import asyncio
import json
import logging
import re
import socket
from datetime import datetime
from pathlib import Path

from config import settings
from core.acme_service import (
    ACMEService,
    get_acme_service,
    parse_certificate,
    validate_certificate_key_match,
)
from core.database import get_database
from core.docker_service import docker_service
from core.encryption_service import get_encryption_service
from models.certificate import (
    Certificate,
    CertificateDryRunResult,
    CertificateStatus,
    CertificateType,
    SSLDiagnosticResult,
)

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    """Base exception for certificate operations."""

    def __init__(self, message: str, domain: str = None, suggestion: str = None):
        self.message = message
        self.domain = domain
        self.suggestion = suggestion
        super().__init__(message)


class CertificateNotFoundError(CertificateError):
    """Certificate not found."""

    pass


class CertificateValidationError(CertificateError):
    """Certificate validation failed."""

    pass


class DNSError(CertificateError):
    """DNS resolution error."""

    pass


class CertManager:
    """
    High-level certificate lifecycle management.

    Handles the complete flow from certificate request through
    installation, renewal, and revocation.
    """

    def __init__(self):
        self.acme: ACMEService = get_acme_service()
        self.acme.set_account_loader(self._load_acme_account)
        self.db = get_database()
        self.cert_base_dir = Path(settings.ssl_cert_dir)
        self.cert_nginx_dir = Path(settings.ssl_cert_nginx_path)

    async def _load_acme_account(self):
        """Load the most recent ACME account from the database."""
        directory_url = self.acme.directory_url
        row = await self.db.fetch_one(
            "SELECT * FROM acme_accounts WHERE directory_url = ? ORDER BY created_at DESC LIMIT 1", (directory_url,)
        )
        if row:
            from models.certificate import ACMEAccount

            # Decrypt the private key if it was encrypted at rest
            encryption = get_encryption_service()
            private_key_pem = encryption.decrypt_string(row["private_key_pem"])
            return ACMEAccount(
                id=row["id"],
                email=row["email"],
                directory_url=row["directory_url"],
                account_url=row["account_url"],
                private_key_pem=private_key_pem,
            )
        return None

    async def _save_acme_account(self, account):
        """Save an ACME account to the database for reuse across restarts."""
        import uuid

        # Check for existing account with same directory_url to avoid duplicates
        existing = await self.db.fetch_one(
            "SELECT id FROM acme_accounts WHERE directory_url = ? LIMIT 1",
            (account.directory_url,),
        )

        # Encrypt the private key at rest if enabled
        encryption = get_encryption_service()
        encrypted_key_pem = encryption.encrypt_string(account.private_key_pem)

        if existing:
            # Update existing account record instead of creating a duplicate
            account_id = existing["id"]
            await self.db.execute(
                """UPDATE acme_accounts
                   SET email = ?, account_url = ?, private_key_pem = ?
                   WHERE id = ?""",
                (account.email, account.account_url, encrypted_key_pem, account_id),
            )
            logger.info(f"Updated existing ACME account {account_id} for {account.directory_url}")
        else:
            account_id = account.id or f"acme-{uuid.uuid4().hex[:12]}"
            await self.db.execute(
                """INSERT INTO acme_accounts
                   (id, email, directory_url, account_url, private_key_pem)
                   VALUES (?, ?, ?, ?, ?)""",
                (account_id, account.email, account.directory_url, account.account_url, encrypted_key_pem),
            )
            logger.info(f"Saved new ACME account {account_id} for {account.directory_url}")

    def _get_cert_dir(self, domain: str) -> Path:
        """Get the certificate directory for a domain (host-writable path)."""
        return self.cert_base_dir / domain

    def _get_cert_nginx_dir(self, domain: str) -> Path:
        """Get the certificate directory as seen inside the NGINX container."""
        return self.cert_nginx_dir / domain

    def _ensure_cert_dir(self, domain: str) -> Path:
        """Ensure certificate directory exists."""
        cert_dir = self._get_cert_dir(domain)
        cert_dir.mkdir(parents=True, exist_ok=True)
        return cert_dir

    async def _find_site_config(self, domain: str) -> Path | None:
        """Find the NGINX config file that serves a given domain."""
        conf_dir = Path(settings.nginx_conf_dir)
        if not conf_dir.exists():
            return None

        # Check common naming patterns first
        for candidate in [
            conf_dir / f"{domain}.conf",
            conf_dir / f"{domain.replace('.', '_')}.conf",
        ]:
            if candidate.exists():
                return candidate

        # Search all .conf files for server_name matching this domain
        for conf_file in conf_dir.glob("*.conf"):
            try:
                content = conf_file.read_text()
                if "server_name" in content and domain in content:
                    return conf_file
            except Exception:
                continue

        return None

    async def _ensure_acme_challenge_routing(self, domain: str) -> bool:
        """
        Ensure the site config has an ACME challenge location block.

        Injects the block before the first 'location /' if missing.
        Validates with nginx -t and reloads NGINX after injection.

        Returns True if block was injected, False if already present or failed.
        """
        config_path = await self._find_site_config(domain)
        if not config_path:
            logger.warning(f"No site config found for {domain}, skipping ACME routing injection")
            return False

        content = config_path.read_text()

        # Already has ACME challenge block
        if "/.well-known/acme-challenge/" in content:
            logger.info(f"ACME challenge routing already present in {config_path.name}")
            return False

        # Build the ACME challenge location block
        acme_block = (
            "\n"
            "    # ACME challenge for Let's Encrypt\n"
            "    location ^~ /.well-known/acme-challenge/ {\n"
            f"        alias {settings.acme_challenge_nginx_path}/;\n"
            '        default_type "text/plain";\n'
            "        try_files $uri =404;\n"
            "    }\n"
        )

        # Find the first 'location / {' (not 'location ^~' or other prefixed locations)
        match = re.search(r"^(\s*location\s+/\s*\{)", content, re.MULTILINE)
        if match:
            insert_pos = match.start()
            new_content = content[:insert_pos] + acme_block + "\n" + content[insert_pos:]
        else:
            logger.warning(f"Could not find 'location /' block in {config_path.name}")
            return False

        # Write updated config
        original_content = content
        config_path.write_text(new_content)

        # Validate with nginx -t
        try:
            success, _stdout, stderr = await docker_service.test_config()
            if not success:
                config_path.write_text(original_content)
                logger.error(f"ACME challenge injection failed validation: {stderr}")
                return False
        except Exception as e:
            config_path.write_text(original_content)
            logger.error(f"Failed to validate config after ACME injection: {e}")
            return False

        # Reload NGINX so the challenge route is live
        try:
            await docker_service.reload_nginx()
        except Exception as e:
            logger.warning(f"Failed to reload NGINX after ACME injection: {e}")

        logger.info(f"Injected ACME challenge routing into {config_path.name}")
        return True

    async def _upgrade_site_to_ssl(self, domain: str, ssl_cert_path: str, ssl_key_path: str) -> bool:
        """
        Upgrade a site config to SSL after certificate issuance.

        Replaces the HTTP-only config with a full SSL template containing
        an HTTP-to-HTTPS redirect and an HTTPS server block.

        Returns True if upgraded, False if already SSL or failed.
        """
        config_path = await self._find_site_config(domain)
        if not config_path:
            logger.warning(f"No site config found for {domain}, skipping SSL upgrade")
            return False

        content = config_path.read_text()

        # Already has SSL
        if "ssl_certificate" in content:
            logger.info(f"Site {domain} already has SSL configuration")
            return False

        # Determine site type
        is_reverse_proxy = "proxy_pass" in content

        # Extract server_names
        server_name_match = re.search(r"server_name\s+(.+?);", content)
        server_names = server_name_match.group(1).strip() if server_name_match else domain

        # Extract existing config values
        root_path = None
        proxy_pass = None
        index_files = "index.html index.htm"

        if is_reverse_proxy:
            proxy_match = re.search(r"proxy_pass\s+(.+?);", content)
            proxy_pass = proxy_match.group(1).strip() if proxy_match else None
        else:
            root_match = re.search(r"root\s+(.+?);", content)
            root_path = root_match.group(1).strip() if root_match else f"/var/www/{domain}"
            index_match = re.search(r"index\s+(.+?);", content)
            if index_match:
                index_files = index_match.group(1).strip()

        # Generate new SSL config
        from core.config_generator.generator import get_config_generator

        generator = get_config_generator()
        acme_challenge_dir = settings.acme_challenge_nginx_path

        try:
            if is_reverse_proxy and proxy_pass:
                new_config = generator.generate_ssl_reverse_proxy(
                    server_names=server_names,
                    proxy_pass=proxy_pass,
                    ssl_cert_path=ssl_cert_path,
                    ssl_key_path=ssl_key_path,
                    acme_challenge_dir=acme_challenge_dir,
                )
            else:
                new_config = generator.generate_ssl_static_site(
                    server_names=server_names,
                    root_path=root_path,
                    ssl_cert_path=ssl_cert_path,
                    ssl_key_path=ssl_key_path,
                    acme_challenge_dir=acme_challenge_dir,
                    index_files=index_files,
                )
        except Exception as e:
            logger.error(f"Failed to generate SSL config for {domain}: {e}")
            return False

        # Write new config, keeping original for rollback
        original_content = content
        config_path.write_text(new_config)

        # Validate with nginx -t
        try:
            success, _stdout, stderr = await docker_service.test_config()
            if not success:
                config_path.write_text(original_content)
                logger.error(f"SSL config upgrade failed validation: {stderr}")
                return False
        except Exception as e:
            config_path.write_text(original_content)
            logger.error(f"Failed to validate SSL config: {e}")
            return False

        # Reload NGINX
        try:
            await docker_service.reload_nginx()
        except Exception as e:
            logger.warning(f"Failed to reload NGINX after SSL upgrade: {e}")

        logger.info(f"Upgraded site {domain} to SSL configuration")
        return True

    async def _save_certificate_files(
        self, domain: str, cert_pem: bytes, key_pem: bytes, chain_pem: bytes = None
    ) -> dict:
        """
        Save certificate files to disk.

        Returns dict with paths to saved files.
        """
        cert_dir = self._ensure_cert_dir(domain)

        # Save fullchain (cert + chain)
        fullchain_path = cert_dir / "fullchain.pem"
        if chain_pem:
            fullchain_content = cert_pem + chain_pem
        else:
            fullchain_content = cert_pem
        fullchain_path.write_bytes(fullchain_content)

        # Save private key (encrypt at rest if enabled)
        privkey_path = cert_dir / "privkey.pem"
        encryption = get_encryption_service()
        privkey_path.write_bytes(encryption.encrypt(key_pem))
        # Restrict permissions on private key
        privkey_path.chmod(0o600)

        # Save cert only
        cert_path = cert_dir / "cert.pem"
        cert_path.write_bytes(cert_pem)

        # Save chain only if provided
        if chain_pem:
            chain_path = cert_dir / "chain.pem"
            chain_path.write_bytes(chain_pem)

        return {
            "fullchain_path": str(fullchain_path),
            "privkey_path": str(privkey_path),
            "cert_path": str(cert_path),
            "chain_path": str(cert_dir / "chain.pem") if chain_pem else None,
        }

    def _parse_datetime(self, value: str) -> datetime | None:
        """Parse datetime string, normalizing to naive UTC."""
        if not value:
            return None
        # Handle ISO format with 'Z' suffix
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        # Convert to naive UTC if timezone-aware
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt

    async def _db_to_certificate(self, row: dict) -> Certificate:
        """Convert database row to Certificate model."""
        return Certificate(
            id=row["id"],
            domain=row["domain"],
            alt_names=json.loads(row["alt_names_json"]) if row.get("alt_names_json") else [],
            certificate_type=CertificateType(row["certificate_type"]),
            status=CertificateStatus(row["status"]),
            cert_path=row.get("cert_path"),
            key_path=row.get("key_path"),
            chain_path=row.get("chain_path"),
            issuer=row.get("issuer"),
            serial_number=row.get("serial_number"),
            not_before=self._parse_datetime(row.get("not_before")),
            not_after=self._parse_datetime(row.get("not_after")),
            fingerprint_sha256=row.get("fingerprint_sha256"),
            created_at=self._parse_datetime(row.get("created_at")) or datetime.utcnow(),
            last_renewed=self._parse_datetime(row.get("last_renewed")),
            renewal_attempts=row.get("renewal_attempts", 0),
            last_renewal_error=row.get("last_renewal_error"),
            auto_renew=bool(row.get("auto_renew", True)),
            acme_account_id=row.get("acme_account_id"),
            acme_order_url=row.get("acme_order_url"),
        )

    async def _certificate_to_db(self, cert: Certificate) -> dict:
        """Convert Certificate model to database row."""
        return {
            "id": cert.id,
            "domain": cert.domain,
            "alt_names_json": json.dumps(cert.alt_names),
            "certificate_type": cert.certificate_type.value,
            "status": cert.status.value,
            "cert_path": cert.cert_path,
            "key_path": cert.key_path,
            "chain_path": cert.chain_path,
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before.isoformat() if cert.not_before else None,
            "not_after": cert.not_after.isoformat() if cert.not_after else None,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "created_at": cert.created_at.isoformat(),
            "last_renewed": cert.last_renewed.isoformat() if cert.last_renewed else None,
            "renewal_attempts": cert.renewal_attempts,
            "last_renewal_error": cert.last_renewal_error,
            "auto_renew": cert.auto_renew,
            "acme_account_id": cert.acme_account_id,
            "acme_order_url": cert.acme_order_url,
        }

    async def check_domain_dns(self, domain: str) -> tuple[bool, list[str]]:
        """
        Check if domain resolves in DNS.

        Returns (resolves, ip_addresses)
        """
        try:
            result = await asyncio.to_thread(socket.getaddrinfo, domain, None)
            ips = list(set(addr[4][0] for addr in result))
            return True, ips
        except socket.gaierror:
            return False, []

    async def check_port_accessible(self, domain: str, port: int, timeout: float = 5.0) -> bool:
        """Check if a port is accessible on the domain."""
        try:

            def check():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((domain, port))
                sock.close()
                return result == 0

            return await asyncio.to_thread(check)
        except Exception:
            return False

    async def get_certificate(self, domain: str) -> Certificate | None:
        """Get a certificate by domain."""
        row = await self.db.fetch_one("SELECT * FROM certificates WHERE domain = ?", (domain,))
        if row:
            return await self._db_to_certificate(row)
        return None

    async def list_certificates(self, status: CertificateStatus | None = None) -> list[Certificate]:
        """List all certificates, optionally filtered by status."""
        if status:
            rows = await self.db.fetch_all(
                "SELECT * FROM certificates WHERE status = ? ORDER BY domain", (status.value,)
            )
        else:
            rows = await self.db.fetch_all("SELECT * FROM certificates ORDER BY domain")

        certs = []
        for row in rows:
            cert = await self._db_to_certificate(row)
            # Update status based on current date
            if cert.status == CertificateStatus.VALID:
                if cert.is_expired:
                    cert.status = CertificateStatus.EXPIRED
                elif cert.is_expiring_soon:
                    cert.status = CertificateStatus.EXPIRING_SOON
            certs.append(cert)

        return certs

    async def get_expiring_soon(self, days: int = None) -> list[Certificate]:
        """Get certificates expiring within specified days."""
        if days is None:
            days = settings.cert_renewal_days

        certs = await self.list_certificates()
        expiring = []

        for cert in certs:
            if cert.not_after:
                days_left = (cert.not_after - datetime.utcnow()).days
                if 0 < days_left <= days:
                    expiring.append(cert)

        return expiring

    async def request_certificate(
        self, domain: str, alt_names: list[str] = None, auto_renew: bool = True, dry_run: bool = False
    ) -> Certificate | CertificateDryRunResult:
        """
        Request a new certificate from Let's Encrypt.

        Args:
            domain: Primary domain
            alt_names: Additional domains (SANs)
            auto_renew: Enable auto-renewal
            dry_run: Only validate, don't actually request

        Returns:
            Certificate on success, or CertificateDryRunResult for dry run
        """
        all_domains = [domain] + (alt_names or [])
        warnings = []

        # Check DNS resolution
        dns_ok, _ips = await self.check_domain_dns(domain)

        # Check port 80 accessibility
        port_80_ok = await self.check_port_accessible(domain, 80)

        if dry_run:
            # Validate only
            would_succeed = dns_ok and port_80_ok

            if not dns_ok:
                warnings.append(
                    {
                        "code": "dns_not_resolving",
                        "message": f"Domain {domain} does not resolve in DNS",
                        "suggestion": "Ensure DNS A record points to this server",
                    }
                )

            if not port_80_ok:
                warnings.append(
                    {
                        "code": "port_80_not_accessible",
                        "message": "Port 80 is not accessible from the internet",
                        "suggestion": "Ensure firewall allows inbound traffic on port 80",
                    }
                )

            return CertificateDryRunResult(
                would_succeed=would_succeed,
                operation="request_certificate",
                message=f"Certificate request for {domain} would {'succeed' if would_succeed else 'fail'}",
                domain_resolves=dns_ok,
                domain_points_to_server=dns_ok,  # Simplified check
                port_80_accessible=port_80_ok,
                nginx_config_valid=True,
                sites_affected=[],
                files_to_create=[
                    str(self._get_cert_dir(domain) / "fullchain.pem"),
                    str(self._get_cert_dir(domain) / "privkey.pem"),
                ],
                warnings=warnings,
            )

        # Actual certificate request
        if not dns_ok:
            raise DNSError(
                f"Domain {domain} does not resolve in DNS",
                domain=domain,
                suggestion="Ensure DNS A record points to this server",
            )

        # Check for existing certificate
        existing = await self.get_certificate(domain)
        if existing:
            if existing.status in [CertificateStatus.VALID, CertificateStatus.PENDING]:
                raise CertificateError(
                    f"Certificate already exists for {domain} with status {existing.status.value}",
                    domain=domain,
                    suggestion="Use /certificates/{domain}/renew to renew an existing certificate",
                )
            # Remove old failed/revoked/expired certificate record
            await self.db.delete("certificates", domain, "domain")

        # Create pending certificate record
        cert = Certificate(
            domain=domain,
            alt_names=alt_names or [],
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.PENDING,
            auto_renew=auto_renew,
        )

        # Save to database
        await self.db.insert("certificates", await self._certificate_to_db(cert))

        # Ensure ACME challenge routing is in the site config before starting
        await self._ensure_acme_challenge_routing(domain)

        try:
            # Register/get ACME account
            account = await self.acme.register_account()
            cert.acme_account_id = account.id

            # Persist account for reuse across restarts
            await self._save_acme_account(account)

            # Create order
            order = await self.acme.create_order(all_domains)
            cert.acme_order_url = str(order.uri) if hasattr(order, "uri") else None

            # Process each authorization
            # Track challenge tokens for cleanup
            challenge_tokens = []

            for authz in order.authorizations:
                # Get HTTP-01 challenge
                challenge, key_authz = await self.acme.get_http_challenge(authz)

                # Get token as string (using ACME library's encoding)
                token_str = challenge.chall.encode("token")
                challenge_tokens.append(token_str)

                # Setup challenge file
                await self.acme.setup_challenge_file(token_str, key_authz)

                # Respond to challenge (tell ACME server we're ready)
                await self.acme.respond_to_challenge(challenge)

            try:
                # Poll for validation (challenge files must stay in place during this)
                validated_order = await self.acme.poll_authorization(order)
            finally:
                # Cleanup all challenge files after validation completes
                for token_str in challenge_tokens:
                    await self.acme.cleanup_challenge(token_str)

            # Finalize and get certificate
            cert_pem, key_pem, chain_pem = await self.acme.finalize_order(validated_order, all_domains)

            # Parse certificate details
            cert_info = parse_certificate(cert_pem)

            # Save certificate files
            paths = await self._save_certificate_files(domain, cert_pem, key_pem, chain_pem)

            # Update certificate record
            cert.status = CertificateStatus.VALID
            cert.cert_path = paths["fullchain_path"]
            cert.key_path = paths["privkey_path"]
            cert.chain_path = paths.get("chain_path")
            cert.issuer = cert_info["issuer"]
            cert.serial_number = cert_info["serial_number"]
            cert.not_before = cert_info["not_before"]
            cert.not_after = cert_info["not_after"]
            cert.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            cert.alt_names = cert_info.get("alt_names", alt_names or [])

            # Update database
            await self.db.update("certificates", cert.id, await self._certificate_to_db(cert))

            # Upgrade site config to SSL (HTTP redirect + HTTPS block)
            # Use NGINX container paths for ssl_certificate directives
            nginx_cert_dir = self._get_cert_nginx_dir(domain)
            await self._upgrade_site_to_ssl(
                domain,
                ssl_cert_path=str(nginx_cert_dir / "fullchain.pem"),
                ssl_key_path=str(nginx_cert_dir / "privkey.pem"),
            )

            logger.info(f"Successfully obtained certificate for {domain}")
            return cert

        except Exception as e:
            # Log the full traceback for debugging
            logger.error(f"Certificate request failed for {domain}: {type(e).__name__}: {e}", exc_info=True)

            # Reset ACME client to prevent stale state on next request
            self.acme.reset()

            # Update certificate status to failed
            cert.status = CertificateStatus.FAILED
            cert.last_renewal_error = str(e) or type(e).__name__
            await self.db.update("certificates", cert.id, await self._certificate_to_db(cert))
            error_detail = str(e) or repr(e)
            raise CertificateError(
                f"Failed to obtain certificate: {error_detail}",
                domain=domain,
                suggestion="Check domain accessibility and DNS configuration",
            )

    async def upload_custom_certificate(
        self, domain: str, cert_pem: str, key_pem: str, chain_pem: str = None, dry_run: bool = False
    ) -> Certificate | CertificateDryRunResult:
        """
        Upload and install a custom SSL certificate.

        Args:
            domain: Domain for the certificate
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            chain_pem: PEM-encoded certificate chain (optional)
            dry_run: Only validate, don't actually install
        """
        cert_bytes = cert_pem.encode("utf-8")
        key_bytes = key_pem.encode("utf-8")
        chain_bytes = chain_pem.encode("utf-8") if chain_pem else None

        warnings = []

        # Validate certificate
        try:
            cert_info = parse_certificate(cert_bytes)
        except Exception as e:
            raise CertificateValidationError(
                f"Invalid certificate format: {e}",
                domain=domain,
                suggestion="Ensure certificate is in valid PEM format",
            )

        # Validate key matches certificate
        try:
            if not validate_certificate_key_match(cert_bytes, key_bytes):
                raise CertificateValidationError(
                    "Private key does not match certificate",
                    domain=domain,
                    suggestion="Ensure private key corresponds to the certificate",
                )
        except Exception as e:
            if "does not match" in str(e):
                raise
            raise CertificateValidationError(
                f"Invalid private key format: {e}",
                domain=domain,
                suggestion="Ensure private key is in valid PEM format",
            )

        # Check expiry
        if cert_info["not_after"] < datetime.utcnow():
            warnings.append(
                {
                    "code": "certificate_expired",
                    "message": "The certificate has already expired",
                    "suggestion": "Upload a valid, non-expired certificate",
                }
            )

        if dry_run:
            return CertificateDryRunResult(
                would_succeed=len([w for w in warnings if "expired" in w["code"]]) == 0,
                operation="upload_certificate",
                message=f"Certificate upload for {domain}",
                domain_resolves=True,
                domain_points_to_server=True,
                port_80_accessible=True,
                nginx_config_valid=True,
                sites_affected=[],
                files_to_create=[
                    str(self._get_cert_dir(domain) / "fullchain.pem"),
                    str(self._get_cert_dir(domain) / "privkey.pem"),
                ],
                warnings=warnings,
            )

        # Save certificate files
        paths = await self._save_certificate_files(domain, cert_bytes, key_bytes, chain_bytes)

        # Create or update certificate record
        existing = await self.get_certificate(domain)

        cert = Certificate(
            id=existing.id if existing else None,
            domain=domain,
            alt_names=cert_info.get("alt_names", []),
            certificate_type=CertificateType.CUSTOM,
            status=CertificateStatus.VALID if cert_info["not_after"] > datetime.utcnow() else CertificateStatus.EXPIRED,
            cert_path=paths["fullchain_path"],
            key_path=paths["privkey_path"],
            chain_path=paths.get("chain_path"),
            issuer=cert_info["issuer"],
            serial_number=cert_info["serial_number"],
            not_before=cert_info["not_before"],
            not_after=cert_info["not_after"],
            fingerprint_sha256=cert_info["fingerprint_sha256"],
            auto_renew=False,  # Custom certs don't auto-renew
        )

        if existing:
            await self.db.update("certificates", cert.id, await self._certificate_to_db(cert))
        else:
            await self.db.insert("certificates", await self._certificate_to_db(cert))

        logger.info(f"Successfully uploaded custom certificate for {domain}")
        return cert

    async def renew_certificate(
        self, domain: str, force: bool = False, dry_run: bool = False
    ) -> Certificate | CertificateDryRunResult:
        """
        Renew an existing certificate.

        Args:
            domain: Domain to renew
            force: Force renewal even if not expiring soon
            dry_run: Only validate, don't actually renew
        """
        cert = await self.get_certificate(domain)
        if not cert:
            raise CertificateNotFoundError(
                f"Certificate not found for {domain}", domain=domain, suggestion="Request a new certificate instead"
            )

        if cert.certificate_type == CertificateType.CUSTOM:
            raise CertificateError(
                "Cannot auto-renew custom certificates", domain=domain, suggestion="Upload a new certificate manually"
            )

        # Check if renewal is needed
        days_left = cert.days_until_expiry
        needs_renewal = force or days_left is None or days_left <= settings.cert_renewal_days

        if dry_run:
            return CertificateDryRunResult(
                would_succeed=needs_renewal,
                operation="renew_certificate",
                message=f"Certificate renewal for {domain}"
                + ("" if needs_renewal else f" (not needed, {days_left} days remaining)"),
                domain_resolves=True,
                domain_points_to_server=True,
                port_80_accessible=True,
                nginx_config_valid=True,
                sites_affected=[],
                files_to_create=[],
                warnings=[]
                if needs_renewal
                else [
                    {
                        "code": "renewal_not_needed",
                        "message": f"Certificate has {days_left} days remaining",
                        "suggestion": "Use force=true to renew anyway",
                    }
                ],
            )

        if not needs_renewal:
            logger.info(f"Certificate for {domain} does not need renewal ({days_left} days left)")
            return cert

        # Increment renewal attempts
        cert.renewal_attempts += 1

        try:
            # Request new certificate (same as initial request)
            new_cert = await self.request_certificate(
                domain=domain, alt_names=cert.alt_names, auto_renew=cert.auto_renew
            )

            # Update renewal timestamp
            new_cert.last_renewed = datetime.utcnow()
            new_cert.renewal_attempts = 0
            new_cert.last_renewal_error = None

            await self.db.update("certificates", new_cert.id, await self._certificate_to_db(new_cert))

            logger.info(f"Successfully renewed certificate for {domain}")
            return new_cert

        except Exception as e:
            # Record failure
            cert.last_renewal_error = str(e)
            await self.db.update("certificates", cert.id, await self._certificate_to_db(cert))
            raise

    async def revoke_certificate(self, domain: str, dry_run: bool = False) -> bool | CertificateDryRunResult:
        """
        Revoke and remove a certificate.

        Args:
            domain: Domain of certificate to revoke
            dry_run: Only validate, don't actually revoke
        """
        cert = await self.get_certificate(domain)
        if not cert:
            raise CertificateNotFoundError(f"Certificate not found for {domain}", domain=domain)

        if dry_run:
            return CertificateDryRunResult(
                would_succeed=True,
                operation="revoke_certificate",
                message=f"Certificate revocation for {domain}",
                domain_resolves=True,
                domain_points_to_server=True,
                port_80_accessible=True,
                nginx_config_valid=True,
                sites_affected=[],
                files_to_create=[],
                warnings=[
                    {
                        "code": "sites_affected",
                        "message": "Sites using this certificate will need to be updated",
                        "suggestion": "Update site configurations to remove SSL or use a new certificate",
                    }
                ],
            )

        # Revoke with ACME if it's a Let's Encrypt cert
        if cert.certificate_type == CertificateType.LETSENCRYPT and cert.cert_path:
            try:
                cert_path = Path(cert.cert_path)
                if cert_path.exists():
                    cert_pem = cert_path.read_bytes()
                    await self.acme.revoke_certificate(cert_pem)
            except Exception as e:
                logger.warning(f"Failed to revoke with ACME (continuing): {e}")

        # Remove certificate files
        cert_dir = self._get_cert_dir(domain)
        if cert_dir.exists():
            import shutil

            shutil.rmtree(cert_dir)

        # Update database
        cert.status = CertificateStatus.REVOKED
        await self.db.update("certificates", cert.id, await self._certificate_to_db(cert))

        logger.info(f"Successfully revoked certificate for {domain}")
        return True

    async def delete_certificate(self, domain: str) -> bool:
        """
        Delete a certificate record from the database.

        Args:
            domain: Domain of certificate to delete
        """
        cert = await self.get_certificate(domain)
        if not cert:
            return False

        # Remove files if they exist
        cert_dir = self._get_cert_dir(domain)
        if cert_dir.exists():
            import shutil

            shutil.rmtree(cert_dir)

        # Delete from database
        await self.db.delete("certificates", cert.id)

        logger.info(f"Deleted certificate for {domain}")
        return True

    async def diagnose_ssl(self, domain: str) -> SSLDiagnosticResult:
        """
        Perform comprehensive SSL diagnostic for a domain.

        Args:
            domain: Domain to check
        """
        result = SSLDiagnosticResult(domain=domain)

        # DNS check
        dns_ok, ips = await self.check_domain_dns(domain)
        result.dns_resolves = dns_ok
        result.dns_ip_addresses = ips

        if dns_ok:
            # Port checks
            result.port_80_open = await self.check_port_accessible(domain, 80)
            result.port_443_open = await self.check_port_accessible(domain, 443)

        # Check for existing certificate
        cert = await self.get_certificate(domain)
        if cert:
            result.has_certificate = True
            result.certificate_valid = cert.status == CertificateStatus.VALID
            result.certificate_expiry = cert.not_after
            result.certificate_issuer = cert.issuer

        # Determine if ready for SSL
        result.ready_for_ssl = dns_ok and result.port_80_open

        # Build issues list
        issues = []
        if not dns_ok:
            issues.append("Domain does not resolve in DNS")
        if dns_ok and not result.port_80_open:
            issues.append("Port 80 is not accessible (required for HTTP-01 challenge)")

        result.issues = issues

        # Build suggestions
        suggestions = []
        if not dns_ok:
            suggestions.append(
                {
                    "action": "Configure DNS A record",
                    "reason": "Domain must resolve to this server for certificate validation",
                    "priority": "high",
                }
            )
        if not result.port_80_open:
            suggestions.append(
                {
                    "action": "Open port 80 in firewall",
                    "reason": "Let's Encrypt requires port 80 for HTTP-01 challenge",
                    "priority": "high",
                }
            )
        if result.ready_for_ssl and not cert:
            suggestions.append(
                {
                    "action": "Request SSL certificate",
                    "reason": "Domain is ready for SSL certificate",
                    "endpoint": "POST /certificates/",
                    "priority": "medium",
                }
            )

        result.suggestions = suggestions

        return result


# Singleton instance
_cert_manager: CertManager | None = None


def get_cert_manager() -> CertManager:
    """Get the global certificate manager instance."""
    global _cert_manager
    if _cert_manager is None:
        _cert_manager = CertManager()
    return _cert_manager
