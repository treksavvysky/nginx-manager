"""
ACME service for Let's Encrypt certificate management.

Provides low-level ACME protocol operations using the acme library
for obtaining SSL certificates from Let's Encrypt.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path

import josepy as jose
from acme import challenges, client, messages
from acme import errors as acme_errors
from acme.client import ClientV2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from config import settings
from models.certificate import ACMEAccount

logger = logging.getLogger(__name__)


class ACMEError(Exception):
    """Base exception for ACME operations."""

    def __init__(self, message: str, suggestion: str = None):
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)


class ACMEChallengeError(ACMEError):
    """ACME challenge failed."""

    pass


class ACMEAuthorizationError(ACMEError):
    """ACME authorization failed."""

    pass


class ACMEOrderError(ACMEError):
    """ACME order failed."""

    pass


class ACMEService:
    """
    Low-level ACME protocol operations.

    Handles account registration, certificate orders, and
    HTTP-01 challenge management for Let's Encrypt.
    """

    def __init__(self):
        self._client: ClientV2 | None = None
        self._account_key: jose.JWK | None = None
        self._challenge_dir = Path(settings.acme_challenge_dir)
        self._account_loader = None

    def set_account_loader(self, loader):
        """Set async callback to load a saved ACME account from persistent storage."""
        self._account_loader = loader

    def reset(self):
        """Reset client state. Call after failures to prevent stale client reuse."""
        logger.info("Resetting ACME client state")
        self._client = None
        self._account_key = None

    @property
    def directory_url(self) -> str:
        """Get the ACME directory URL based on settings."""
        if settings.acme_use_staging:
            return settings.acme_staging_url
        return settings.acme_directory_url

    async def _get_or_create_account_key(self) -> jose.JWK:
        """Get existing account key, load from storage, or generate a new one."""
        if self._account_key:
            return self._account_key

        # Try loading saved account from persistent storage
        if self._account_loader:
            try:
                saved_account = await self._account_loader()
                if saved_account:
                    logger.info("Loading ACME account from database")
                    await self.load_account(saved_account)
                    return self._account_key
            except Exception as e:
                logger.warning(f"Failed to load saved ACME account: {e}")

        # Generate new RSA key for account
        logger.info("Generating new ACME account key")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._account_key = jose.JWKRSA(key=private_key)
        return self._account_key

    async def _get_client(self) -> ClientV2:
        """Get or create ACME client."""
        if self._client:
            return self._client

        account_key = await self._get_or_create_account_key()

        # Create client in thread pool (blocking network call)
        def create_client():
            net = client.ClientNetwork(account_key, user_agent="nginx-manager/1.0")
            directory = messages.Directory.from_json(net.get(self.directory_url).json())
            return ClientV2(directory, net=net)

        self._client = await asyncio.to_thread(create_client)
        return self._client

    async def register_account(self, email: str | None = None) -> ACMEAccount:
        """
        Register a new ACME account or retrieve existing one.

        Args:
            email: Email for account registration (optional but recommended)

        Returns:
            ACMEAccount with registration details
        """
        acme_client = await self._get_client()
        account_key = await self._get_or_create_account_key()

        email_to_use = email or settings.acme_account_email or None

        def do_registration():
            regr = messages.NewRegistration.from_data(terms_of_service_agreed=True)
            if email_to_use:
                regr = regr.update(contact=(f"mailto:{email_to_use}",))

            try:
                account_resource = acme_client.new_account(regr)
                logger.info("Created new ACME account")
                return account_resource
            except acme_errors.ConflictError as conflict:
                # Account already exists — use the location URL to query it
                logger.info(f"ACME account already exists at {conflict.location}, retrieving")
                existing_regr = messages.RegistrationResource(uri=conflict.location, body=messages.Registration())
                return acme_client.query_registration(existing_regr)

        account_resource = await asyncio.to_thread(do_registration)

        # Serialize private key
        private_key_pem = account_key.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        return ACMEAccount(
            email=email_to_use,
            directory_url=self.directory_url,
            account_url=account_resource.uri if hasattr(account_resource, "uri") else None,
            private_key_pem=private_key_pem,
        )

    async def load_account(self, account: ACMEAccount) -> None:
        """
        Load an existing ACME account from saved credentials.

        Args:
            account: ACMEAccount with private key
        """
        # Load private key from PEM
        private_key = serialization.load_pem_private_key(account.private_key_pem.encode("utf-8"), password=None)
        self._account_key = jose.JWKRSA(key=private_key)

        # Recreate client with loaded key
        self._client = None
        await self._get_client()

    def _make_csr(self, domains: list[str]) -> bytes:
        """
        Create a CSR for the given domains.

        Args:
            domains: List of domain names

        Returns:
            PEM-encoded CSR bytes
        """
        # Generate a temporary key for the CSR
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build CSR with SAN extension
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))

        # Add Subject Alternative Names
        san_list = [x509.DNSName(domain) for domain in domains]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        # Sign the CSR
        csr = builder.sign(private_key, hashes.SHA256())

        # Return PEM-encoded CSR
        return csr.public_bytes(serialization.Encoding.PEM)

    async def create_order(self, domains: list[str]) -> messages.OrderResource:
        """
        Create a new certificate order.

        Args:
            domains: List of domains for the certificate

        Returns:
            OrderResource with authorization URLs
        """
        acme_client = await self._get_client()

        # Create CSR outside the thread
        csr_der = self._make_csr(domains)

        def do_create_order():
            return acme_client.new_order(csr_der)

        try:
            order = await asyncio.to_thread(do_create_order)
            logger.info(f"Created ACME order for domains: {domains}")
            return order
        except Exception as e:
            raise ACMEOrderError(
                f"Failed to create order: {e}", suggestion="Check that all domains are valid and resolvable"
            )

    async def get_http_challenge(self, authorization: messages.AuthorizationResource) -> tuple[challenges.HTTP01, str]:
        """
        Extract HTTP-01 challenge from authorization.

        Args:
            authorization: Authorization resource from order

        Returns:
            Tuple of (challenge, key_authorization)
        """
        acme_client = await self._get_client()

        for challenge in authorization.body.challenges:
            if isinstance(challenge.chall, challenges.HTTP01):
                # Compute key authorization
                key_authz = challenge.chall.key_authorization(acme_client.net.key)
                return challenge, key_authz

        raise ACMEChallengeError("No HTTP-01 challenge found", suggestion="Server may only support DNS-01 challenges")

    async def setup_challenge_file(self, token, key_authorization: str) -> Path:
        """
        Create HTTP-01 challenge file.

        Args:
            token: Challenge token (str or bytes)
            key_authorization: Key authorization string

        Returns:
            Path to created challenge file
        """
        # Ensure challenge directory exists
        self._challenge_dir.mkdir(parents=True, exist_ok=True)

        # Handle bytes token from ACME library
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        challenge_path = self._challenge_dir / token
        challenge_path.write_text(key_authorization)

        logger.info(f"Created challenge file at {challenge_path}")
        return challenge_path

    async def cleanup_challenge(self, token) -> None:
        """
        Remove HTTP-01 challenge file.

        Args:
            token: Challenge token (str or bytes)
        """
        # Handle bytes token from ACME library
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        challenge_path = self._challenge_dir / token
        if challenge_path.exists():
            challenge_path.unlink()
            logger.info(f"Removed challenge file {challenge_path}")

    async def respond_to_challenge(self, challenge):
        """
        Notify ACME server that challenge is ready.

        Args:
            challenge: Challenge to respond to

        Returns:
            Updated challenge resource
        """
        acme_client = await self._get_client()

        def do_respond():
            return acme_client.answer_challenge(challenge, challenge.chall.response(acme_client.net.key))

        try:
            response = await asyncio.to_thread(do_respond)
            logger.info(f"Responded to challenge for token {challenge.chall.token}")
            return response
        except Exception as e:
            raise ACMEChallengeError(
                f"Failed to respond to challenge: {e}",
                suggestion="Ensure challenge file is accessible at http://domain/.well-known/acme-challenge/{token}",
            )

    async def poll_authorization(
        self, order: messages.OrderResource, timeout: int = 300, interval: float = 2.0
    ) -> messages.OrderResource:
        """
        Poll until order authorizations are valid.

        Args:
            order: Order resource to poll
            timeout: Maximum seconds to wait
            interval: Seconds between polls

        Returns:
            Updated order resource
        """
        acme_client = await self._get_client()
        from datetime import timedelta

        deadline_dt = datetime.utcnow() + timedelta(seconds=timeout)
        deadline_ts = deadline_dt.timestamp()

        def poll_order():
            return acme_client.poll_authorizations(order, deadline_dt)

        while datetime.utcnow().timestamp() < deadline_ts:
            try:
                updated_order = await asyncio.to_thread(poll_order)

                # Check if all authorizations are valid
                all_valid = all(authz.body.status == messages.STATUS_VALID for authz in updated_order.authorizations)

                if all_valid:
                    logger.info("All authorizations validated")
                    return updated_order

                # Check for failures
                for authz in updated_order.authorizations:
                    if authz.body.status == messages.STATUS_INVALID:
                        raise ACMEAuthorizationError(
                            f"Authorization failed for {authz.body.identifier.value}",
                            suggestion="Check that the domain points to this server and port 80 is accessible",
                        )

            except ACMEAuthorizationError:
                raise
            except Exception as e:
                logger.warning(f"Poll error: {e}")

            await asyncio.sleep(interval)

        raise ACMEAuthorizationError(
            f"Authorization timed out after {timeout} seconds",
            suggestion="Increase timeout or check domain accessibility",
        )

    async def finalize_order(
        self, order: messages.OrderResource, domains: list[str], timeout: int = 300
    ) -> tuple[bytes, bytes, bytes]:
        """
        Finalize order and download certificate.

        Args:
            order: Validated order resource
            domains: List of domains for CSR
            timeout: Timeout in seconds for finalization

        Returns:
            Tuple of (certificate_pem, private_key_pem, chain_pem)
        """
        acme_client = await self._get_client()

        # Generate private key for certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build CSR with SAN extension
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))

        # Add Subject Alternative Names
        san_list = [x509.DNSName(domain) for domain in domains]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        # Sign the CSR and get PEM bytes
        csr = builder.sign(private_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        from datetime import timedelta

        deadline = datetime.utcnow() + timedelta(seconds=timeout)

        def do_finalize():
            # Finalize order (CSR was already provided during order creation)
            # But we need to update the order with our new CSR for the final cert
            updated_order = order.update(csr_pem=csr_pem)
            finalized = acme_client.finalize_order(updated_order, deadline)
            return finalized

        try:
            finalized_order = await asyncio.to_thread(do_finalize)
        except Exception as e:
            raise ACMEOrderError(
                f"Failed to finalize order: {e}", suggestion="Check that all authorizations completed successfully"
            )

        # Extract certificate chain
        fullchain_pem = finalized_order.fullchain_pem.encode("utf-8")

        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Split fullchain into cert and chain
        certs = fullchain_pem.split(b"-----END CERTIFICATE-----")
        cert_pem = certs[0] + b"-----END CERTIFICATE-----\n"
        chain_pem = b"-----END CERTIFICATE-----".join(certs[1:])
        if chain_pem.strip():
            chain_pem = chain_pem.strip() + b"\n"
        else:
            chain_pem = b""

        logger.info(f"Successfully obtained certificate for {domains}")

        return cert_pem, private_key_pem, chain_pem

    async def revoke_certificate(self, cert_pem: bytes, reason: int = 0) -> bool:
        """
        Revoke a certificate.

        Args:
            cert_pem: PEM-encoded certificate
            reason: Revocation reason code (0 = unspecified)

        Returns:
            True if revocation succeeded
        """
        acme_client = await self._get_client()

        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem)

        def do_revoke():
            acme_client.revoke(jose.ComparableX509(cert), reason)

        try:
            await asyncio.to_thread(do_revoke)
            logger.info("Certificate revoked successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")
            raise ACMEError(
                f"Failed to revoke certificate: {e}", suggestion="Certificate may already be revoked or expired"
            )


def parse_certificate(cert_pem: bytes) -> dict:
    """
    Parse a PEM certificate and extract details.

    Args:
        cert_pem: PEM-encoded certificate

    Returns:
        Dictionary with certificate details
    """
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Extract subject
    subject_parts = []
    for attr in cert.subject:
        subject_parts.append(f"{attr.oid._name}={attr.value}")
    subject = ", ".join(subject_parts)

    # Extract issuer
    issuer_parts = []
    for attr in cert.issuer:
        issuer_parts.append(f"{attr.oid._name}={attr.value}")
    issuer = ", ".join(issuer_parts)

    # Extract SANs
    alt_names = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        alt_names = [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    # Compute fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "alt_names": alt_names,
        "fingerprint_sha256": fingerprint,
    }


def validate_certificate_key_match(cert_pem: bytes, key_pem: bytes) -> bool:
    """
    Validate that a certificate and private key match.

    Args:
        cert_pem: PEM-encoded certificate
        key_pem: PEM-encoded private key

    Returns:
        True if they match
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    private_key = serialization.load_pem_private_key(key_pem, password=None)

    # Get public key from certificate and private key
    cert_public = cert.public_key()
    key_public = private_key.public_key()

    # Compare public key bytes
    cert_bytes = cert_public.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_bytes = key_public.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return cert_bytes == key_bytes


# Singleton instance
_acme_service: ACMEService | None = None


def get_acme_service() -> ACMEService:
    """Get the global ACME service instance."""
    global _acme_service
    if _acme_service is None:
        _acme_service = ACMEService()
    return _acme_service
