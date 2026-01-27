"""
SQLite database management for transactions and events.

Provides async database operations using aiosqlite for
storing transaction history and event logs.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
import json

import aiosqlite

from config import settings

logger = logging.getLogger(__name__)

# Database schema
SCHEMA = """
-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER,

    resource_type TEXT NOT NULL,
    resource_id TEXT,

    snapshot_path TEXT,
    before_state_json TEXT,
    after_state_json TEXT,

    request_data_json TEXT,
    result_data_json TEXT,

    error_message TEXT,
    error_details_json TEXT,

    parent_transaction_id TEXT,
    rollback_transaction_id TEXT,

    nginx_validated BOOLEAN DEFAULT FALSE,
    health_verified BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (parent_transaction_id) REFERENCES transactions(id),
    FOREIGN KEY (rollback_transaction_id) REFERENCES transactions(id)
);

CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_operation ON transactions(operation);
CREATE INDEX IF NOT EXISTS idx_transactions_resource ON transactions(resource_type, resource_id);

-- Events table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL DEFAULT 'info',

    category TEXT NOT NULL,
    action TEXT NOT NULL,

    transaction_id TEXT,
    resource_type TEXT,
    resource_id TEXT,

    message TEXT NOT NULL,
    details_json TEXT,

    source TEXT DEFAULT 'api',

    FOREIGN KEY (transaction_id) REFERENCES transactions(id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_transaction_id ON events(transaction_id);
CREATE INDEX IF NOT EXISTS idx_events_resource ON events(resource_type, resource_id);

-- Certificates table (Phase 3: SSL Management)
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    alt_names_json TEXT,
    certificate_type TEXT NOT NULL DEFAULT 'letsencrypt',
    status TEXT NOT NULL DEFAULT 'pending',

    cert_path TEXT,
    key_path TEXT,
    chain_path TEXT,

    issuer TEXT,
    serial_number TEXT,
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    fingerprint_sha256 TEXT,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_renewed TIMESTAMP,
    renewal_attempts INTEGER DEFAULT 0,
    last_renewal_error TEXT,
    auto_renew BOOLEAN DEFAULT TRUE,

    acme_account_id TEXT,
    acme_order_url TEXT,

    FOREIGN KEY (acme_account_id) REFERENCES acme_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);

-- ACME accounts table (for Let's Encrypt account persistence)
CREATE TABLE IF NOT EXISTS acme_accounts (
    id TEXT PRIMARY KEY,
    email TEXT,
    directory_url TEXT NOT NULL,
    account_url TEXT,
    private_key_pem TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    terms_accepted BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_acme_accounts_directory_url ON acme_accounts(directory_url);
"""


class Database:
    """Async SQLite database manager."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.transaction_db_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Initialize database and create tables if needed."""
        # Ensure parent directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        async with self.connection() as db:
            await db.executescript(SCHEMA)
            await db.commit()

        logger.info(f"Database initialized at {self.db_path}")

    @asynccontextmanager
    async def connection(self):
        """Get a database connection context manager."""
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
        finally:
            await conn.close()

    async def execute(
        self,
        query: str,
        params: tuple = ()
    ) -> aiosqlite.Cursor:
        """Execute a query and return the cursor."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor

    async def fetch_one(
        self,
        query: str,
        params: tuple = ()
    ) -> Optional[Dict[str, Any]]:
        """Execute a query and fetch one result."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None

    async def fetch_all(
        self,
        query: str,
        params: tuple = ()
    ) -> List[Dict[str, Any]]:
        """Execute a query and fetch all results."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def insert(
        self,
        table: str,
        data: Dict[str, Any]
    ) -> str:
        """Insert a row and return the id."""
        columns = list(data.keys())
        placeholders = ", ".join(["?" for _ in columns])
        columns_str = ", ".join(columns)

        query = f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})"
        values = tuple(data.values())

        async with self.connection() as db:
            await db.execute(query, values)
            await db.commit()

        return data.get("id", "")

    async def update(
        self,
        table: str,
        id_value: str,
        data: Dict[str, Any],
        id_column: str = "id"
    ) -> bool:
        """Update a row by id."""
        set_clause = ", ".join([f"{k} = ?" for k in data.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {id_column} = ?"
        values = tuple(data.values()) + (id_value,)

        async with self.connection() as db:
            cursor = await db.execute(query, values)
            await db.commit()
            return cursor.rowcount > 0

    async def delete(
        self,
        table: str,
        id_value: str,
        id_column: str = "id"
    ) -> bool:
        """Delete a row by id."""
        query = f"DELETE FROM {table} WHERE {id_column} = ?"

        async with self.connection() as db:
            cursor = await db.execute(query, (id_value,))
            await db.commit()
            return cursor.rowcount > 0

    async def count(
        self,
        table: str,
        where_clause: str = "",
        params: tuple = ()
    ) -> int:
        """Count rows in a table."""
        query = f"SELECT COUNT(*) as count FROM {table}"
        if where_clause:
            query += f" WHERE {where_clause}"

        result = await self.fetch_one(query, params)
        return result["count"] if result else 0

    async def delete_older_than(
        self,
        table: str,
        timestamp_column: str,
        days: int
    ) -> int:
        """Delete rows older than specified days. Returns count deleted."""
        query = f"""
            DELETE FROM {table}
            WHERE {timestamp_column} < datetime('now', '-{days} days')
        """

        async with self.connection() as db:
            cursor = await db.execute(query)
            await db.commit()
            return cursor.rowcount


def serialize_json(data: Optional[Dict[str, Any]]) -> Optional[str]:
    """Serialize a dict to JSON string for storage."""
    if data is None:
        return None
    return json.dumps(data)


def deserialize_json(data: Optional[str]) -> Optional[Dict[str, Any]]:
    """Deserialize a JSON string from storage."""
    if data is None:
        return None
    return json.loads(data)


# Singleton database instance
_db_instance: Optional[Database] = None


def get_database() -> Database:
    """Get the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance


async def initialize_database() -> Database:
    """Initialize and return the database instance."""
    db = get_database()
    await db.initialize()
    return db
