"""
GPT Actions schema generator.

Transforms the FastAPI-generated OpenAPI 3.1 schema into a format
compatible with OpenAI Custom GPT Actions requirements.
"""

import copy
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


def generate_gpt_schema(
    openapi_schema: Dict[str, Any],
    server_url: str = "https://your-server.example.com:8000",
    include_tags: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    max_description_length: int = 300
) -> Dict[str, Any]:
    """
    Transform FastAPI OpenAPI schema for GPT Actions compatibility.

    Modifications applied:
    1. Set servers array with deployment URL
    2. Ensure every path operation has an operationId
    3. Filter paths by tag and exclusion list
    4. Add API Key security scheme placeholder
    5. Truncate long descriptions to fit GPT schema size limits

    Args:
        openapi_schema: Raw OpenAPI schema from FastAPI
        server_url: The public URL where the API is deployed
        include_tags: Only include endpoints with these tags (None = all)
        exclude_paths: Paths to exclude from the schema
        max_description_length: Maximum description length before truncation

    Returns:
        GPT-compatible OpenAPI schema dict
    """
    schema = copy.deepcopy(openapi_schema)

    # 1. Set servers
    schema["servers"] = [{"url": server_url}]

    # 2. Add security scheme placeholder for Phase 5
    schema.setdefault("components", {})
    schema["components"]["securitySchemes"] = {
        "apiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for authentication"
        }
    }

    # 3. Filter paths
    default_excludes = [
        "/docs", "/redoc", "/openapi.json",
        "/gpt/openapi.json", "/gpt/instructions",
    ]
    all_excludes = set(default_excludes + (exclude_paths or []))

    filtered_paths = {}
    for path, methods in schema.get("paths", {}).items():
        if path in all_excludes:
            continue

        if include_tags:
            filtered_methods = {}
            for method, operation in methods.items():
                if method not in ("get", "post", "put", "delete", "patch"):
                    continue
                tags = operation.get("tags", [])
                if any(t in include_tags for t in tags):
                    filtered_methods[method] = operation
            if filtered_methods:
                filtered_paths[path] = filtered_methods
        else:
            filtered_paths[path] = methods

    schema["paths"] = filtered_paths

    # 4. Ensure operationId on every operation
    _ensure_operation_ids(schema)

    # 5. Add security requirement to all operations
    _add_security_to_operations(schema)

    # 6. Truncate long descriptions
    _truncate_descriptions(schema, max_length=max_description_length)

    return schema


def _add_security_to_operations(schema: Dict[str, Any]) -> None:
    """Add API key security requirement to all operations."""
    for path, methods in schema.get("paths", {}).items():
        for method, operation in methods.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            operation["security"] = [{"apiKey": []}]


def _ensure_operation_ids(schema: Dict[str, Any]) -> None:
    """Ensure every operation has an operationId."""
    seen_ids = set()
    for path, methods in schema.get("paths", {}).items():
        for method, operation in methods.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            if "operationId" not in operation:
                clean_path = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
                op_id = f"{method}_{clean_path}"
                # Ensure uniqueness
                counter = 1
                base_id = op_id
                while op_id in seen_ids:
                    op_id = f"{base_id}_{counter}"
                    counter += 1
                operation["operationId"] = op_id
                logger.debug(f"Generated operationId '{op_id}' for {method.upper()} {path}")
            seen_ids.add(operation["operationId"])


def _truncate_descriptions(schema: Dict[str, Any], max_length: int = 300) -> None:
    """Truncate descriptions to fit within GPT schema limits."""
    for path, methods in schema.get("paths", {}).items():
        for method, operation in methods.items():
            if method not in ("get", "post", "put", "delete", "patch"):
                continue
            desc = operation.get("description", "")
            if len(desc) > max_length:
                operation["description"] = desc[:max_length - 3] + "..."

    # Also truncate the top-level description
    if "info" in schema:
        desc = schema["info"].get("description", "")
        if len(desc) > max_length:
            schema["info"]["description"] = desc[:max_length - 3] + "..."
