"""
Crossplane-based NGINX configuration parser.

Provides full directive support including nested blocks, includes,
and upstream parsing. Replaces the regex-based parser for reliable
AI-agent-ready configuration parsing.
"""

import glob as glob_module
import logging
from datetime import datetime
from pathlib import Path

import crossplane

from models.nginx import (
    GeoBlock,
    ListenDirective,
    LocationBlock,
    MapBlock,
    ParsedNginxConfig,
    ServerBlock,
    SSLConfig,
    UpstreamBlock,
    UpstreamServer,
)

logger = logging.getLogger(__name__)


class CrossplaneParser:
    """Full-featured NGINX parser using crossplane library."""

    def __init__(self):
        """Initialize the parser with tracking for circular include detection."""
        self._parsing_files: set[str] = set()

    def parse_config_file(
        self,
        file_path: Path,
        resolve_includes: bool = False,
        _visited: set[str] | None = None,
    ) -> ParsedNginxConfig | None:
        """
        Parse a single NGINX configuration file.

        Args:
            file_path: Path to the .conf file
            resolve_includes: If True, recursively parse included files
            _visited: Internal set for circular include detection

        Returns:
            ParsedNginxConfig with full directive tree, or None if file not found
        """
        try:
            if not file_path.exists():
                logger.warning(f"Config file not found: {file_path}")
                return None

            # Convert to absolute path for consistent tracking
            abs_path = str(file_path.resolve())

            # Initialize visited set for circular include detection
            if _visited is None:
                _visited = set()

            # Check for circular includes
            if abs_path in _visited:
                logger.warning(f"Circular include detected: {abs_path}")
                return None

            _visited.add(abs_path)

            # Get file metadata
            stat = file_path.stat()

            # Parse with crossplane
            # check_ctx=False: Site configs in conf.d/ are fragments meant to be
            # included in http block, so context validation would fail
            # check_args=False: Allow flexible argument counts
            payload = crossplane.parse(
                str(file_path),
                catch_errors=True,
                check_ctx=False,
                check_args=False,
            )

            # Check for parse errors
            errors = payload.get("errors", [])
            status = "ok" if payload.get("status") != "failed" else "failed"

            if errors:
                logger.warning(f"Parse warnings in {file_path}: {errors}")

            # Process the parsed config
            server_blocks = []
            upstreams = []
            maps = []
            geos = []
            includes = []
            resolved_includes = []
            included_configs = []
            raw_directives = []

            for config in payload.get("config", []):
                file_errors = config.get("errors", [])
                if file_errors:
                    errors.extend(file_errors)

                parsed = config.get("parsed", [])
                raw_directives.extend(parsed)

                # Recursively extract all include patterns from the directive tree
                self._extract_includes_recursive(parsed, includes)

                for directive in parsed:
                    directive_name = directive.get("directive", "")

                    if directive_name == "server":
                        block = directive.get("block", [])
                        line = directive.get("line", 0)
                        server_block = self._parse_server_block(block, line)
                        server_blocks.append(server_block)

                    elif directive_name == "upstream":
                        args = directive.get("args", [])
                        block = directive.get("block", [])
                        line = directive.get("line", 0)
                        if args:
                            upstream = self._parse_upstream_block(args[0], block, line)
                            upstreams.append(upstream)

                    elif directive_name == "map":
                        args = directive.get("args", [])
                        block = directive.get("block", [])
                        line = directive.get("line", 0)
                        map_block = self._parse_map_block(args, block, line)
                        maps.append(map_block)

                    elif directive_name == "geo":
                        args = directive.get("args", [])
                        block = directive.get("block", [])
                        line = directive.get("line", 0)
                        geo_block = self._parse_geo_block(args, block, line)
                        geos.append(geo_block)

                    # Note: includes are extracted via _extract_includes_recursive above,
                    # so we don't need to handle them again here

            # Resolve includes if requested (process all collected includes)
            if resolve_includes and includes:
                for include_pattern in includes:
                    resolved_files = self._resolve_include_pattern(include_pattern, file_path.parent)
                    resolved_includes.extend(resolved_files)

                    # Parse included files
                    for resolved_file in resolved_files:
                        included_config = self.parse_config_file(
                            Path(resolved_file),
                            resolve_includes=True,
                            _visited=_visited,
                        )
                        if included_config:
                            included_configs.append(included_config)

            return ParsedNginxConfig(
                file_path=str(file_path),
                file_size=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_ctime),
                updated_at=datetime.fromtimestamp(stat.st_mtime),
                status=status,
                errors=errors,
                server_blocks=server_blocks,
                upstreams=upstreams,
                maps=maps,
                geos=geos,
                includes=includes,
                resolved_includes=resolved_includes,
                included_configs=included_configs,
                raw_directives=raw_directives,
            )

        except Exception as e:
            logger.error(f"Error parsing config file {file_path}: {e}")
            return None

    def _extract_includes_recursive(self, directives: list[dict], includes: list[str]) -> None:
        """
        Recursively extract all include patterns from a directive tree.

        Args:
            directives: List of directive dictionaries
            includes: List to append found include patterns to
        """
        for directive in directives:
            directive_name = directive.get("directive", "")
            args = directive.get("args", [])

            if directive_name == "include" and args:
                include_pattern = args[0]
                if include_pattern not in includes:
                    includes.append(include_pattern)

            # Recurse into nested blocks
            block = directive.get("block", [])
            if block:
                self._extract_includes_recursive(block, includes)

    def _resolve_include_pattern(self, pattern: str, base_dir: Path) -> list[str]:
        """
        Resolve an include pattern to actual file paths.

        Handles glob patterns like *.conf, /etc/nginx/conf.d/*.conf, etc.

        Args:
            pattern: Include pattern (may contain wildcards)
            base_dir: Base directory for relative paths

        Returns:
            List of resolved absolute file paths
        """
        resolved = []

        # Handle relative paths
        if not pattern.startswith("/"):
            pattern = str(base_dir / pattern)

        # Expand glob patterns
        matched_files = glob_module.glob(pattern)

        # Sort for deterministic ordering
        matched_files.sort()

        for file_path in matched_files:
            path = Path(file_path)
            if path.is_file():
                resolved.append(str(path.resolve()))
            else:
                logger.debug(f"Include pattern matched non-file: {file_path}")

        if not matched_files:
            logger.debug(f"Include pattern matched no files: {pattern}")

        return resolved

    def _parse_map_block(self, args: list[str], block: list[dict], line: int) -> MapBlock:
        """
        Parse a map directive block.

        map $uri $new_uri {
            default 0;
            ~^/old/ /new/;
            /exact /replacement;
        }
        """
        source_variable = args[0] if args else ""
        target_variable = args[1] if len(args) > 1 else ""
        default = None
        hostnames = False
        volatile = False
        mappings = {}

        for directive in block:
            name = directive.get("directive", "")
            directive_args = directive.get("args", [])

            if name == "default":
                default = directive_args[0] if directive_args else None
            elif name == "hostnames":
                hostnames = True
            elif name == "volatile":
                volatile = True
            elif name == "include":
                # Map blocks can include external mapping files
                # We store them but don't resolve here (would need separate parsing)
                pass
            else:
                # Regular mapping: key value
                # In crossplane, mappings are parsed as directives where
                # the key is the directive name and value is in args
                if directive_args:
                    mappings[name] = directive_args[0]
                else:
                    # Some patterns like "~*\.jpg$" might have no explicit value
                    mappings[name] = ""

        return MapBlock(
            source_variable=source_variable,
            target_variable=target_variable,
            default=default,
            hostnames=hostnames,
            volatile=volatile,
            mappings=mappings,
            line=line,
        )

    def _parse_geo_block(self, args: list[str], block: list[dict], line: int) -> GeoBlock:
        """
        Parse a geo directive block.

        geo $remote_addr $geo_country {
            default unknown;
            127.0.0.1/32 local;
            10.0.0.0/8 private;
            proxy 192.168.1.1;
            delete 192.168.0.0/16;
        }
        """
        # geo directive can have 1 or 2 args:
        # geo $var { ... } - uses $remote_addr as source
        # geo $source $var { ... } - explicit source variable
        source_variable = None
        target_variable = ""

        if len(args) == 1:
            target_variable = args[0]
        elif len(args) >= 2:
            source_variable = args[0]
            target_variable = args[1]

        default = None
        delete_networks = []
        proxy_addresses = []
        proxy_recursive = False
        ranges = False
        mappings = {}
        geo_includes = []

        for directive in block:
            name = directive.get("directive", "")
            directive_args = directive.get("args", [])

            if name == "default":
                default = directive_args[0] if directive_args else None
            elif name == "delete":
                if directive_args:
                    delete_networks.append(directive_args[0])
            elif name == "proxy":
                if directive_args:
                    proxy_addresses.append(directive_args[0])
            elif name == "proxy_recursive":
                proxy_recursive = True
            elif name == "ranges":
                ranges = True
            elif name == "include":
                if directive_args:
                    geo_includes.append(directive_args[0])
            else:
                # Network/address to value mapping
                if directive_args:
                    mappings[name] = directive_args[0]
                else:
                    mappings[name] = ""

        return GeoBlock(
            source_variable=source_variable,
            target_variable=target_variable,
            default=default,
            delete=delete_networks,
            proxy=proxy_addresses,
            proxy_recursive=proxy_recursive,
            ranges=ranges,
            mappings=mappings,
            includes=geo_includes,
            line=line,
        )

    def _parse_server_block(self, block: list[dict], line: int) -> ServerBlock:
        """Extract structured ServerBlock from raw directives."""
        server_names = []
        listen_directives = []
        locations = []
        error_pages = {}
        root = None
        index = None
        access_log = None
        error_log = None
        other_directives = {}

        # SSL-related directives to extract
        ssl_cert = None
        ssl_key = None
        ssl_trusted = None
        ssl_protocols = []
        ssl_ciphers = None
        ssl_prefer_server_ciphers = False
        ssl_session_cache = None
        ssl_session_timeout = None
        ssl_enabled = False

        for directive in block:
            name = directive.get("directive", "")
            args = directive.get("args", [])
            directive_line = directive.get("line", 0)

            if name == "server_name":
                server_names.extend(args)

            elif name == "listen":
                listen_dir = self._parse_listen_directive(args)
                listen_directives.append(listen_dir)
                if listen_dir.ssl:
                    ssl_enabled = True

            elif name == "location":
                loc_block = directive.get("block", [])
                location = self._parse_location_block(args, loc_block, directive_line)
                locations.append(location)

            elif name == "root":
                root = args[0] if args else None

            elif name == "index":
                index = args

            elif name == "access_log":
                access_log = args[0] if args else None

            elif name == "error_log":
                error_log = args[0] if args else None

            elif name == "error_page":
                # error_page 404 /404.html; or error_page 500 502 503 504 /50x.html;
                if len(args) >= 2:
                    page_path = args[-1]
                    for code in args[:-1]:
                        try:
                            error_pages[int(code)] = page_path
                        except ValueError:
                            pass

            # SSL directives
            elif name == "ssl_certificate":
                ssl_cert = args[0] if args else None
                ssl_enabled = True

            elif name == "ssl_certificate_key":
                ssl_key = args[0] if args else None

            elif name == "ssl_trusted_certificate":
                ssl_trusted = args[0] if args else None

            elif name == "ssl_protocols":
                ssl_protocols = args

            elif name == "ssl_ciphers":
                ssl_ciphers = args[0] if args else None

            elif name == "ssl_prefer_server_ciphers":
                ssl_prefer_server_ciphers = args[0].lower() == "on" if args else False

            elif name == "ssl_session_cache":
                ssl_session_cache = " ".join(args) if args else None

            elif name == "ssl_session_timeout":
                ssl_session_timeout = args[0] if args else None

            elif name == "ssl":
                # Standalone 'ssl on;' directive (deprecated but may exist)
                ssl_enabled = args[0].lower() == "on" if args else False

            else:
                # Store other directives
                if args:
                    other_directives[name] = args[0] if len(args) == 1 else args

        ssl_config = SSLConfig(
            enabled=ssl_enabled,
            certificate=ssl_cert,
            certificate_key=ssl_key,
            trusted_certificate=ssl_trusted,
            protocols=ssl_protocols,
            ciphers=ssl_ciphers,
            prefer_server_ciphers=ssl_prefer_server_ciphers,
            session_cache=ssl_session_cache,
            session_timeout=ssl_session_timeout,
        )

        return ServerBlock(
            server_names=server_names,
            listen=listen_directives,
            ssl=ssl_config,
            root=root,
            index=index,
            locations=locations,
            error_pages=error_pages,
            access_log=access_log,
            error_log=error_log,
            directives=other_directives,
            line=line,
        )

    def _parse_location_block(self, args: list[str], block: list[dict], line: int) -> LocationBlock:
        """Extract LocationBlock from location directive."""
        # Parse location modifier and path
        modifier = None
        path = "/"

        if len(args) == 1:
            path = args[0]
        elif len(args) >= 2:
            # Check if first arg is a modifier
            if args[0] in ("=", "~", "~*", "^~"):
                modifier = args[0]
                path = args[1] if len(args) > 1 else "/"
            else:
                path = args[0]

        proxy_pass = None
        root = None
        alias = None
        index = None
        try_files = None
        return_code = None
        return_value = None
        rewrite_rules = []
        headers = {}
        other_directives = {}

        for directive in block:
            name = directive.get("directive", "")
            directive_args = directive.get("args", [])

            if name == "proxy_pass":
                proxy_pass = directive_args[0] if directive_args else None

            elif name == "root":
                root = directive_args[0] if directive_args else None

            elif name == "alias":
                alias = directive_args[0] if directive_args else None

            elif name == "index":
                index = directive_args

            elif name == "try_files":
                try_files = " ".join(directive_args) if directive_args else None

            elif name == "return":
                if directive_args:
                    try:
                        return_code = int(directive_args[0])
                        return_value = directive_args[1] if len(directive_args) > 1 else None
                    except ValueError:
                        # Non-numeric return (e.g., return $scheme://...)
                        return_value = " ".join(directive_args)

            elif name == "rewrite":
                rewrite_rules.append(
                    {
                        "pattern": directive_args[0] if directive_args else None,
                        "replacement": directive_args[1] if len(directive_args) > 1 else None,
                        "flag": directive_args[2] if len(directive_args) > 2 else None,
                    }
                )

            elif name in ("proxy_set_header", "add_header"):
                if len(directive_args) >= 2:
                    headers[directive_args[0]] = directive_args[1]

            else:
                if directive_args:
                    other_directives[name] = directive_args[0] if len(directive_args) == 1 else directive_args

        return LocationBlock(
            modifier=modifier,
            path=path,
            proxy_pass=proxy_pass,
            root=root,
            alias=alias,
            index=index,
            try_files=try_files,
            return_code=return_code,
            return_value=return_value,
            rewrite_rules=rewrite_rules,
            headers=headers,
            directives=other_directives,
            line=line,
        )

    def _parse_upstream_block(self, name: str, block: list[dict], line: int) -> UpstreamBlock:
        """Extract UpstreamBlock from upstream directive."""
        servers = []
        load_balancing = None
        keepalive = None

        for directive in block:
            directive_name = directive.get("directive", "")
            args = directive.get("args", [])

            if directive_name == "server":
                server = self._parse_upstream_server(args)
                servers.append(server)

            elif directive_name in ("ip_hash", "least_conn", "random", "hash"):
                load_balancing = directive_name
                if args:
                    load_balancing = f"{directive_name} {' '.join(args)}"

            elif directive_name == "keepalive":
                try:
                    keepalive = int(args[0]) if args else None
                except ValueError:
                    pass

        return UpstreamBlock(
            name=name,
            servers=servers,
            load_balancing=load_balancing,
            keepalive=keepalive,
            line=line,
        )

    def _parse_upstream_server(self, args: list[str]) -> UpstreamServer:
        """Parse upstream server directive arguments."""
        address = args[0] if args else ""
        weight = None
        max_fails = None
        fail_timeout = None
        backup = False
        down = False

        # Parse additional parameters
        for _i, arg in enumerate(args[1:], 1):
            if arg.startswith("weight="):
                try:
                    weight = int(arg.split("=")[1])
                except (ValueError, IndexError):
                    pass
            elif arg.startswith("max_fails="):
                try:
                    max_fails = int(arg.split("=")[1])
                except (ValueError, IndexError):
                    pass
            elif arg.startswith("fail_timeout="):
                fail_timeout = arg.split("=")[1]
            elif arg == "backup":
                backup = True
            elif arg == "down":
                down = True

        return UpstreamServer(
            address=address,
            weight=weight,
            max_fails=max_fails,
            fail_timeout=fail_timeout,
            backup=backup,
            down=down,
        )

    def _parse_listen_directive(self, args: list[str]) -> ListenDirective:
        """Parse listen directive arguments into structured form."""
        port = 80
        address = None
        ssl = False
        http2 = False
        default_server = False

        if not args:
            return ListenDirective(
                port=port, address=address, ssl=ssl, http2=http2, default_server=default_server, raw_args=args
            )

        first_arg = args[0]

        # Parse address:port or just port
        if first_arg.startswith("["):
            # IPv6: [::]:80 or [::1]:80
            if "]:" in first_arg:
                parts = first_arg.split("]:")
                address = parts[0] + "]"
                try:
                    port = int(parts[1])
                except ValueError:
                    pass
            else:
                # Just [::] without port
                address = first_arg
        elif ":" in first_arg and not first_arg.startswith("unix:"):
            # IPv4 with port: 127.0.0.1:8080
            parts = first_arg.rsplit(":", 1)
            address = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        elif first_arg.startswith("unix:"):
            # Unix socket
            address = first_arg
            port = 0
        else:
            # Just port number
            try:
                port = int(first_arg)
            except ValueError:
                pass

        # Parse flags
        for arg in args[1:]:
            arg_lower = arg.lower()
            if arg_lower == "ssl":
                ssl = True
            elif arg_lower == "http2":
                http2 = True
            elif arg_lower == "default_server":
                default_server = True

        return ListenDirective(
            port=port,
            address=address,
            ssl=ssl,
            http2=http2,
            default_server=default_server,
            raw_args=args,
        )


# Global parser instance
nginx_parser = CrossplaneParser()
