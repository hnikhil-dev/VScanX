"""
VScanX Directory Enumeration Module
Discovers hidden directories and files
"""

import concurrent.futures
import logging
from typing import Any, Dict
from urllib.parse import urljoin, urlparse

from core.config import COMMON_DIRECTORIES, COMMON_FILES
from core.request_handler import RequestHandler
from modules.base_module import BaseModule


class DirectoryEnumerator(BaseModule):
    """
    Directory and file enumeration module
    Discovers common paths and files
    """

    def __init__(self, max_threads: int = 5, handler=None):
        super().__init__()
        self.name = "Directory Enumerator"
        self.description = (
            "Directory and file discovery with status code and size tracking"
        )
        self.version = "2.0.0"

        # Use provided handler or create new one
        self.handler = handler if handler else RequestHandler()

        self.max_threads = max_threads
        self.found_paths = []
        # Verbose flag (default False)
        self.verbose = False
        # Status codes indicating interesting responses
        self.interesting_codes = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found/Redirect",
            401: "Unauthorized",
            403: "Forbidden",
            500: "Internal Server Error",
        }

    def run(self, target: str, verbose: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Execute directory enumeration on target

        Args:
            target: Target URL
            verbose: Enable verbose output

        Returns:
            Dictionary with scan results
        """
        logger = logging.getLogger("vscanx.module.dir_enum")
        self.clear_results()
        self.found_paths = []
        self.verbose = verbose

        logger.info("dir_enum_start", extra={"target": target})

        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.debug(
            "dir_enum_counts",
            extra={"directories": len(COMMON_DIRECTORIES), "files": len(COMMON_FILES)},
        )

        # Test directories and files with threading
        all_paths = [f"{dir}/" for dir in COMMON_DIRECTORIES] + COMMON_FILES

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            futures = {
                executor.submit(self._test_path, base_url, path): path
                for path in all_paths
            }

            for future in concurrent.futures.as_completed(futures):
                path = futures[future]
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        logger.exception("Error testing %s: %s", path, e)

        if not self.found_paths:
            logger.info("dir_enum_none_found", extra={"target": target})
        else:
            logger.info(
                "dir_enum_found",
                extra={"target": target, "count": len(self.found_paths)},
            )

        self.handler.close()

        return {
            "module": self.name,
            "target": target,
            "found_paths": self.found_paths,
            "findings": self.get_results(),
        }

    def _test_path(self, base_url: str, path: str) -> None:
        """
        Test if a path exists
        Tracks status code, response size, and interesting findings

        Args:
            base_url: Base URL
            path: Path to test
        """
        full_url = urljoin(base_url, path)

        logger = logging.getLogger("vscanx.module.dir_enum")
        response = self.handler.get(full_url, allow_redirects=False)

        if not response:
            return

        status_code = response.status_code
        response_size = len(response.content)
        status_text = self.interesting_codes.get(status_code, "")

        # Flag as interesting if status code matches our list
        if status_code in self.interesting_codes:
            severity = "MEDIUM" if status_code in [200, 301, 302] else "LOW"

            # Special handling for sensitive files/directories
            sensitive_items = [
                ".env",
                ".git",
                "config.php",
                "config.xml",
                "web.config",
                "backup",
                "database.sql",
                "private",
                "secret",
                "admin",
                ".htaccess",
                ".htpasswd",
                "wp-admin",
                "wp-config.php",
            ]
            if any(sens in path.lower() for sens in sensitive_items):
                severity = "HIGH"

            # 401 Unauthorized suggests authentication required (potentially interesting)
            if status_code == 401:
                severity = "MEDIUM"

            # 403 Forbidden suggests path exists but access denied
            if status_code == 403:
                severity = "LOW"

            self.found_paths.append(
                {
                    "path": path,
                    "url": full_url,
                    "status": status_code,
                    "size": response_size,
                    "status_text": status_text,
                }
            )

            self.add_result(
                severity=severity,
                finding=f"Accessible path: {path}",
                details=f"Status: {status_code} {status_text} | Size: {response_size} bytes | URL: {full_url}",
                remediation="Review access controls and consider restricting unnecessary directories",
            )

            logger.info(
                "dir_enum_path",
                extra={"path": path, "status": status_code, "size": response_size},
            )
