"""
VScanX Directory Enumeration Module
Discovers hidden directories and files
"""

import concurrent.futures
import asyncio
import logging
from typing import Any, Dict
from urllib.parse import urljoin, urlparse

from core.config import (
    COMMON_DIRECTORIES,
    COMMON_FILES,
    DIR_ENUM_DEFAULT_EXTENSIONS,
    DIR_ENUM_MAX_RECURSION_DEPTH,
)
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
        self.recursive = False
        self.max_depth = DIR_ENUM_MAX_RECURSION_DEPTH
        self.extensions = DIR_ENUM_DEFAULT_EXTENSIONS
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

        return {
            "module": self.name,
            "target": target,
            "found_paths": self.found_paths,
            "findings": self.get_results(),
        }

    async def run_async(
        self, target: str, verbose: bool = False, **kwargs
    ) -> Dict[str, Any]:
        """Async directory enumeration with bounded concurrency and optional recursion."""
        self.clear_results()
        self.found_paths = []
        self.verbose = verbose
        self.recursive = bool(kwargs.get("recursive", False))
        self.max_depth = int(kwargs.get("max_depth", DIR_ENUM_MAX_RECURSION_DEPTH))
        self.extensions = list(kwargs.get("extensions", DIR_ENUM_DEFAULT_EXTENSIONS))
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        all_paths = self._expand_paths([f"{dir}/" for dir in COMMON_DIRECTORIES] + COMMON_FILES)
        semaphore = asyncio.Semaphore(max(1, self.max_threads))

        async def worker(path: str) -> None:
            async with semaphore:
                await self._test_path_async(base_url, path)

        await asyncio.gather(*(worker(path) for path in all_paths))

        if self.recursive:
            await self._recurse_async(base_url, semaphore)
        return {
            "module": self.name,
            "target": target,
            "found_paths": self.found_paths,
            "findings": self.get_results(),
        }

    def _expand_paths(self, paths):
        expanded = []
        for p in paths:
            if p.endswith("/") or "." in p.split("/")[-1]:
                expanded.append(p)
                continue
            for ext in self.extensions:
                expanded.append(f"{p}{ext}")
        return list(dict.fromkeys(expanded))

    async def _recurse_async(self, base_url: str, semaphore: asyncio.Semaphore) -> None:
        """BFS recursion into discovered directories up to max_depth."""
        dirs = []
        for fp in self.found_paths:
            path = fp.get("path", "")
            status = fp.get("status")
            if status in [200, 401, 403] and path.endswith("/"):
                dirs.append(path)
        seen = set(dirs)
        frontier = [(d, 1) for d in dirs]

        async def worker_dir(dir_path: str, depth: int):
            if depth > self.max_depth:
                return
            candidates = self._expand_paths(
                [f"{dir_path}{d}/" for d in COMMON_DIRECTORIES[:25]]
                + [f"{dir_path}{f}" for f in COMMON_FILES[:25]]
            )
            async def limited_test(c):
                async with semaphore:
                    await self._test_path_async(base_url, c)
            await asyncio.gather(*(limited_test(c) for c in candidates))

        while frontier:
            current, depth = frontier.pop(0)
            await worker_dir(current, depth)
            for fp in self.found_paths:
                p = fp.get("path", "")
                status = fp.get("status")
                if status in [200, 401, 403] and p.endswith("/") and p not in seen and depth + 1 <= self.max_depth:
                    seen.add(p)
                    frontier.append((p, depth + 1))

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

    async def _test_path_async(self, base_url: str, path: str) -> None:
        full_url = urljoin(base_url, path)
        response = await self.handler.async_get(full_url, allow_redirects=False)
        if not response:
            return

        status_code = response.status_code
        response_size = len(response.content)
        status_text = self.interesting_codes.get(status_code, "")
        if status_code in self.interesting_codes:
            severity = "MEDIUM" if status_code in [200, 301, 302] else "LOW"
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
            if status_code == 401:
                severity = "MEDIUM"
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
