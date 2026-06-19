#!/usr/bin/env python3
"""
Web Security Crawler - Live Terminal Web Discovery Tool

A breadth-first web crawler that discovers websites in real-time,
labels them by security (HTTP/HTTPS), and logs all findings.

Author: CursBNR Security Tools
License: MIT
"""

import sys
import time
import signal
import threading
import urllib.parse
import urllib.robotparser
from collections import deque
from datetime import datetime
from typing import Set, Optional
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


@dataclass
class CrawlResult:
    """Represents a discovered URL with its security status and metadata."""
    url: str
    is_secure: bool
    status_code: Optional[int] = None
    title: Optional[str] = None
    depth: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None
    content_type: Optional[str] = None
    server: Optional[str] = None

    @property
    def security_label(self) -> str:
        """Returns colored security label for terminal display."""
        if self.is_secure:
            return f"{Fore.GREEN}🟢 SECURE{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}🔴 INSECURE{Style.RESET_ALL}"

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        return urllib.parse.urlparse(self.url).netloc

    def __str__(self) -> str:
        """Format for terminal display."""
        status = f" [{self.status_code}]" if self.status_code else ""
        title = f" | {self.title[:50]}..." if self.title and len(self.title) > 50 else f" | {self.title}" if self.title else ""
        error = f" {Fore.YELLOW}[{self.error}]{Style.RESET_ALL}" if self.error else ""
        return f"[{self.timestamp.split('T')[1].split('.')[0]}] {self.security_label}{status} {Fore.CYAN}{self.url}{Style.RESET_ALL}{title}{error}"


class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm."""

    def __init__(self, max_requests: float = 2.0, per_seconds: float = 1.0):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.tokens = max_requests
        self.last_update = time.time()
        self._lock = threading.Lock()

    def acquire(self):
        """Wait until a token is available."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.max_requests, self.tokens + elapsed * (self.max_requests / self.per_seconds))
            self.last_update = now

            if self.tokens < 1:
                sleep_time = (1 - self.tokens) * (self.per_seconds / self.max_requests)
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class WebSecurityCrawler:
    """
    Breadth-first web crawler with security labeling.

    Features:
    - Real-time terminal logging with color-coded security labels
    - Duplicate detection and avoidance
    - Error handling and recovery
    - Rate limiting to avoid being blocked
    - Multithreaded crawling for speed
    - robots.txt compliance
    - Graceful shutdown on Ctrl+C
    """

    # Default seed URLs for crawling
    DEFAULT_SEEDS = [
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://www.bbc.com",
        "https://www.reddit.com",
        "https://news.ycombinator.com",
        "https://github.com/explore",
        "https://stackoverflow.com/questions",
        "https://www.nytimes.com",
        "https://www.theguardian.com",
        "https://medium.com",
        "https://dev.to",
    ]

    # Request headers to appear as a legitimate browser
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    def __init__(
        self,
        seeds: Optional[list] = None,
        max_depth: int = 3,
        max_workers: int = 5,
        rate_limit: float = 2.0,
        timeout: int = 10,
        output_file: str = "websites.txt",
        respect_robots: bool = True,
        same_domain_only: bool = False,
    ):
        self.seeds = seeds or self.DEFAULT_SEEDS
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.timeout = timeout
        self.output_file = output_file
        self.respect_robots = respect_robots
        self.same_domain_only = same_domain_only

        # Thread-safe data structures
        self.visited: Set[str] = set()
        self.visited_lock = threading.Lock()
        self.queue: deque = deque()
        self.queue_lock = threading.Lock()
        self.file_lock = threading.Lock()

        # Statistics
        self.stats = {
            "secure": 0,
            "insecure": 0,
            "errors": 0,
            "total": 0,
        }
        self.stats_lock = threading.Lock()

        # Rate limiter
        self.rate_limiter = RateLimiter(max_requests=rate_limit, per_seconds=1.0)

        # robots.txt parsers cache
        self.robot_parsers: dict = {}

        # Shutdown flag
        self.running = True

        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

        # Initialize output file
        self._init_output_file()

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n{Fore.YELLOW}⚠️  Shutdown signal received. Finishing current tasks...{Style.RESET_ALL}")
        self.running = False

    def _init_output_file(self):
        """Initialize or append to the output file."""
        with self.file_lock:
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"Web Security Crawl Session - {datetime.now().isoformat()}\n")
                f.write(f"{'='*80}\n\n")

    def _is_allowed_by_robots(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if not self.respect_robots:
            return True

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        if base_url not in self.robot_parsers:
            try:
                rp = urllib.robotparser.RobotFileParser()
                rp.set_url(f"{base_url}/robots.txt")
                rp.read()
                self.robot_parsers[base_url] = rp
            except Exception:
                return True

        return self.robot_parsers[base_url].can_fetch("*", url)

    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate a URL."""
        try:
            # Handle relative URLs
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                parsed_base = urllib.parse.urlparse(base_url)
                url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            elif not url.startswith(("http://", "https://")):
                return None

            # Parse and clean
            parsed = urllib.parse.urlparse(url)

            # Skip non-HTTP protocols
            if parsed.scheme not in ("http", "https"):
                return None

            # Skip common non-content URLs
            skip_extensions = (
                ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".css", ".js",
                ".svg", ".ico", ".mp4", ".mp3", ".zip", ".tar", ".gz",
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            )
            if parsed.path.lower().endswith(skip_extensions):
                return None

            # Skip fragments and common non-page paths
            if parsed.fragment and not parsed.path:
                return None

            # Normalize: remove fragment, default port, trailing slash
            netloc = parsed.netloc.lower()
            if ":" in netloc:
                host, port = netloc.rsplit(":", 1)
                if (parsed.scheme == "http" and port == "80") or                    (parsed.scheme == "https" and port == "443"):
                    netloc = host

            path = parsed.path.rstrip("/") or "/"

            # Reconstruct clean URL
            clean_url = f"{parsed.scheme}://{netloc}{path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"

            return clean_url

        except Exception:
            return None

    def _is_duplicate(self, url: str) -> bool:
        """Thread-safe duplicate check."""
        with self.visited_lock:
            if url in self.visited:
                return True
            self.visited.add(url)
            return False

    def _extract_links(self, html: str, base_url: str) -> list:
        """Extract all valid links from HTML content."""
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                normalized = self._normalize_url(href, base_url)
                if normalized:
                    links.append(normalized)
        except Exception as e:
            pass
        return links

    def _fetch_page(self, url: str) -> tuple:
        """Fetch a page and return (html_content, response_headers, error)."""
        try:
            self.rate_limiter.acquire()

            response = requests.get(
                url,
                headers=self.HEADERS,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )

            # Only process HTML content
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                return None, response.headers, None

            # Limit content size to avoid memory issues
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 5 * 1024 * 1024:  # 5MB limit
                    break

            html = content.decode("utf-8", errors="ignore")
            return html, response.headers, None

        except requests.exceptions.Timeout:
            return None, None, "TIMEOUT"
        except requests.exceptions.ConnectionError:
            return None, None, "CONNECTION_ERROR"
        except requests.exceptions.TooManyRedirects:
            return None, None, "TOO_MANY_REDIRECTS"
        except requests.exceptions.RequestException as e:
            return None, None, str(e)[:50]
        except Exception as e:
            return None, None, str(e)[:50]

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML."""
        try:
            soup = BeautifulSoup(html, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                return title_tag.get_text(strip=True)
        except Exception:
            pass
        return None

    def _save_result(self, result: CrawlResult):
        """Thread-safe save to file."""
        with self.file_lock:
            with open(self.output_file, "a", encoding="utf-8") as f:
                status = "SECURE" if result.is_secure else "INSECURE"
                line = f"[{status}] {result.url}"
                if result.title:
                    line += f" | {result.title}"
                if result.error:
                    line += f" | ERROR: {result.error}"
                f.write(line + "\n")

    def _print_banner(self):
        """Print startup banner."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                    🔒 WEB SECURITY CRAWLER 🔒                         ║
║                                                                      ║
║  Discovers websites in real-time and labels them by security         ║
║  🟢 SECURE = HTTPS  |  🔴 INSECURE = HTTP                           ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Configuration:{Style.RESET_ALL}
  • Max Depth: {self.max_depth}
  • Workers: {self.max_workers}
  • Rate Limit: {self.rate_limiter.max_requests} req/sec
  • Output: {self.output_file}
  • Seeds: {len(self.seeds)} starting URLs

{Fore.GREEN}Press Ctrl+C to stop crawling gracefully.{Style.RESET_ALL}
{Fore.CYAN}{"─"*80}{Style.RESET_ALL}
"""
        print(banner)

    def _print_stats(self):
        """Print crawling statistics."""
        with self.stats_lock:
            total = self.stats["total"]
            secure = self.stats["secure"]
            insecure = self.stats["insecure"]
            errors = self.stats["errors"]

            secure_pct = (secure / total * 100) if total > 0 else 0

            stats_line = (
                f"{Fore.CYAN}│ Stats:{Style.RESET_ALL} "
                f"{Fore.GREEN}Secure: {secure} ({secure_pct:.1f}%){Style.RESET_ALL}  "
                f"{Fore.RED}Insecure: {insecure}{Style.RESET_ALL}  "
                f"{Fore.YELLOW}Errors: {errors}{Style.RESET_ALL}  "
                f"Total: {total}  "
                f"Queue: {len(self.queue)}{Style.RESET_ALL}"
            )
            print(f"\r{stats_line:<80}", end="", flush=True)

    def _crawl_url(self, url: str, depth: int):
        """Crawl a single URL and process results."""
        if not self.running:
            return

        # Skip if already visited
        if self._is_duplicate(url):
            return

        # Check robots.txt
        if not self._is_allowed_by_robots(url):
            return

        # Determine security status
        is_secure = url.startswith("https://")

        # Fetch page
        html, headers, error = self._fetch_page(url)

        # Create result
        result = CrawlResult(
            url=url,
            is_secure=is_secure,
            status_code=None,
            title=None,
            depth=depth,
            error=error,
        )

        if html and headers:
            result.status_code = 200
            result.title = self._extract_title(html)
            result.content_type = headers.get("Content-Type")
            result.server = headers.get("Server")

            # Extract and queue new links
            if depth < self.max_depth:
                links = self._extract_links(html, url)
                with self.queue_lock:
                    for link in links:
                        if not self.same_domain_only or                            urllib.parse.urlparse(link).netloc == urllib.parse.urlparse(url).netloc:
                            self.queue.append((link, depth + 1))

        # Update stats
        with self.stats_lock:
            self.stats["total"] += 1
            if result.is_secure:
                self.stats["secure"] += 1
            else:
                self.stats["insecure"] += 1
            if result.error:
                self.stats["errors"] += 1

        # Print and save
        print(f"\n{result}")
        self._save_result(result)
        self._print_stats()

    def _worker(self):
        """Worker thread that processes URLs from the queue."""
        while self.running:
            try:
                with self.queue_lock:
                    if not self.queue:
                        time.sleep(0.1)
                        continue
                    url, depth = self.queue.popleft()

                self._crawl_url(url, depth)

            except Exception as e:
                pass

    def start(self):
        """Start the crawler with all workers."""
        self._print_banner()

        # Initialize queue with seeds
        for seed in self.seeds:
            normalized = self._normalize_url(seed, seed)
            if normalized:
                self.queue.append((normalized, 0))

        # Start worker threads
        threads = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for all threads to finish
        try:
            while self.running:
                time.sleep(0.5)

                # Check if queue is empty and all workers idle
                with self.queue_lock:
                    if len(self.queue) == 0:
                        # Give workers time to finish
                        time.sleep(2)
                        with self.queue_lock:
                            if len(self.queue) == 0:
                                print(f"\n{Fore.GREEN}✅ Crawl complete! Queue exhausted.{Style.RESET_ALL}")
                                self.running = False
                                break

        except KeyboardInterrupt:
            pass

        finally:
            self.running = False
            print(f"\n{Fore.CYAN}Waiting for workers to finish...{Style.RESET_ALL}")
            for t in threads:
                t.join(timeout=5)

            self._print_final_stats()

    def _print_final_stats(self):
        """Print final statistics."""
        with self.stats_lock:
            total = self.stats["total"]
            secure = self.stats["secure"]
            insecure = self.stats["insecure"]
            errors = self.stats["errors"]

            secure_pct = (secure / total * 100) if total > 0 else 0

            print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                         📊 CRAWL COMPLETE 📊                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total Discovered:  {total:>6}                                          ║
║  🟢 Secure (HTTPS):  {secure:>6}  ({secure_pct:>5.1f}%)                              ║
║  🔴 Insecure (HTTP): {insecure:>6}  ({100-secure_pct:>5.1f}%)                              ║
║  ⚠️  Errors:         {errors:>6}                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Results saved to: {self.output_file:<45} ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def main():
    """Main entry point with CLI argument parsing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Web Security Crawler - Discover and label websites by security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crawler.py                          # Start with default seeds
  python crawler.py -s https://example.com   # Use custom seed
  python crawler.py -d 5 -w 10             # Deep crawl with 10 workers
  python crawler.py --same-domain            # Stay within seed domains
        """
    )

    parser.add_argument(
        "-s", "--seeds",
        nargs="+",
        help="Custom seed URLs to start crawling from"
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=5,
        help="Number of worker threads (default: 5)"
    )
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=2.0,
        help="Max requests per second (default: 2.0)"
    )
    parser.add_argument(
        "-o", "--output",
        default="websites.txt",
        help="Output file path (default: websites.txt)"
    )
    parser.add_argument(
        "--same-domain",
        action="store_true",
        help="Only crawl within the same domain as seeds"
    )
    parser.add_argument(
        "--no-robots",
        action="store_true",
        help="Ignore robots.txt (not recommended)"
    )

    args = parser.parse_args()

    # Create crawler instance
    crawler = WebSecurityCrawler(
        seeds=args.seeds,
        max_depth=args.depth,
        max_workers=args.workers,
        rate_limit=args.rate,
        output_file=args.output,
        respect_robots=not args.no_robots,
        same_domain_only=args.same_domain,
    )

    # Start crawling
    crawler.start()


if __name__ == "__main__":
    main()
