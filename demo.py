#!/usr/bin/env python3
"""
Demo script that simulates the crawler output without actually crawling.
Useful for testing the display format.
"""

import time
import random
from colorama import init, Fore, Style

init(autoreset=True)

# Sample URLs for demo
SECURE_URLS = [
    "https://en.wikipedia.org/wiki/Python_(programming_language)",
    "https://github.com/python/cpython",
    "https://docs.python.org/3/tutorial/",
    "https://stackoverflow.com/questions/tagged/python",
    "https://realpython.com",
    "https://www.python.org/dev/peps/pep-0020/",
    "https://pypi.org/project/requests/",
    "https://flask.palletsprojects.com",
    "https://fastapi.tiangolo.com",
    "https://www.djangoproject.com",
    "https://docs.docker.com",
    "https://kubernetes.io/docs",
    "https://aws.amazon.com/documentation/",
    "https://cloud.google.com/docs",
    "https://azure.microsoft.com/en-us/documentation/",
]

INSECURE_URLS = [
    "http://legacy-system.company.local",
    "http://old-api.example.com/v1",
    "http://test-server.internal/dashboard",
    "http://staging.unsecured.com",
    "http://dev.localhost:8080",
]

def print_banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                    🔒 WEB SECURITY CRAWLER 🔒                         ║
║                                                                      ║
║  DEMO MODE - Simulating crawl output                                 ║
║  🟢 SECURE = HTTPS  |  🔴 INSECURE = HTTP                           ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}Press Ctrl+C to stop.{Style.RESET_ALL}
{Fore.CYAN}{"─"*80}{Style.RESET_ALL}
""")

def simulate_crawl():
    print_banner()

    secure_count = 0
    insecure_count = 0

    try:
        while True:
            # Randomly choose secure or insecure
            if random.random() > 0.15:  # 85% secure
                url = random.choice(SECURE_URLS)
                label = f"{Fore.GREEN}🟢 SECURE{Style.RESET_ALL}"
                secure_count += 1
            else:
                url = random.choice(INSECURE_URLS)
                label = f"{Fore.RED}🔴 INSECURE{Style.RESET_ALL}"
                insecure_count += 1

            # Simulate status code
            status = random.choice([200, 200, 200, 301, 302, 404, 500])
            status_str = f" [{status}]" if random.random() > 0.3 else ""

            # Print crawl line
            print(f"[{time.strftime('%H:%M:%S')}] {label}{status_str} {Fore.CYAN}{url}{Style.RESET_ALL}")

            # Print stats line
            total = secure_count + insecure_count
            secure_pct = (secure_count / total * 100) if total > 0 else 0
            stats = (
                f"{Fore.CYAN}│ Stats:{Style.RESET_ALL} "
                f"{Fore.GREEN}Secure: {secure_count} ({secure_pct:.1f}%){Style.RESET_ALL}  "
                f"{Fore.RED}Insecure: {insecure_count}{Style.RESET_ALL}  "
                f"Total: {total}"
            )
            print(f"\r{stats:<80}", end="", flush=True)

            # Random delay between 0.5 and 2 seconds
            time.sleep(random.uniform(0.5, 2.0))

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Demo stopped by user.{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Final Stats:{Style.RESET_ALL}")
        print(f"  Total: {secure_count + insecure_count}")
        print(f"  {Fore.GREEN}Secure: {secure_count}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Insecure: {insecure_count}{Style.RESET_ALL}")

if __name__ == "__main__":
    simulate_crawl()
