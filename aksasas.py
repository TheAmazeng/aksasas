import requests
import threading
import urllib.parse
import time
from mitmproxy import http

# ANSI escape codes for coloring
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

banner = r"""
 █████╗ ██╗  ██╗███████╗ █████╗ ███████╗ █████╗ ███████╗
██╔══██╗██║ ██╔╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║█████╔╝ ███████╗███████║███████╗███████║███████╗
██╔══██║██╔═██╗ ╚════██║██╔══██║╚════██║██╔══██║╚════██║
██║  ██║██║  ██╗███████║██║  ██║███████║██║  ██║███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
                                                        Made by 0ranos

Let your browser connect to mitm proxy on port 8088 to proceed.                                                   
"""

# Session to reuse connections
session = requests.Session()

# Store the hostnames to include in the scope (whitelist)
include_hosts = None

def request(flow: http.HTTPFlow) -> None:
    global include_hosts

    # Prompt for hostnames if not already provided
    if include_hosts is None:
        include_hosts = input("Enter the hostnames to include (e.g., 'tomatoes.com,amogus.org,raju.biz'): ").split(',')

    url = flow.request.url
    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.netloc
    
    # Only process requests if the host matches any of the specified substrings (whitelist)
    if any(host.endswith(f".{keyword.strip()}") or host == keyword.strip() for keyword in include_hosts):
        threading.Thread(target=test_reflections, args=(flow,)).start()

def test_reflections(flow):
    if flow.request.urlencoded_form:
        test_params(flow, flow.request.urlencoded_form, "POST")

    if flow.request.query:
        test_params(flow, flow.request.query, "GET")

def test_params(flow, params, method):
    original_params = params.copy()
    canary_prefix = "0ranos"
    for param in original_params:
        for injection in ['<', '>', '"']:
            prefixed_injection = f"{canary_prefix}{injection}"
            modified_params = original_params.copy()
            modified_params[param] = prefixed_injection

            # Rebuild the URL for GET requests
            if method == "GET":
                url_parts = list(urllib.parse.urlparse(flow.request.url))
                query = urllib.parse.urlencode(modified_params)
                url_parts[4] = query
                modified_url = urllib.parse.urlunparse(url_parts)
            else:
                modified_url = flow.request.url

            success = False
            retries = 3
            while not success and retries > 0:
                try:
                    response = session.request(
                        method=method,
                        url=modified_url,
                        headers=dict(flow.request.headers),
                        data=modified_params if method == "POST" else None
                    )
                    success = True
                except requests.exceptions.ConnectionError as e:
                    retries -= 1
                    time.sleep(1)

            if not success:
                continue

            if success and 'Content-Type' in response.headers and response.headers['Content-Type'].startswith('text/html'):
                if is_whitelisted_reflection(response.text, prefixed_injection):
                    print(f"{BOLD}{YELLOW}Potential vulnerability found!{RESET}")
                    print(f"{BLUE}URL: {RESET}{modified_url}")
                    print(f"{GREEN}Parameter: {RESET}{param}")
                    print(f"{RED}Injection: {RESET}{prefixed_injection}")
                    print(f"{YELLOW}--------------------------------------{RESET}")

            time.sleep(3)

def is_whitelisted_reflection(response_text, prefixed_injection):
    # Ensure that the reflected character is exactly the same as what was injected
    return prefixed_injection in response_text

if __name__ == "__main__":
    print(banner)

    from mitmproxy.tools.main import mitmdump
    mitmdump(["-p", "8088", "-q", "-s", __file__])  # Using -q to suppress the mitmproxy logging
