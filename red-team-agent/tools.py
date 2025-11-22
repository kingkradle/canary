"""Tools for the Red Team Agent"""
from langchain.tools import tool
import requests
from typing import List, Optional
import sys
import os

# Handle both package and direct imports
try:
    from .config import config
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config


def get_playwright_tools():
    """
    Get Playwright browser automation tools if available.
    These tools allow the agent to interact with web pages directly.
    
    Returns:
        List of Playwright tools, or empty list if not available
    """
    try:
        from langchain_community.tools.playwright import (
            NavigateTool,
            NavigateBackTool,
            ClickTool,
            ExtractTextTool,
            ExtractHyperlinksTool,
            GetElementsTool,
            CurrentWebPageTool,
        )
        from playwright.async_api import async_playwright
        
        # Note: Playwright tools require async context
        # We'll create a simple wrapper or use the sync version
        # For now, return empty list and we'll add a simpler implementation
        return []
    except ImportError:
        return []
    
    except Exception as e:
        print(f"Warning: Could not load Playwright tools: {e}")
        return []


@tool
def scan_website(url: str) -> str:
    """
    Scan a website for basic information like HTTP status and headers.
    This is useful for initial reconnaissance of the target website.
    
    Args:
        url: The full URL to scan (e.g., https://example.com)
    
    Returns:
        String containing HTTP status code and response headers
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        return f"Status: {response.status_code}\nHeaders:\n{headers_str}"
    except requests.exceptions.RequestException as e:
        return f"Error scanning {url}: {str(e)}"


@tool
def check_endpoint(url: str) -> str:
    """
    Check a specific endpoint/URL path on the target website.
    Useful for testing specific routes or pages.
    
    Args:
        url: The full URL including path (e.g., https://example.com/api/users)
    
    Returns:
        String containing endpoint status and basic response info
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
        content_preview = response.text[:300] if response.text else "(empty)"
        # Check if redirected to login (302/307) or if accessible without auth
        redirect_to_login = response.status_code in [302, 307] and 'login' in str(response.headers.get('Location', '')).lower()
        auth_status = "REQUIRES_AUTH" if redirect_to_login else "ACCESSIBLE"
        return f"Status: {response.status_code}\nAuth: {auth_status}\nContent preview: {content_preview}"
    except requests.exceptions.RequestException as e:
        return f"Error checking endpoint {url}: {str(e)}"


@tool
def check_admin_endpoints(base_url: str) -> str:
    """
    Check common admin and management endpoints for authentication bypass vulnerabilities.
    Tests endpoints like /admin, /dashboard, /management, etc.
    
    Args:
        base_url: The base URL of the website (e.g., https://example.com or full URL)
    
    Returns:
        String containing which admin endpoints are accessible without authentication
    """
    # Extract base domain from full URL if needed
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Remove trailing slash
    base_url = base_url.rstrip('/')
    
    # Common admin endpoints to check (excluding login pages - those are supposed to be accessible)
    admin_paths = [
        '/admin',              # Admin dashboard (should require auth)
        '/dashboard',          # Dashboard (should require auth)
        '/management',         # Management panel
        '/api/admin',          # Admin API
        '/admin/index',        # Admin index page
        '/administrator',      # Administrator panel
        '/wp-admin',           # WordPress admin
        '/backend',            # Backend panel
        '/panel',              # Control panel
        # Note: /admin/login is excluded - login pages should be accessible
    ]
    
    results = []
    accessible = []
    
    for path in admin_paths:
        url = base_url + path
        try:
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            # Check if redirected to login (authentication required) or accessible
            is_redirect = response.status_code in [302, 307, 301]
            redirect_location = response.headers.get('Location', '')
            requires_auth = is_redirect and ('login' in redirect_location.lower() or 'auth' in redirect_location.lower())
            
            # Check if accessible without authentication
            # Note: /admin/login being accessible is normal (it's a login page)
            # But /admin, /dashboard, etc. being accessible is a vulnerability
            if response.status_code == 200 and not requires_auth:
                # Login pages are expected to be accessible
                if 'login' in path.lower():
                    results.append(f"{path} - Status: {response.status_code} (Login page - normal)")
                else:
                    # Admin/dashboard pages accessible without auth = CRITICAL
                    accessible.append(f"{path} - Status: {response.status_code} - CRITICAL: Accessible without authentication")
            elif response.status_code == 403:
                results.append(f"{path} - Status: 403 (Forbidden - protected)")
            elif requires_auth:
                results.append(f"{path} - Status: {response.status_code} (Redirected to login - protected)")
            else:
                results.append(f"{path} - Status: {response.status_code}")
        except requests.exceptions.RequestException:
            results.append(f"{path} - Error or unreachable")
    
    output = []
    if accessible:
        output.append("CRITICAL: Found admin endpoints accessible without authentication:")
        output.extend(accessible)
        output.append("")
    output.append("All checked endpoints:")
    output.extend(results)
    
    return "\n".join(output)


@tool
def navigate_page(url: str) -> str:
    """
    Navigate to a URL using Playwright browser automation.
    This allows the agent to interact with web pages, see rendered content, and test client-side vulnerabilities.
    
    Args:
        url: The URL to navigate to
    
    Returns:
        String containing page title and basic page information
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=10000)
            
            title = page.title()
            url_after_nav = page.url
            
            # Get basic page info
            content_length = len(page.content())
            
            browser.close()
            
            return f"Navigated to: {url_after_nav}\nTitle: {title}\nContent size: {content_length} chars"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error navigating to {url}: {str(e)}"


@tool
def take_screenshot(url: str) -> str:
    """
    Take a screenshot of a web page using Playwright.
    Useful for seeing the actual rendered page and checking for visual elements or client-side vulnerabilities.
    
    Args:
        url: The URL to screenshot
    
    Returns:
        String with screenshot information and file path
    """
    try:
        from playwright.sync_api import sync_playwright
        from pathlib import Path
        
        screenshot_dir = Path(__file__).parent.parent / "logs" / "screenshots"
        screenshot_dir.mkdir(exist_ok=True, parents=True)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=10000)
            
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = screenshot_dir / f"screenshot_{timestamp}.png"
            
            page.screenshot(path=str(screenshot_path), full_page=False)
            title = page.title()
            
            browser.close()
            
            return f"Screenshot saved: {screenshot_path}\nPage title: {title}\nURL: {url}"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error taking screenshot of {url}: {str(e)}"


@tool
def check_page_content(url: str, search_text: Optional[str] = None) -> str:
    """
    Check the rendered page content using Playwright.
    This sees the actual DOM and JavaScript-rendered content, not just the raw HTML.
    Useful for testing client-side vulnerabilities and checking for exposed sensitive information.
    
    Args:
        url: The URL to check
        search_text: Optional text to search for in the page content
    
    Returns:
        String containing page content information
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Get visible text content
            text_content = page.locator("body").inner_text()[:2000]  # First 2000 chars
            
            # Check for specific text if provided
            found_text = ""
            if search_text:
                if search_text.lower() in text_content.lower():
                    found_text = f"\n✓ Found search text: '{search_text}'"
                else:
                    found_text = f"\n✗ Search text '{search_text}' not found"
            
            title = page.title()
            url_after_nav = page.url
            
            browser.close()
            
            return f"URL: {url_after_nav}\nTitle: {title}\nContent preview: {text_content[:500]}...{found_text}"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error checking page content for {url}: {str(e)}"


def get_playwright_toolkit_tools():
    """
    Get Playwright Browser Toolkit tools from LangChain.
    These provide comprehensive browser automation capabilities like navigate, click, extract, etc.
    
    Returns:
        List of Playwright toolkit tools, or empty list if not available
    """
    try:
        # Playwright toolkit requires async setup, which can be complex
        # For now, we use our custom sync tools
        # Can be enhanced later with proper async integration
        return []
    except ImportError:
        return []
    except Exception as e:
        return []


@tool
def browser_interact(url: str, action: str = "navigate", selector: Optional[str] = None, text: Optional[str] = None) -> str:
    """
    Interact with a web page using browser automation (Playwright/Browser-use).
    This allows the agent to navigate, click, fill forms, and extract information from rendered pages.
    
    Args:
        url: The URL to interact with
        action: Action to perform - "navigate", "click", "fill", "extract", "screenshot"
        selector: CSS selector for element to interact with (required for click/fill)
        text: Text to fill in a form field (required for fill action)
    
    Returns:
        String containing the result of the interaction
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            result = ""
            
            if action == "navigate":
                result = f"Navigated to: {page.url}\nTitle: {page.title()}"
            
            elif action == "click" and selector:
                try:
                    page.click(selector, timeout=5000)
                    result = f"Clicked element: {selector}\nCurrent URL: {page.url}"
                except Exception as e:
                    result = f"Error clicking {selector}: {str(e)}"
            
            elif action == "fill" and selector and text:
                try:
                    page.fill(selector, text)
                    result = f"Filled {selector} with text: {text}"
                except Exception as e:
                    result = f"Error filling {selector}: {str(e)}"
            
            elif action == "extract":
                if selector:
                    try:
                        elements = page.query_selector_all(selector)
                        texts = [el.inner_text() for el in elements[:10]]  # Limit to 10
                        result = f"Extracted from {selector}:\n" + "\n".join(texts)
                    except Exception as e:
                        result = f"Error extracting from {selector}: {str(e)}"
                else:
                    # Extract all visible text
                    text_content = page.locator("body").inner_text()[:2000]
                    result = f"Page content:\n{text_content}"
            
            elif action == "screenshot":
                from pathlib import Path
                screenshot_dir = Path(__file__).parent.parent / "logs" / "screenshots"
                screenshot_dir.mkdir(exist_ok=True, parents=True)
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                screenshot_path = screenshot_dir / f"interaction_{timestamp}.png"
                page.screenshot(path=str(screenshot_path))
                result = f"Screenshot saved: {screenshot_path}"
            
            else:
                result = f"Action '{action}' not supported or missing required parameters"
            
            browser.close()
            return result
            
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error during browser interaction: {str(e)}"


def get_browser_use_tools():
    """
    Get Browser-use tools if available.
    Browser-use provides browser automation interface.
    
    Returns:
        List of Browser-use tools, or empty list if not available
    """
    tools = []
    
    # Always add browser_interact if Playwright is available
    # It provides comprehensive browser automation
    try:
        from playwright.sync_api import sync_playwright
        tools.append(browser_interact)
    except ImportError:
        pass
    
    # Try to use browser-use package if available (more advanced features)
    try:
        import browser_use
        # Browser-use package is available
        # The browser_interact tool can be enhanced to use it
        pass
    except ImportError:
        pass
    
    return tools


def get_tools() -> List:
    """
    Get all available tools for the agent
    
    Returns:
        List of tool instances
    """
    tools = [
        scan_website,
        check_endpoint,
        check_admin_endpoints,
    ]
    
    # Add custom Playwright tools if available
    try:
        from playwright.sync_api import sync_playwright
        # Test if playwright works
        tools.extend([
            navigate_page,
            take_screenshot,
            check_page_content,
        ])
    except ImportError:
        pass  # Playwright not installed, skip browser tools
    except Exception:
        pass  # Playwright installed but browsers not installed
    
    # Add Browser-use/Playwright browser interaction tool
    browser_use_tools = get_browser_use_tools()
    if browser_use_tools:
        tools.extend(browser_use_tools)
    
    return tools

