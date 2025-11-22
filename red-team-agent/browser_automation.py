"""Browser automation for visualizing agent testing process"""
import subprocess
import webbrowser
from typing import Optional
from pathlib import Path
import sys
import os

# Handle both package and direct imports
try:
    from .logger import AgentLogger
except ImportError:
    # For direct script execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    try:
        from logger import AgentLogger
    except ImportError:
        AgentLogger = None  # Optional dependency


class BrowserAutomation:
    """Browser automation for visualizing the testing process"""
    
    def __init__(self, website_url: str, logger: Optional[AgentLogger] = None):
        """
        Initialize browser automation
        
        Args:
            website_url: URL to open
            logger: Optional logger for capturing screenshots
        """
        self.website_url = website_url
        self.logger = logger
        self.browser_opened = False
    
    def open_browser(self):
        """Open the website in the default browser"""
        try:
            print(f"🌐 Opening browser: {self.website_url}")
            webbrowser.open(self.website_url)
            self.browser_opened = True
            return True
        except Exception as e:
            print(f"⚠️  Could not open browser: {e}")
            return False
    
    def open_with_playwright(self, headless: bool = False):
        """
        Open browser using Playwright (if installed)
        Requires: pip install playwright && playwright install
        
        Args:
            headless: If True, run browser in headless mode
        """
        try:
            from playwright.sync_api import sync_playwright
            
            print(f"🎭 Opening browser with Playwright: {self.website_url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                page = browser.new_page()
                page.goto(self.website_url)
                
                if not headless:
                    print("Browser window opened. Press Enter to close...")
                    input()
                
                # Take screenshot if logger is available
                if self.logger:
                    screenshot_dir = Path(self.logger.output_dir) / "screenshots"
                    screenshot_dir.mkdir(exist_ok=True)
                    screenshot_path = screenshot_dir / f"{self.logger.run_id}_initial.png"
                    page.screenshot(path=str(screenshot_path))
                    print(f"📸 Screenshot saved: {screenshot_path}")
                
                if headless:
                    browser.close()
                else:
                    print("Closing browser...")
                    browser.close()
            
            self.browser_opened = True
            return True
            
        except ImportError:
            print("⚠️  Playwright not installed. Install with: pip install playwright && playwright install")
            return False
        except Exception as e:
            print(f"⚠️  Error with Playwright: {e}")
            return False
    
    @staticmethod
    def is_playwright_available() -> bool:
        """Check if Playwright is available"""
        try:
            from playwright.sync_api import sync_playwright
            return True
        except ImportError:
            return False


def open_website_in_browser(url: str, use_playwright: bool = False, headless: bool = False):
    """
    Simple function to open a website in browser
    
    Args:
        url: Website URL to open
        use_playwright: If True, use Playwright instead of default browser
        headless: If True and using Playwright, run in headless mode
    """
    browser = BrowserAutomation(url)
    
    if use_playwright and BrowserAutomation.is_playwright_available():
        return browser.open_with_playwright(headless=headless)
    else:
        return browser.open_browser()

