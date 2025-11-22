"""Simple script to activate the red team agent"""
import sys
import os
import argparse

# Add parent directory to path so we can import from red_team_agent package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from red_team_agent import activate_agent

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Activate Red Team Agent for security testing")
    parser.add_argument("website_url", help="Target website URL to test")
    parser.add_argument("model", nargs="?", default=None, help="Model to use (e.g., openai/gpt-4o)")
    parser.add_argument("--open-browser", action="store_true", help="Open website in browser during testing")
    parser.add_argument("--playwright", action="store_true", help="Use Playwright for browser automation (requires --open-browser)")
    
    args = parser.parse_args()
    
    print(f"Activating Red Team Agent...")
    print(f"Target: {args.website_url}")
    print(f"Model: {args.model or 'default'}")
    if args.open_browser:
        print(f"Browser: Will open in browser")
        if args.playwright:
            print(f"Browser Automation: Playwright")
    print("-" * 50)
    
    result = activate_agent(
        website_url=args.website_url,
        model=args.model,
        open_browser=args.open_browser,
        use_playwright=args.playwright
    )
    
    print("-" * 50)
    print("Results:")
    print(f"Report saved to: {result.get('report_file', 'Not saved')}")
    print()
    
    # Show structured summary if available
    structured = result.get("structured", {})
    if structured:
        print("📋 Verification Steps:", len(structured.get("verification_steps", [])))
        print("🔍 Findings:", len(structured.get("findings", [])))
        print("💡 Recommendations:", len(structured.get("recommendations", [])))
        print("\nFull report available in the saved file.")

