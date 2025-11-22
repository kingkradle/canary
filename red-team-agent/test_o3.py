"""Test script for o3 model - with logging and browser support"""
import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import directly
from agent import activate_agent

# Target URL and model
WEBSITE_URL = "https://v0.app/chat/blog-with-hidden-vulnerability-rVsrXU04WBX"
MODEL = "openai/o3-mini"

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Red Team Agent with o3 model")
    parser.add_argument("--url", default=WEBSITE_URL, help="Website URL to test")
    parser.add_argument("--model", default=MODEL, help="Model to use")
    parser.add_argument("--open-browser", action="store_true", help="Open website in browser")
    parser.add_argument("--playwright", action="store_true", help="Use Playwright for browser automation")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Red Team Agent Test - O3 Model")
    print("=" * 60)
    print(f"Target URL: {args.url}")
    print(f"Model: {args.model}")
    print(f"Open Browser: {args.open_browser}")
    print(f"Use Playwright: {args.playwright}")
    print("=" * 60)
    print()
    
    try:
        result = activate_agent(
            website_url=args.url,
            model=args.model,
            open_browser=args.open_browser,
            use_playwright=args.playwright
        )
        
        print()
        print("=" * 60)
        print("Results:")
        print("=" * 60)
        print(f"Report saved to: {result.get('report_file', 'Not saved')}")
        print()
        
        # Show structured report
        structured = result.get("structured", {})
        if structured:
            print("📋 Verification Steps:")
            for step in structured.get("verification_steps", [])[:5]:
                print(f"  - {step}")
            if len(structured.get("verification_steps", [])) > 5:
                print(f"  ... and {len(structured.get('verification_steps', [])) - 5} more")
            
            print("\n🔍 Findings:")
            for finding in structured.get("findings", [])[:5]:
                print(f"  - {finding}")
            if len(structured.get("findings", [])) > 5:
                print(f"  ... and {len(structured.get('findings', [])) - 5} more")
            
            print("\n💡 Recommendations:")
            for rec in structured.get("recommendations", [])[:5]:
                print(f"  - {rec}")
            if len(structured.get("recommendations", [])) > 5:
                print(f"  ... and {len(structured.get('recommendations', [])) - 5} more")
        
        print("\n" + "=" * 60)
        print("Full report available in the saved file.")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
