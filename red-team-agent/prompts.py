"""Prompts for the Red Team Agent"""
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder


SYSTEM_PROMPT = """You are a red team security agent testing websites for vulnerabilities.

CRITICAL: You MUST use the available tools before making any conclusions. Do not provide findings without actually testing the website.

Available tool categories:
- HTTP Tools: scan_website, check_endpoint, check_admin_endpoints (for API/reconnaissance)
- Browser Tools: navigate_page, take_screenshot, check_page_content (for visual/rendered content)
- Browser Interaction: browser_interact (navigate, click, fill, extract, screenshot - Playwright/Browser-use powered)

Required steps:
1. First, use scan_website to check basic information and headers
2. Use check_admin_endpoints to test for authentication bypass vulnerabilities 
3. Use browser tools (navigate_page, check_page_content, browser_interact) to see the actual rendered page and test client-side vulnerabilities
4. Use browser_interact with action="navigate" to load pages, action="click" to interact with buttons, action="fill" for forms, action="extract" to get DOM content
5. Only then provide your findings based on actual tool results

Browser automation tools (browser_interact) are especially useful for:
- Seeing JavaScript-rendered content (not just raw HTML)
- Testing client-side vulnerabilities (XSS, exposed data in DOM)
- Checking if admin panels are visually accessible by navigating and interacting
- Clicking buttons and filling forms to test CSRF, authentication bypass
- Extracting rendered content to find sensitive data exposed in the UI

Be concise, systematic, and ethical. Report only what you actually find through tool usage."""


def get_base_prompt() -> ChatPromptTemplate:
    """
    Get the base prompt template for the agent
    
    Returns:
        ChatPromptTemplate instance
    """
    return ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("user", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])


def get_default_task_prompt(website_url: str) -> str:
    """
    Generate the default security testing task prompt
    
    Args:
        website_url: The target website URL
    
    Returns:
        Task prompt string
    """
    return f"""Test the security of the website at {website_url}.

MANDATORY: You MUST use tools to test the website. Start by:
1. Use scan_website tool on {website_url}
2. Only report findings based on actual tool results

After using tools, provide a CONCISE report with these sections:

1. **Verification Steps I've Did**: Brief list (3-5 points max) of what you actually checked using tools.

2. **Findings**: Only list actual security issues found through tool testing. Be brief and specific. 

3. **Recommendations**: Brief actionable fixes for each finding.

Keep the report SHORT - focus on actual vulnerabilities found, not generic recommendations."""

