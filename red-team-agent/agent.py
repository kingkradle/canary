"""Red Team Agent for security testing"""
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from typing import Optional
import sys
import os

# Handle both package and direct imports
try:
    from .config import config
    from .tools import get_tools
    from .prompts import get_default_task_prompt, SYSTEM_PROMPT
    from .logger import AgentLogger
except ImportError:
    # For direct script execution
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config
    from tools import get_tools
    from prompts import get_default_task_prompt, SYSTEM_PROMPT
    from logger import AgentLogger


class RedTeamAgent:
    """Red Team Agent for security testing websites"""
    
    def __init__(self, model: Optional[str] = None, website_url: Optional[str] = None, logger: Optional[AgentLogger] = None):
        """
        Initialize the Red Team Agent
        
        Args:
            model: Model to use (e.g., 'openai/gpt-4o', 'anthropic/claude-3.5-sonnet')
            website_url: Target website URL to test
            logger: Optional AgentLogger instance for logging
        """
        # Validate configuration
        config.validate()
        
        # Set instance variables
        self.model_name = model or config.DEFAULT_MODEL
        self.website_url = website_url
        self.logger = logger or AgentLogger()
        
        # Initialize components
        self.llm = self._create_llm()
        self.agent = self._create_agent()
        
        # Set logger run info
        if website_url:
            self.logger.set_run_info(website_url, self.model_name, "")
    
    def _create_llm(self) -> ChatOpenAI:
        """Create LLM instance with OpenRouter"""
        return ChatOpenAI(
            model=self.model_name,
            openai_api_base=config.OPENROUTER_BASE_URL,
            openai_api_key=config.OPENROUTER_API_KEY,
            temperature=config.TEMPERATURE,
        )
    
    def _create_agent(self):
        """Create the agent with tools and prompt"""
        tools = get_tools()
        
        agent = create_agent(
            model=self.llm,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
            debug=True
        )
        
        return agent
    
    def activate(self, task: Optional[str] = None) -> dict:
        """
        Activate the agent to test the website
        
        Args:
            task: Optional specific task/prompt. If None, uses default security testing prompt.
        
        Returns:
            Agent execution result dictionary
        """
        if not self.website_url:
            raise ValueError(
                "Website URL not provided. "
                "Set it during initialization: RedTeamAgent(website_url='https://example.com')"
            )
        
        task_prompt = task or get_default_task_prompt(self.website_url)
        
        # Update logger with task
        self.logger.set_run_info(self.website_url, self.model_name, task_prompt)
        self.logger.log_message("human", task_prompt)
        
        # Use invoke with messages format for new agent API
        # Wrap in callback to capture intermediate steps
        result = self.agent.invoke({
            "messages": [HumanMessage(content=task_prompt)]
        })
        
        # Extract messages and log them
        messages = result.get("messages", [])
        
        # Process messages and log tool calls, reasoning, etc.
        for msg in messages:
            if isinstance(msg, AIMessage):
                content = msg.content
                self.logger.log_message("ai", content or "")
                
                # Extract reasoning if available (for o3 and similar models)
                if hasattr(msg, 'response_metadata') and msg.response_metadata:
                    metadata = msg.response_metadata
                    if 'reasoning_tokens' in str(metadata):
                        # Log reasoning tokens info
                        pass
                
                # Log tool calls
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    for tool_call in msg.tool_calls:
                        tool_name = tool_call.get('name', 'unknown')
                        tool_args = tool_call.get('args', {})
                        self.logger.log_tool_call(tool_name, tool_args, "pending")
            
            elif isinstance(msg, ToolMessage):
                self.logger.log_tool_call(
                    msg.name if hasattr(msg, 'name') else 'unknown',
                    {},
                    msg.content[:1000] if msg.content else ""
                )
        
        # Get final output
        final_output = ""
        if messages:
            last_msg = messages[-1]
            if isinstance(last_msg, AIMessage):
                final_output = last_msg.content or str(messages[-1])
            else:
                final_output = str(messages[-1])
        
        # Parse structured report
        self.logger.parse_and_extract_structured_report(final_output)
        
        # Save report to file
        report_file = self.logger.save_report()
        
        return {
            "output": final_output,
            "report_file": str(report_file),
            "structured": self.logger.log_data["structured_report"]
        }


def activate_agent(
    website_url: str,
    model: Optional[str] = None,
    task: Optional[str] = None,
    open_browser: bool = False,
    use_playwright: bool = False
) -> dict:
    """
    Simple function to activate the red team agent
    
    Args:
        website_url: Target website URL
        model: Model to use (defaults to config)
        task: Optional specific task/prompt
        open_browser: If True, open website in browser
        use_playwright: If True and open_browser is True, use Playwright for automation
    
    Returns:
        Agent execution result dictionary
    """
    # Create logger
    logger = AgentLogger()
    
    # Open browser if requested
    if open_browser:
        try:
            try:
                from .browser_automation import open_website_in_browser
            except ImportError:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from browser_automation import open_website_in_browser
            open_website_in_browser(website_url, use_playwright=use_playwright, headless=False)
        except Exception as e:
            print(f"⚠️  Could not open browser: {e}")
    
    # Create and activate agent
    agent = RedTeamAgent(model=model, website_url=website_url, logger=logger)
    return agent.activate(task=task)
