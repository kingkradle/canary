"""Logging and report generation for Red Team Agent"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import re


class AgentLogger:
    """Logger for capturing agent execution and generating reports"""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the logger
        
        Args:
            output_dir: Directory to save logs. Defaults to ./logs in red-team-agent directory
        """
        if output_dir is None:
            self.output_dir = Path(__file__).parent / "logs"
        else:
            self.output_dir = Path(output_dir)
        
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_data = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "website_url": None,
            "model": None,
            "task": None,
            "messages": [],
            "tool_calls": [],
            "reasoning_steps": [],
            "final_report": None,
            "structured_report": {
                "verification_steps": [],
                "findings": [],
                "recommendations": []
            }
        }
    
    def log_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Log a message (human or AI)"""
        self.log_data["messages"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        })
    
    def log_tool_call(self, tool_name: str, args: Dict, result: str):
        """Log a tool call and its result"""
        self.log_data["tool_calls"].append({
            "tool": tool_name,
            "args": args,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_reasoning(self, reasoning: str):
        """Log reasoning/CoT steps"""
        self.log_data["reasoning_steps"].append({
            "step": len(self.log_data["reasoning_steps"]) + 1,
            "reasoning": reasoning,
            "timestamp": datetime.now().isoformat()
        })
    
    def set_run_info(self, website_url: str, model: str, task: str):
        """Set run information"""
        self.log_data["website_url"] = website_url
        self.log_data["model"] = model
        self.log_data["task"] = task
    
    def parse_and_extract_structured_report(self, final_output: str):
        """Parse the final output and extract structured information"""
        self.log_data["final_report"] = final_output
        
        # Extract Verification Steps
        verification_pattern = r"(?:Verification Steps|Verification|Testing Steps)[:\s]*(.*?)(?=Findings|Recommendations|$)"
        verification_matches = re.findall(verification_pattern, final_output, re.DOTALL | re.IGNORECASE)
        if verification_matches:
            steps = [s.strip() for s in verification_matches[0].split('\n') if s.strip() and not s.strip().startswith('-')]
            self.log_data["structured_report"]["verification_steps"] = steps
        
        # Also try to extract bulleted steps
        step_pattern = r"•\s*(.*?)(?=\n|•|Findings|Recommendations)"
        steps = re.findall(step_pattern, final_output, re.DOTALL)
        if steps:
            self.log_data["structured_report"]["verification_steps"].extend([s.strip() for s in steps if s.strip()])
        
        # Extract Findings
        findings_pattern = r"(?:Findings|Finding)[:\s]*(.*?)(?=Recommendations|General Recommendations|Final Notes|$)"
        findings_matches = re.findall(findings_pattern, final_output, re.DOTALL | re.IGNORECASE)
        if findings_matches:
            findings_text = findings_matches[0]
            # Split by lines and bullets
            findings = []
            for line in findings_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                    findings.append(line.lstrip('-•* ').strip())
            self.log_data["structured_report"]["findings"] = findings
        
        # Extract Recommendations
        recommendations_pattern = r"(?:Recommendations|Recommendation)[:\s]*(.*?)(?=General Recommendations|Final Notes|End of|$)"
        recommendations_matches = re.findall(recommendations_pattern, final_output, re.DOTALL | re.IGNORECASE)
        if recommendations_matches:
            recs_text = recommendations_matches[0]
            recommendations = []
            for line in recs_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*') or '▪' in line):
                    recommendations.append(line.lstrip('-•*▪ ').strip())
            self.log_data["structured_report"]["recommendations"] = recommendations
    
    def save_report(self) -> Path:
        """Save the report to files"""
        # Save full JSON log
        json_file = self.output_dir / f"run_{self.run_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.log_data, f, indent=2, ensure_ascii=False)
        
        # Save human-readable report
        report_file = self.output_dir / f"report_{self.run_id}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown_report())
        
        return report_file
    
    def _generate_markdown_report(self) -> str:
        """Generate a concise markdown report from the log data"""
        report = []
        report.append("# Security Assessment Report")
        report.append(f"\n**URL:** {self.log_data['website_url']} | **Model:** {self.log_data['model']} | **Run:** {self.log_data['run_id']}")
        report.append("\n---\n")
        
        # Verification Steps (Brief)
        report.append("## Verification Steps")
        # Extract only key steps (first 5)
        if self.log_data["structured_report"]["verification_steps"]:
            steps = self.log_data["structured_report"]["verification_steps"][:5]
            for step in steps:
                # Truncate long steps
                step_text = step[:200] + "..." if len(step) > 200 else step
                report.append(f"- {step_text}")
        elif self.log_data["tool_calls"]:
            tools_used = set(tc['tool'] for tc in self.log_data["tool_calls"])
            report.append("- Tools used: " + ", ".join(tools_used))
        else:
            report.append("- Basic scanning performed")
        
        report.append("\n---\n")
        
        # Findings (Critical First)
        report.append("## Findings")
        if self.log_data["structured_report"]["findings"]:
            findings = self.log_data["structured_report"]["findings"]
            # Prioritize findings with "CRITICAL" or "VULNERABLE" keywords
            critical = [f for f in findings if any(word in f.upper() for word in ['CRITICAL', 'VULNERABLE', 'AUTH', 'ADMIN'])]
            others = [f for f in findings if f not in critical]
            
            for finding in critical + others[:10]:  # Limit to 10 findings max
                finding_text = finding[:300] + "..." if len(finding) > 300 else finding
                report.append(f"- {finding_text}")
        else:
            # Try to extract from final report
            final = self.log_data.get("final_report", "")
            if "CRITICAL" in final.upper() or "VULNERABLE" in final.upper():
                report.append("- Critical vulnerabilities may be present. Check full report.")
            else:
                report.append("- No critical vulnerabilities detected.")
        
        report.append("\n---\n")
        
        # Recommendations (Brief - top 5)
        report.append("## Recommendations")
        if self.log_data["structured_report"]["recommendations"]:
            recs = self.log_data["structured_report"]["recommendations"][:5]
            for rec in recs:
                rec_text = rec[:200] + "..." if len(rec) > 200 else rec
                report.append(f"- {rec_text}")
        else:
            report.append("- See full report for recommendations.")
        
        report.append("\n---\n")
        
        # Full Report (Truncated if too long)
        report.append("## Full Report")
        if self.log_data["final_report"]:
            full_text = self.log_data["final_report"]
            # Truncate if over 3000 characters
            if len(full_text) > 3000:
                report.append(full_text[:3000] + "\n\n... (truncated, see JSON log for full report)")
            else:
                report.append(full_text)
        else:
            report.append("Full report not available.")
        
        return "\n".join(report)

