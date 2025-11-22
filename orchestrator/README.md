# Orchestrator

The Orchestrator runs the red-team agent and auditor sequentially, automatically auditing the red-team agent's performance after it completes.

## Overview

The orchestrator:
1. Runs the red-team agent with the specified website and parameters
2. Extracts the run_id from the red-team agent's result
3. Automatically runs the auditor to check if the vulnerability was found
4. Displays a summary of both results

## Usage

### Basic Usage

```bash
python orchestrator/orchestrator.py --website <website_url>
```

Example:
```bash
python orchestrator/orchestrator.py --website http://localhost:3000/
```

### Options

- `--website <url>`: **Required** - Website URL to test
- `--model <model>`: Model to use for red-team agent (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default
- `--task <task>`: Optional specific task/prompt for red-team agent
- `--open-browser`: Open website in browser during red-team testing
- `--playwright`: Use Playwright for browser automation (requires --open-browser)
- `--skip-audit`: Skip running the auditor after red-team agent completes
- `--red-team-logs-dir <path>`: Directory containing red-team agent logs (default: ../red-team-agent/logs)
- `--no-save-audit`: Don't save the audit report to files

### Examples

```bash
# Basic run
python orchestrator/orchestrator.py --website http://localhost:3000/

# Use specific model
python orchestrator/orchestrator.py --website http://localhost:3000/ --model openai/gpt-4o

# Skip auditor (only run red-team agent)
python orchestrator/orchestrator.py --website http://localhost:3000/ --skip-audit

# Open browser during testing
python orchestrator/orchestrator.py --website http://localhost:3000/ --open-browser

# Use Playwright for browser automation
python orchestrator/orchestrator.py --website http://localhost:3000/ --open-browser --playwright
```

## As a Python Module

```python
from orchestrator import run_orchestrator

# Run orchestrator
result = run_orchestrator(
    website_url="http://localhost:3000/",
    model="openai/gpt-4o",
    save_audit_report=True
)

# Check results
if result["status"] == "success":
    vulnerability_found = result.get("vulnerability_found", False)
    run_id = result.get("run_id")
    print(f"Run ID: {run_id}")
    print(f"Vulnerability found: {vulnerability_found}")
```

## Output

The orchestrator displays:
1. Red-team agent execution and results
2. Auditor execution and audit report
3. Summary with final verdict

### Example Output

```
======================================================================
🔴 RED-TEAM AGENT
======================================================================

🔴 Testing: http://localhost:3000/
🤖 Model: openai/gpt-4o

[... red-team agent execution ...]

✅ Red-team agent completed. Run ID: 1763831525832

======================================================================
🔍 AUDITOR AGENT
======================================================================

# Auditor Report

[... audit report ...]

======================================================================
📊 SUMMARY
======================================================================
✅ Red-team agent completed: Run ID 1763831525832
❌ Auditor result: Vulnerability NOT FOUND
======================================================================
```

## Exit Codes

- `0`: Orchestrator completed successfully and vulnerability was found
- `1`: Orchestrator completed but vulnerability was not found, or an error occurred

## Workflow

1. **Red-Team Agent Phase**:
   - Initializes and runs the red-team agent
   - Tests the specified website
   - Generates security assessment report
   - Returns run_id and report file location

2. **Auditor Phase** (if not skipped):
   - Loads the red-team agent's report using the run_id
   - Compares findings to actual vulnerability details
   - Generates audit report
   - Saves audit reports to `auditor/logs/`

3. **Summary**:
   - Displays both results
   - Shows final verdict: was the vulnerability found?

## Integration

The orchestrator is designed to be used as part of an automated testing pipeline:

```bash
# Run test for a specific website
python orchestrator/orchestrator.py --website http://localhost:3000/ --model openai/gpt-4o

# Exit code indicates success (vulnerability found) or failure (not found)
if [ $? -eq 0 ]; then
    echo "Vulnerability was found!"
else
    echo "Vulnerability was not found or error occurred"
fi
```

## Files

- `orchestrator.py`: Main orchestrator script
- `__init__.py`: Package initialization
- `README.md`: This file

