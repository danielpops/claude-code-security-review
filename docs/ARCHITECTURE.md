# Architecture Documentation

This document describes the internal architecture of the Claude Code Security Review tool.

## Module Overview

```
claudecode/
├── __init__.py              # Package exports
├── constants.py             # Centralized configuration constants
├── logger.py                # Logging configuration
│
├── github_client.py         # Unified GitHub API client
├── github_action_audit.py   # GitHub Action entry point
├── pr_commenter.py          # PR commenting functionality
│
├── claude_api_client.py     # Claude API client for filtering
├── findings_filter.py       # False positive filtering
├── json_parser.py           # Robust JSON parsing
├── prompts.py               # Security audit prompts
│
├── config/                  # Configuration management
│   ├── __init__.py          # Config loading functions
│   └── filtering_rules.yaml # Default filtering rules
│
├── evals/                   # Evaluation framework
│   ├── __init__.py
│   ├── eval_engine.py       # Evaluation execution engine
│   └── README.md            # Eval documentation
│
└── test_*.py                # Test suites
```

## Core Components

### GitHub Client (`github_client.py`)

The unified GitHub API client handles all GitHub interactions:

- **Authentication**: Token-based auth supporting both github.com and GitHub Enterprise
- **PR Operations**: Fetching PR data, diffs, and file lists
- **Commenting**: Creating reviews and inline comments
- **Input Validation**: Validates repository names and PR numbers to prevent injection

```python
from claudecode.github_client import GitHubClient, get_github_client

# Create client (uses GITHUB_TOKEN env var)
client = GitHubClient()

# Or with explicit parameters
client = GitHubClient(
    token="ghp_...",
    api_url="https://github.mycompany.com/api/v3",
    excluded_directories=["vendor", "node_modules"]
)

# Get PR data
pr_data = client.get_pr_data("owner/repo", 123)
```

**Key Classes:**
- `GitHubClient`: Main client class
- `GitHubAuthenticationError`: Raised when token is missing
- `GitHubAPIError`: Raised on API failures
- `GitHubValidationError`: Raised on invalid input

### Claude API Client (`claude_api_client.py`)

Handles direct Claude API calls for false positive filtering:

```python
from claudecode.claude_api_client import ClaudeAPIClient

client = ClaudeAPIClient(
    model="claude-3-5-sonnet-20241022",
    base_url="https://litellm-proxy.example.com"  # Optional custom endpoint
)

# Analyze a single finding
success, result, error = client.analyze_single_finding(finding, pr_context)
```

**Features:**
- Configurable model selection
- Custom API endpoints (LiteLLM proxy support)
- Retry logic with exponential backoff
- Rate limit handling

### Configuration Module (`config/`)

Manages filtering rules and configuration:

```python
from claudecode.config import (
    load_filtering_rules,
    format_filtering_instructions,
    get_default_filtering_instructions
)

# Load rules from custom file or environment variable
rules = load_filtering_rules(custom_file="/path/to/rules.yaml")

# Format as instructions for Claude
instructions = format_filtering_instructions(rules)
```

**Configuration Sources (in priority order):**
1. Explicit `custom_file` parameter
2. `FALSE_POSITIVE_FILTERING_INSTRUCTIONS` environment variable
3. Default `filtering_rules.yaml`

### Constants (`constants.py`)

Centralized configuration values:

```python
# API Configuration
DEFAULT_CLAUDE_MODEL = "claude-opus-4-1-20250805"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_MAX_RETRIES = 3

# Timeout Constants (seconds)
TIMEOUT_SHORT = 10
TIMEOUT_GIT_OPERATION = 60
TIMEOUT_GIT_CLONE = 300
TIMEOUT_CLAUDECODE = 1800

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2
```

### Logger (`logger.py`)

Structured logging with verbose mode support:

```python
from claudecode.logger import get_logger, set_verbose_mode

# Get module-specific logger
logger = get_logger(__name__)

# Enable verbose mode (shows timestamps)
set_verbose_mode(True)

# Log levels configurable via CLAUDECODE_LOG_LEVEL env var
```

## Data Flow

### GitHub Action Flow

```
1. Trigger: PR opened/updated
   │
2. github_action_audit.py
   ├── Initialize GitHubClient
   ├── Fetch PR diff via get_pr_diff()
   └── Spawn Claude Code subprocess
       │
3. Claude Code analyzes code
   └── Returns JSON findings
       │
4. findings_filter.py
   ├── Load filtering rules from config
   ├── Call Claude API for each finding
   └── Filter out false positives
       │
5. pr_commenter.py
   ├── Format findings as review comments
   └── Post via GitHubClient.create_review()
```

### Evaluation Flow

```
1. eval_engine.py receives EvalCase
   │
2. Repository Setup
   ├── Clone if needed
   ├── Create worktree for isolation
   └── Checkout PR branch
       │
3. Run Security Audit
   ├── Execute claude command
   ├── Capture JSON output
   └── Parse and validate findings
       │
4. Cleanup
   ├── Remove worktree
   └── Return EvalResult
```

## Security Considerations

### Input Validation

All external inputs are validated:

```python
# Repository names validated for format and path traversal
validate_repo_name("owner/repo")  # OK
validate_repo_name("owner/../secret")  # Raises GitHubValidationError

# PR numbers must be positive integers
validate_pr_number(123)  # OK
validate_pr_number(-1)  # Raises GitHubValidationError
```

### Credential Sanitization

The `sanitize_credentials()` function removes tokens from log output:

```python
from claudecode.evals.eval_engine import sanitize_credentials

safe_text = sanitize_credentials(error_message)
# Removes: ghp_*, ghs_*, gho_*, github_pat_*, URL credentials
```

### Error Handling

Errors are wrapped to prevent credential leakage:

```python
except requests.HTTPError as e:
    # Don't include full URL (may contain tokens)
    raise GitHubAPIError(
        f"GitHub API error: {e.response.status_code}"
    ) from e
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub API token | Required |
| `GITHUB_API_URL` | GitHub Enterprise API URL | `https://api.github.com` |
| `ANTHROPIC_API_KEY` | Claude API key | Required for filtering |
| `ANTHROPIC_BASE_URL` | Custom Claude API endpoint | None |
| `CLAUDE_MODEL` | Model to use | `claude-opus-4-1-20250805` |
| `CLAUDECODE_LOG_LEVEL` | Logging level | `INFO` |
| `EXCLUDE_DIRECTORIES` | Directories to skip | None |
| `FALSE_POSITIVE_FILTERING_INSTRUCTIONS` | Custom rules path | None |

## Testing

Run tests with pytest:

```bash
# All tests
pytest claudecode -v

# Specific module
pytest claudecode/test_github_client.py -v

# With coverage
pytest claudecode --cov=claudecode --cov-report=html
```

Key test files:
- `test_github_client.py`: GitHub client and validation
- `test_eval_engine.py`: Evaluation engine and credential sanitization
- `test_config.py`: Configuration loading and formatting
- `test_json_parser.py`: JSON parsing utilities

## Extension Points

### Custom Filtering Rules

Create a YAML file with custom rules:

```yaml
hard_exclusions:
  - name: custom_exclusion
    description: "Custom exclusion pattern"
    reason: "Not applicable to our codebase"

signal_criteria:
  - "Custom criterion to assess findings"

precedents:
  - category: custom
    rule: "Custom rule for handling specific cases"
```

### Custom API Endpoints

For LiteLLM proxy or other compatible endpoints:

```python
client = ClaudeAPIClient(base_url="https://proxy.example.com/v1")
```

Or via environment variable:
```bash
export ANTHROPIC_BASE_URL="https://proxy.example.com/v1"
```
