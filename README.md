# Diffguard

LLM-powered security review of staged git diffs.

Diffguard builds surgical context around your code changes (expanding hunks, resolving scopes and symbols via tree-sitter), sends compact context to OpenAI, and returns actionable security findings aligned with OWASP/CWE.

## Installation

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```bash
# Clone the repository
git clone https://github.com/yourusername/diffguard.git
cd diffguard

# Install as a global CLI tool
uv tool install .
```

This installs `diffguard` as a globally available command. The `uv tool install` command:
- Creates an isolated virtual environment for diffguard
- Installs all dependencies
- Makes the `diffguard` command available system-wide

### Setting up your API key

Diffguard requires an OpenAI API key. Export it in your shell:

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.) for persistence
export OPENAI_API_KEY=sk-your-key-here
```

### Updating diffguard

When new changes are available:

```bash
cd /path/to/diffguard
git pull
uv tool install . --force
```

The `--force` flag reinstalls the tool even if it's already installed, picking up any new changes.

## Usage

Navigate to any git repository, stage your changes, and run diffguard:

```bash
cd /path/to/your/project

# Stage your changes
git add -p

# Run security analysis
diffguard

# Dry run (see what would be analyzed without calling the LLM)
diffguard --dry-run

# Output as JSON
diffguard --json

# Save report to file
diffguard --output report.json

# Verbose output
diffguard --verbose
```

## Configuration

Create a `.diffguard.toml` file in your project root (or any parent directory) to customize settings. All settings are optional and have sensible defaults.

```toml
# LLM model to use for analysis
model = "gpt-5.2"  # default

# Number of lines to expand around each changed hunk for context
hunk_expansion_lines = 50  # default

# Maximum lines for scope extraction before truncation
scope_size_limit = 200  # default

# How deep to follow imports for symbol resolution
symbol_resolution_depth = 1  # default

# Maximum concurrent API calls
max_concurrent_api_calls = 5  # default

# API timeout in seconds
timeout = 120  # default

# Patterns identifying third-party code paths (excluded from symbol resolution)
third_party_patterns = ["venv/", ".venv/", "site-packages/", "node_modules/"]  # default
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Your OpenAI API key (required) |

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Type check
uv run mypy .
```

## License

PolyForm Noncommercial License 1.0.0 - see [LICENSE](LICENSE) for details.
