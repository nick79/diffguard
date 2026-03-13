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

If `--force` doesn't pick up changes (e.g. cached build artifacts), do a full reinstall:

```bash
uv tool uninstall diffguard
uv cache clean diffguard
uv tool install .
```

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

# Show help
diffguard --help

# Show version
diffguard --version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass — no blocking findings (warn/allow findings may still be printed) |
| 1 | Block — findings above severity threshold exist (commit should be rejected) |
| 2 | Error — not a git repo, missing API key, config error, LLM failure, etc. |
| 130 | Interrupted (Ctrl+C) |

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

# LLM sampling temperature (0 = deterministic, higher = more creative)
temperature = 0.0  # default

# Minimum confidence level for findings ("Low", "Medium", "High")
# Set to "Medium" to filter out borderline findings and improve run-to-run consistency
min_confidence = "Low"  # default (keep all findings)

# Maximum concurrent API calls
max_concurrent_api_calls = 5  # default

# API timeout in seconds
timeout = 120  # default

# Patterns identifying third-party code paths (excluded from analysis and symbol resolution)
third_party_patterns = ["venv/", ".venv/", "site-packages/", "node_modules/", "bower_components/", "target/", "build/", ".gradle/", "vendor/bundle/", "vendor/ruby/", ".bundle/", "tmp/cache/", "log/"]  # default

# Path to baseline file (relative to project root)
baseline_path = ".diffguard-baseline.json"  # default

# Additional glob patterns for sensitive file exclusion
# These are added on top of the built-in defaults (.env, *.pem, *.key, etc.)
sensitive_patterns = ["*.secret.json", "**/private/**"]  # default: []

# Whether to include the built-in sensitive file patterns
use_default_sensitive_patterns = true  # default

# Severity thresholds: action per severity level
# Actions: "block" (exit 1), "warn" (print warning, exit 0), "allow" (no output)
[thresholds]
critical = "block"   # default
high = "block"       # default
medium = "warn"      # default
low = "allow"        # default
info = "allow"       # default
```

### Sensitive File Exclusion

Diffguard automatically excludes files matching known secrets patterns from being sent to the LLM. This provides defense-in-depth even if sensitive files are accidentally staged.

**Default patterns include:**
- Environment files: `.env`, `.env.*`, `*.env`
- Private keys: `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, etc.
- Certificates: `*.crt`, `*.p12`, `*.pfx`, `*.jks`
- Secrets files: `secrets.json`, `credentials.json`, `secrets.yaml`, etc.
- Cloud credentials: `.aws/credentials`, `service-account*.json`, etc.
- Infrastructure: `*.tfvars`, `*.tfstate`, etc.

The two settings work together:

| `use_default_sensitive_patterns` | `sensitive_patterns` | Result |
|---|---|---|
| `true` (default) | empty (default) | Built-in patterns only |
| `true` | `["*.custom"]` | Built-in + your custom patterns |
| `false` | `["*.custom"]` | Your custom patterns only |
| `false` | empty | No exclusion (not recommended) |

Built-in patterns are enabled by default for security. To extend them, add your patterns to `sensitive_patterns` — they are appended to the built-in list. To take full control, set `use_default_sensitive_patterns = false` and provide your own complete list.

### Severity Thresholds

Control what happens when findings of each severity level are detected:

| Action | Behavior |
|--------|----------|
| `block` | Finding causes exit code 1 (blocks commit in pre-commit hook) |
| `warn` | Finding is printed with a warning, but does not block |
| `allow` | Finding is included in output but does not block |

Defaults: Critical and High block, Medium warns, Low and Info are allowed. Customize in `.diffguard.toml`:

```toml
[thresholds]
medium = "block"   # upgrade Medium to blocking
high = "warn"      # downgrade High to warning-only
```

Only the levels you specify are overridden — unmentioned levels keep their defaults.

### Severity Classification

Diffguard uses a two-stage approach to classify finding severity:

1. **LLM identifies the vulnerability** — the OpenAI model detects security issues and assigns a CWE identifier (e.g., CWE-89 for SQL Injection).
2. **Deterministic severity mapping** — a built-in CWE-to-severity mapping (295 CWEs) assigns the final severity in code, ensuring the same CWE always gets the same severity regardless of LLM output variance.

This hybrid approach combines the LLM's ability to *find* vulnerabilities with deterministic, standards-based severity assignment. The same codebase will always produce the same severity breakdown across runs.

#### Severity levels

| Level | Description | Examples |
|-------|-------------|----------|
| **Critical** | Unauthenticated RCE, command/code injection, complete auth bypass | OS command injection (CWE-78), eval injection (CWE-95), SSTI (CWE-1336) |
| **High** | Exploitable with significant impact, may require some conditions | SQL injection (CWE-89), XSS (CWE-79), path traversal (CWE-22), SSRF (CWE-918) |
| **Medium** | Conditional exploitation or moderate impact | CSRF (CWE-352), information disclosure (CWE-200), open redirect (CWE-601) |
| **Low** | Minor issues with minimal security impact | Verbose error messages (CWE-209), debug code (CWE-489), obsolete functions |
| **Info** | Best practice recommendations, no direct exploitability | Code quality, insufficient logging, coding standards |

#### Override rules

- **Low confidence cap**: If the LLM has low confidence in a finding, severity is capped at Medium — preventing high-severity alerts on uncertain detections.
- **Unmapped CWEs**: For CWEs not in the built-in map, the LLM's suggested severity is used as a fallback.

#### Sources

The built-in CWE-to-severity mapping covers 295 CWEs compiled from:

- [MITRE CWE Top 25 (2024/2025)](https://cwe.mitre.org/top25/) — most dangerous software weaknesses
- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/) — web application security risks
- [SANS Top 25](https://www.sans.org/top25-software-errors) — most dangerous software errors
- [CWE-1003 Simplified Mapping](https://cwe.mitre.org/data/definitions/1003.html) — commonly mapped CWEs in published vulnerabilities
- SAST tool coverage from SonarQube, Semgrep, CodeQL, Checkmarx, Fortify, GitLab SAST, and Mend SAST

### Baseline Management

Suppress known false positives so they don't appear in future scans. Baselined findings are automatically excluded from scan results, exit code evaluation, and output. If any findings are suppressed, the summary shows the count (e.g., "2 issues found (1 suppressed)").

#### Adding a finding to the baseline

After a scan, use the finding ID shown in the output:

```bash
diffguard baseline add cwe89-a1b2c3d4e5f6a7b8 --reason "Validated input upstream"
```

#### Bulk-adding Low/Info findings

```bash
diffguard baseline add --all-low
```

#### Removing a finding from the baseline

```bash
diffguard baseline remove cwe89-a1b2c3d4e5f6a7b8
```

#### Listing baselined findings

```bash
diffguard baseline list
```

The baseline file defaults to `.diffguard-baseline.json` in the project root. Override with:

```toml
baseline_path = "custom/path/baseline.json"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Your OpenAI API key (required) |

## Supported Languages

Diffguard uses [tree-sitter](https://tree-sitter.github.io/) for AST parsing to build precise context around code changes. Full language support includes scope detection, import extraction, symbol resolution, and first-party/third-party code classification.

| Language | Extensions | AST Support |
|----------|-----------|-------------|
| Python | `.py`, `.pyi` | Full |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` | Full |
| TypeScript | `.ts`, `.mts`, `.cts`, `.tsx` | Full |
| Java | `.java` | Full |
| Ruby | `.rb` | Full |
| Go | `.go` | Full |
| PHP | `.php` | Full |
| HTML & Templates | `.html`, `.htm`, `.ejs`, `.hbs`, `.handlebars`, `.njk`, `.nunjucks`, `.pug`, `.erb`, `.jinja`, `.jinja2`, `.mustache`, `.blade.php` | Analysis-only |
| Makefile | `Makefile`, `makefile`, `GNUmakefile`, `.mk` | Analysis-only |

Files with unsupported or unrecognized extensions are still included in the diff analysis — they just skip AST-based context enrichment and use raw hunk expansion instead.

### Python

**Scope detection:** Functions, async functions, classes, methods, nested definitions. Decorators are included in scope boundaries. Lambdas and comprehensions are not treated as scopes.

**Symbol resolution:** When a changed code region references a symbol imported from a first-party module, diffguard resolves the import to its source file and includes the symbol's definition in the LLM context. This gives the LLM visibility into helper functions, base classes, and utilities that the changed code depends on.

**First-party detection:** Only first-party (project-local) symbols are resolved — third-party and stdlib code is excluded:
- Relative imports (`from .module import X`) are always first-party
- Standard library modules (`os`, `json`, `pathlib`, etc.) are excluded
- Modules whose resolved file path matches a `third_party_patterns` entry are excluded

**Third-party code patterns:** The `third_party_patterns` config controls which paths are excluded from analysis and symbol resolution. Files under these paths are skipped entirely in the pipeline (never sent to the LLM) and are also excluded from symbol resolution. Default patterns for Python:
- `venv/` — standard virtual environment
- `.venv/` — common virtual environment alternative
- `site-packages/` — installed packages

These patterns are matched against file paths. Staged files under these directories are skipped during analysis, and symbols resolving to these directories are not included in the LLM context.

**Module resolution:** Diffguard resolves Python imports to file paths using standard conventions:
- `module.py` — single-file modules
- `module/__init__.py` — package modules
- `src/module.py` and `src/module/__init__.py` — src layout projects

### JavaScript

**Scope detection:** Functions, arrow functions, function expressions, generator functions, async functions, classes, and methods. Arrow functions and function expressions assigned to variables inherit the variable name. Anonymous callbacks get `<anonymous>`.

**Symbol resolution:** When a changed code region references a symbol imported from a first-party module, diffguard resolves the import to its source file. Both ES6 imports (`import { x } from './utils'`) and CommonJS (`const x = require('./utils')`) are supported. Dynamic `import()` expressions are also detected.

**First-party detection:** Only first-party (project-local) symbols are resolved — third-party packages are excluded:
- Relative imports (`./utils`, `../lib`) are always first-party
- Bare specifiers matching the `name` field or `workspaces` entries in `package.json` are first-party
- All other bare specifiers (e.g., `lodash`, `express`) are treated as third-party

**Third-party code patterns:** Default patterns for JavaScript:
- `node_modules/` — npm/yarn installed packages
- `bower_components/` — Bower installed packages

**Generated file detection:** Minified and bundled JavaScript files are automatically excluded from analysis:
- Filename patterns: `.min.js`, `.min.mjs`, `.min.cjs`, `.bundle.js`, `.chunk.js`
- Content heuristic: files with average line length > 500 characters

**Module resolution:** Diffguard resolves JavaScript imports using standard Node.js conventions:
- `./module.js` — exact file path
- `./module` — tries `.js`, `.mjs`, `.cjs`, `.jsx` extensions
- `./lib` — tries `index.js` in directory (index convention)

### TypeScript

**Scope detection:** Typed functions, arrow functions with type annotations, function expressions, generator functions, async functions, classes (including generics), methods, and namespaces. Extends JavaScript scope detection patterns with TypeScript-specific constructs.

**Symbol resolution:** When a changed code region references a symbol imported from a first-party module, diffguard resolves the import to its source file. Both ES6 imports and CommonJS `require()` calls are supported. Type-only imports (`import type { ... }`) and inline type imports (`import { type Foo, bar }`) are recognized and excluded from runtime symbol resolution — only value imports are resolved.

**First-party detection:** Same rules as JavaScript — relative imports are first-party, bare specifiers are checked against `package.json` name/workspaces:
- Relative imports (`./utils`, `../lib`) are always first-party
- Bare specifiers matching the `name` field or `workspaces` entries in `package.json` are first-party
- All other bare specifiers (e.g., `lodash`, `@types/node`) are treated as third-party

**Third-party code patterns:** Same as JavaScript:
- `node_modules/` — npm/yarn installed packages
- `bower_components/` — Bower installed packages

**Generated file detection:** Generated TypeScript files are automatically excluded from analysis:
- Declaration files (`.d.ts`, `.d.mts`, `.d.cts`) with generated headers (`// Generated by`, `// Auto-generated`) in the first 5 lines
- Content heuristic: files with average line length > 500 characters (minified/bundled)
- Note: `.d.ts` files in `node_modules/` are already skipped by vendor path filtering

**Module resolution:** Diffguard resolves TypeScript imports using standard conventions:
- `./module.ts` — exact file path
- `./module` — tries `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.mjs`, `.cjs`, `.jsx` extensions
- `./lib` — tries `index.ts`/`index.tsx`/etc. in directory (index convention)

### Java

**Scope detection:** Classes, interfaces, enums, methods, constructors, static methods, inner classes, and lambdas. Annotations (e.g., `@Override`, `@Service`) are included in scope boundaries as part of the method/class declaration.

**Symbol resolution:** When a changed code region references a symbol imported from a first-party package, diffguard resolves the import to its source file. Both regular imports (`import com.example.Helper;`) and static imports (`import static com.example.Utils.format;`) are supported. Wildcard imports (`import com.example.*;`) are also detected.

**First-party detection:** Only first-party (project-local) symbols are resolved — standard library and third-party code is excluded:
- Standard library packages (`java.*`, `javax.*`, `jdk.*`, `com.sun.*`) are excluded
- Project base package is detected from `pom.xml` (`<groupId>`), `build.gradle`/`build.gradle.kts` (`group`), or inferred from `src/main/java/` directory structure
- Imports matching the project base package are first-party
- Imports resolvable to files under `src/main/java/` or `src/test/java/` are first-party

**Third-party/build output paths:** Default patterns for Java:
- `target/` — Maven build output
- `build/` — Gradle build output
- `.gradle/` — Gradle cache directory

**Generated file detection:** Generated Java files are automatically excluded from analysis:
- Path patterns: `**/generated-sources/**`, `**/generated/**`, `**/apt_generated/**` (annotation processor output)
- Content heuristic: files with `@Generated` annotation in the first 20 lines

**Module resolution:** Diffguard resolves Java imports using standard Maven/Gradle conventions:
- `com.example.MyClass` → `src/main/java/com/example/MyClass.java`
- Also tries `src/test/java/` and `src/` layouts

### Ruby

**Scope detection:** Methods (`def`), class methods (`def self.method`), classes, modules, blocks (`do...end` / `{ }`), and lambdas (`->`). Nested modules and classes are correctly resolved to the innermost scope.

**Symbol resolution:** When a changed code region references a symbol imported via `require` or `require_relative`, diffguard resolves the import to its source file. Ruby's snake_case-to-CamelCase naming convention is used to match class names to file names (e.g., `require 'my_helper'` resolves symbol `MyHelper`).

**First-party detection:** Only first-party (project-local) symbols are resolved — standard library and third-party gems are excluded:
- `require_relative` imports are always first-party
- Standard library modules (`json`, `net/http`, `fileutils`, etc.) are excluded
- Gems listed in `Gemfile` are treated as third-party
- `require` calls that resolve to a local file (under `lib/`, `app/`, or project root) are first-party

**Third-party/vendor paths:** Default patterns for Ruby:
- `vendor/bundle/` — Bundler gem install location
- `vendor/ruby/` — Alternative Bundler path
- `.bundle/` — Bundler metadata

**Generated file detection:** Generated Ruby files are automatically excluded from analysis:
- `db/schema.rb` — Rails auto-generated schema dump
- Content heuristic: files with `# This file is auto-generated`, `# Generated by`, or `# DO NOT EDIT` in the first 5 lines

**Module resolution:** Diffguard resolves Ruby imports using standard conventions:
- `require_relative './helper'` — relative to current file, tries `.rb` extension
- `require 'my_app/helper'` — tries `lib/my_app/helper.rb`, `my_app/helper.rb`, `app/my_app/helper.rb`

#### Ruby Framework Support

**Rails:** Diffguard detects Rails projects (via `config/application.rb`) and adds Zeitwerk-style autoload resolution. When a changed region references a class with no explicit `require`, diffguard resolves it via Rails conventions:
- `User` → `app/models/user.rb`
- `UsersController` → `app/controllers/users_controller.rb`
- `Admin::DashboardController` → `app/controllers/admin/dashboard_controller.rb`
- `UserMailer` → `app/mailers/user_mailer.rb`
- `UserJob` → `app/jobs/user_job.rb`

Additional excluded paths for Rails projects: `tmp/cache/`, `log/`

Additional generated file detection: `db/migrate/*.rb` files with `# This migration was auto-generated` header

**Sinatra / Padrino:** Fully supported via base Ruby support — route blocks are captured as block scopes, and explicit `require` statements are handled by the standard Ruby import extraction.

### Go

**Scope detection:** Functions, methods (value and pointer receivers), anonymous functions (goroutines), and init functions. Go does not have classes — struct types are defined at package level and are not treated as scopes.

**Symbol resolution:** When a changed code region references a symbol imported from a first-party package, diffguard resolves the import to its source file. Both single imports (`import "fmt"`) and grouped imports (`import (...)`) are supported, including aliased imports (`import f "fmt"`), blank/side-effect imports (`import _ "database/sql"`), and dot imports (`import . "strings"`).

**First-party detection:** Only first-party (project-local) symbols are resolved — standard library and third-party code is excluded:
- Standard library packages (no dots in import path: `fmt`, `net/http`, `crypto/tls`) are excluded
- The module path is read from `go.mod` (e.g., `module github.com/myorg/myapp`)
- Imports prefixed with the module path are first-party
- All other imports (with dots but not matching module path) are third-party

**Third-party/vendor paths:** Default patterns for Go:
- `vendor/` — Go modules vendor directory

**Generated file detection:** Generated Go files are automatically excluded from analysis:
- `// Code generated ... DO NOT EDIT.` convention (the standard `go generate` header, as first content line after optional build tags)
- Filename patterns: `*.pb.go` (protobuf), `*_string.go` (stringer), `mock_*.go`/`*_mock.go` (mock generators), `*_gen.go` (general generated suffix)

**Module resolution:** Diffguard resolves Go imports using `go.mod` module path:
- `github.com/myorg/myapp/internal/utils` → `internal/utils/*.go` (first non-test `.go` file in the package directory)

### PHP

**Scope detection:** Functions, methods (public/private/protected/static), classes, traits, interfaces, anonymous functions (closures with `use` clause), and arrow functions (PHP 7.4+). Constructors (`__construct`) are detected as methods.

**Symbol resolution:** When a changed code region references a symbol imported via `use` statements, diffguard resolves the import to its source file using PSR-4 autoload conventions. Both `use` class imports and grouped use statements (`use App\Models\{User, Post}`) are supported. `require`/`include` and their `_once` variants are also detected.

**First-party detection:** Only first-party (project-local) symbols are resolved — third-party packages are excluded:
- `use` statements matching PSR-4 namespace prefixes from `composer.json` are first-party
- `require`/`include` with relative paths (`./`, `../`, `__DIR__`) are first-party
- All other `use` statements (e.g., `Symfony\...`, `Laravel\...`) are treated as third-party

**Third-party/vendor paths:** Default patterns for PHP:
- `vendor/` — Composer installed packages

**Generated/cache file detection:** Generated and cached PHP files are automatically excluded from analysis:
- Path patterns: `var/cache/` (Symfony), `bootstrap/cache/` (Laravel), `storage/framework/cache/` (Laravel)
- Content heuristic: files with `<?php // auto-generated`, `@generated`, or similar markers in the first 5 lines

**Module resolution:** Diffguard resolves PHP imports using PSR-4 conventions from `composer.json`:
- `App\Services\UserService` with `{"App\\": "src/"}` → `src/Services/UserService.php`
- Also tries `src/`, `app/`, `lib/` directories as fallbacks

### HTML & Templates

**Analysis-only support.** HTML and common template file formats are detected and sent to the LLM for security analysis with raw hunk expansion. No AST-based scope detection, import extraction, or symbol resolution is performed.

**Extensions:** `.html`, `.htm`, `.ejs`, `.hbs`, `.handlebars`, `.njk`, `.nunjucks`, `.pug`, `.erb`, `.jinja`, `.jinja2`, `.mustache`, `.blade.php`

**Blade templates:** Files ending in `.blade.php` are detected as HTML templates (analysis-only), not as PHP files. This ensures Blade templates get XSS-focused analysis rather than full PHP AST parsing. Regular `.php` files are unaffected.

**Key XSS surfaces detected by the LLM:**
- EJS: `<%- userInput %>` (unescaped output)
- Jinja2/Nunjucks: `{{ var | safe }}`, `{% autoescape false %}`
- Handlebars/Mustache: `{{{ raw }}}` (triple-brace unescaped)
- Pug: `!{userInput}` (unescaped interpolation)
- ERB: `<%= raw_html %>` combined with `html_safe`
- Blade: `{!! $variable !!}` (unescaped), `@php` blocks

**Generated file detection:** Minified HTML files (average line length > 500 characters) are automatically excluded from analysis.

### Makefile

**Analysis-only support.** Makefiles are detected by filename (`Makefile`, `makefile`, `GNUmakefile`) or extension (`.mk`) and included in diff analysis with raw hunk expansion. No AST-based scope detection, import extraction, or symbol resolution is performed — the LLM analyzes the raw code context directly.

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
