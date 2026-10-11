# Contributing

Thank you for considering a contribution to Web Security Checker.

## Before You Start

- Only use the project against websites and systems you own or are explicitly authorized to inspect.
- Keep changes focused and explain their purpose.
- Do not include credentials, tokens, private URLs, or other sensitive data in commits, issues, or pull requests.

## Development Setup

```bash
git clone https://github.com/AetherisV/Web-Security-Checker.git
cd Web-Security-Checker
python -m venv .venv
```

Activate the environment, then install dependencies:

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Testing

Run the test suite before submitting a change:

```bash
python -m pytest
```

Also check changed files for whitespace errors:

```bash
git diff --check
```

## Pull Requests

- Use a clear, concise title.
- Describe the problem and the proposed change.
- Add or update tests when behavior changes.
- Update documentation when commands, options, output, or policy behavior changes.
- Confirm that `python -m pytest` passes.
- Keep pull requests small enough to review.

## Reporting Security Issues

Do not open a public issue for suspected vulnerabilities. Follow the instructions in [SECURITY.md](SECURITY.md).
