# Contributing to otvoren-vot

## Welcome

otvoren-vot is an open-source e-voting system intended for use in Bulgarian national elections. This is security-critical infrastructure — every contribution is scrutinized with that responsibility in mind. We welcome contributions from developers, cryptographers, security researchers, and domain experts, and we ask that all contributors approach this project with the same seriousness we do.

By contributing, you accept that your changes may be subject to extended review, independent audit, or formal verification before merging.

---

## Development Setup

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Go | 1.22+ |
| Node.js | 20+ |
| Python | 3.12+ |
| Docker | 24+ |
| PostgreSQL | 16+ |

### Getting Started

```bash
git clone https://github.com/otvoren-vot/otvoren-vot.git
cd otvoren-vot
cp .env.example .env
docker compose up -d postgres
make setup
```

Refer to `docs/` for component-specific setup instructions.

---

## Code Style

### Go

- Format with `gofmt` before every commit.
- Pass `go vet ./...` with zero warnings.
- Use `golangci-lint run` for extended static analysis (config in `.golangci.yml`).

### TypeScript

- ESLint with `strict` mode enabled (config in `.eslintrc.json`).
- Prettier for formatting (config in `.prettierrc`).
- No `any` types without an explicit, documented justification.

### Python

- Format with `black`.
- Lint with `ruff` (config in `pyproject.toml`).
- Type annotations required on all public functions.

---

## Branch Strategy

- `main` is a protected branch. Direct pushes are not permitted.
- Create feature branches from `main`: `feature/<short-description>`.
- For bug fixes: `fix/<short-description>`.
- For security patches: `security/<short-description>` — these follow an expedited review path.
- All merges to `main` use squash merges to keep history linear and auditable.

---

## Pull Request Process

### Before Opening a PR

1. Ensure all tests pass locally: `make test`.
2. Run linters: `make lint`.
3. Verify your build is reproducible (see [Reproducible Builds](#reproducible-builds)).
4. For any change touching cryptographic code or key management, open a discussion issue first.

### PR Description Template

```
## What
Brief description of the change.

## Why
The motivation or problem this change addresses.

## How
A summary of the technical approach taken.

## Testing
How the change was tested. Include test names or coverage data where relevant.
```

### Review Requirements

- All PRs require at least one approving review before merge.
- PRs touching cryptographic primitives, authentication, or key management require **two** approving reviews, at least one from a designated security reviewer.
- Reviewers may request formal justification or additional test coverage at their discretion.

---

## Testing

Test-driven development is expected. Write tests before writing implementation code.

- Unit tests live alongside the code they test.
- Integration and end-to-end tests live under `tests/`.
- Run the full suite: `make test`.
- Run tests for a specific component: `make test-<component>` (see `Makefile` for targets).
- Aim for meaningful coverage — coverage for its own sake is not the goal.

---

## Reproducible Builds

All release artifacts must be reproducible. To verify:

```bash
# Build the Docker image
docker build -t otvoren-vot:local .

# Extract and hash the binary
docker run --rm otvoren-vot:local sha256sum /app/server

# Compare against the published hash in releases/checksums.txt
```

If your change affects the build process, update `releases/checksums.txt` and document what changed and why in the PR.

---

## Security

- **No secrets in code.** No API keys, passwords, certificates, or cryptographic material may appear in source files or commit history.
- **No hardcoded configuration** that varies by environment. Use environment variables or the config system.
- **Cryptographic changes** (algorithms, key sizes, protocols, random number generation) require:
  - A discussion issue opened before any code is written.
  - Formal documentation of the cryptographic rationale.
  - Review and approval by **two** designated security reviewers.
- If you discover a security vulnerability in this project, do not open a public issue. Follow the [responsible disclosure policy](SECURITY.md).

---

## Code of Conduct

This project adheres to the [Contributor Covenant, version 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this standard. Instances of unacceptable behavior may be reported to the project maintainers.
