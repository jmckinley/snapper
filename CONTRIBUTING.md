# Contributing to Snapper

Thank you for your interest in contributing to Snapper. This document covers the process for contributing code, reporting bugs, and suggesting features.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/snapper.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Start the development environment: `docker compose up -d`
5. Make your changes
6. Run tests: `docker compose exec app pytest tests/ -v`
7. Push and open a pull request

## Developer Certificate of Origin (DCO)

All contributions to Snapper must include a `Signed-off-by` line in the commit message, certifying that you have the right to submit the contribution under the project's PolyForm Noncommercial License.

### What is the DCO?

The [Developer Certificate of Origin](https://developercertificate.org/) (DCO) is a lightweight way to certify that you wrote or have the right to submit code. By adding a `Signed-off-by` line, you attest to the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to Sign Off

Add `-s` to your `git commit` command:

```bash
git commit -s -m "Add feature X"
```

This produces a commit message like:

```
Add feature X

Signed-off-by: Your Name <your.email@example.com>
```

If you forgot to sign off, amend the last commit:

```bash
git commit --amend -s
```

### Enforcement

Pull requests without DCO sign-off will not be merged. The [DCO Probot](https://github.com/apps/dco) checks all commits automatically.

## Code Guidelines

### Style

- **Python:** Follow PEP 8. Use `black` for formatting, `flake8` for linting.
- **Tests:** Every new feature or bug fix should include tests.
- **Commits:** Write clear, concise commit messages. Use imperative mood ("Add feature" not "Added feature").

### Running Checks

```bash
# Format
docker compose exec app black app/ tests/

# Lint
docker compose exec app flake8 app/ tests/

# Type check
docker compose exec app mypy app/

# Test
docker compose exec app pytest tests/ -v
```

### Testing

- Unit tests go in `tests/test_*.py`
- E2E tests go in `tests/e2e/test_*.py`
- Use the existing fixtures in `tests/conftest.py`
- Async tests use `@pytest.mark.asyncio`
- Aim for the test to verify real behavior, not mock internals

## Reporting Bugs

Open an issue at https://github.com/jmckinley/snapper/issues with:

- Steps to reproduce
- Expected vs actual behavior
- Snapper version / commit hash
- Docker and OS version

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the PolyForm Noncommercial License 1.0.0.
