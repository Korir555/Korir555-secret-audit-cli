# Secret Audit CLI

`secret_audit_cli.py` is a defensive scanner for finding likely leaked credentials in repositories, env files, cloud configs, and local tool configuration. It redacts evidence by default and emits stable fingerprints so you can deduplicate findings without printing the secret itself.

## Quick start

```bash
python3 secret_audit_cli.py /path/to/repo
```

Scan the current repo and common home config locations:

```bash
python3 secret_audit_cli.py . --include-home-configs --password-store-summary
```

Use JSON in CI and fail the job if anything is found:

```bash
python3 secret_audit_cli.py . --json --fail-on-findings
```

## What it checks

- Known token formats: AWS, GitHub, GitLab, Slack, Stripe, Google API keys, JWTs, private key headers.
- Suspicious key/value assignments such as `API_KEY=...`, `password: ...`, `client_secret=...`.
- High-entropy blobs that often indicate tokens or encoded secrets.
- Optional cloud and tool configs such as AWS, Azure, gcloud, Docker, kubeconfig, npm, PyPI, gh, and `.netrc`.
- Optional password store summary for `pass`, Bitwarden CLI, and 1Password CLI without decrypting or printing stored passwords.

## Cleanup workflow

1. Remove the secret from the file and from git history if it was committed.
2. Rotate the credential with the provider. Treat committed secrets as compromised.
3. Re-run this scanner and a specialized tool such as `gitleaks` or `trufflehog`.
4. Add pre-commit and CI checks to prevent future leaks.

## Notes

This tool favors useful signal over perfect classification. Review each finding before taking action, and tune the patterns if your codebase has expected test tokens.
