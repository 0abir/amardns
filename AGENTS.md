# Project Rules and Constraints

## ⛔ Strictly Forbidden: Fly.io Deployment
- **DO NOT** under any circumstances run `fly deploy`, `flyctl deploy`, or any `fly` CLI commands.
- **DO NOT** recreate `fly.toml` or `scripts/deploy.sh`.
- Fly.io deployment has been permanently retired and disabled for this project.
- Deployments and releases are managed strictly through standard Docker container builds (`ghcr.io/0abir/amardns:latest`) and GitHub Actions.
