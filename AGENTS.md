# Project Rules and Constraints

## Automated Fly.io Execution Strictly Forbidden
- Automated agents and tools must **NOT** execute `fly deploy`, `flyctl deploy`, or any `fly` CLI commands.
- Fly.io deployment templates and scripts (`fly.toml`, `fly.toml.example`, `scripts/deploy.sh`) are maintained solely for developer local manual use.
- All Fly.io configuration files and scripts must remain git-ignored (`.gitignore`) and must never be tracked or committed to the repository.
- Public deployments and releases are managed strictly through standard Docker container builds (`ghcr.io/0abir/amardns:latest`) and GitHub Actions.
