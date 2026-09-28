# Project Rules and Constraints

## Fly.io Deployment
- Fly.io deployment templates and scripts (`fly.toml`, `fly.toml.example`, `scripts/deploy.sh`) are maintained for developer and operational use.
- All Fly.io configuration files and scripts must remain git-ignored (`.gitignore`) and must never be tracked or committed to the repository.
- Public deployments and releases are managed through standard Docker container builds (`ghcr.io/0abir/amardns:latest`) and GitHub Actions.
