# Security Policy

## Reporting a vulnerability

Please do not publish exploitable details, credentials, private Discord data, or deployment logs in a public issue. Contact the project maintainer through a private channel associated with the repository, or use GitHub's private vulnerability reporting feature if it is enabled. Include a concise impact summary and reproduction steps that do not expose real user data.

## Deployment guidance

- Keep `.env`, runtime configuration, database files, backups, and logs private.
- Use unique, strong secrets and restrict dashboard access to trusted operators.
- Run the dashboard on a trusted network and keep the application updated.
- Use least-privilege Discord permissions and a dedicated test channel.
- Keep `TEST_MODE=true` until channel routing and permissions have been reviewed.
- Only configure public sources that you are permitted to access.

Security fixes should avoid including live credentials, private user data, or sensitive production artifacts in commits and test fixtures.
