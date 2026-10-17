## Summary

<!-- What changed and why? -->

## Validation

- [ ] `python -m compileall .`
- [ ] `python -m pytest -v`
- [ ] `docker compose config`
- [ ] Frontend syntax/build check (when applicable)
- [ ] Live service validation described separately from mocked tests

## Security and rollout

- [ ] No secrets, private identifiers, logs, backups, database files, or model weights added
- [ ] TEST_MODE remains enabled unless the change explicitly concerns another environment
- [ ] User-visible and operational limitations are documented
