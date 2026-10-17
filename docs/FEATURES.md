# Feature guide

HEX ALERT brings public security intelligence and Discord operations into a self-hosted workspace. Availability depends on configured feeds, permissions, credentials, and hardware.

| Workspace | What it does | Operator controls |
| --- | --- | --- |
| Dashboard & health | Collection totals, service state, latest records, source failures | Refresh, service diagnosis, local health endpoint |
| Sources | Public RSS/Atom, JSON and supported employer boards | Test, normalized preview, save disabled, explicit enable |
| Job intelligence | Lever, Greenhouse, Ashby, Remote OK and permitted public career pages | Role/location/experience filters, freshness, score, baseline, suppression |
| CVEs | NVD and CISA KEV ingestion | Critical thresholds, verified exploitation context, category routing |
| News & threats | Configured security feeds with source links | Deduplication, classification, polling and review |
| Crawlers | Bounded public-site fetching and change monitoring | Robots checks, selectors, depth/page limits, pause/resume |
| Discord | Persistent bot configuration and database channel mappings | Permission checks, test channel, explicit mapped-route tests |
| Alert history | Delivery state and message identifiers | Inspect failures and resolved channels |
| Automation | Rules, schedules, community messages and Channel Pulse | Per-channel settings, quiet hours, activity skip, daily limits |
| Command & embed builders | Custom slash responses and embed templates | Validation, access controls, cooldowns |
| AI assistant | HEX ALPHA identity with Local GGUF and optional external adapters | Provider, model, system prompt, streaming, bounded memory, retrieval |
| Accounts & security | Admin sign-in, optional PIN and TOTP, local recovery tools | Session management, recovery, audit events |
| Backup | ZIP export/restore workflow with manifest validation | Pre-restore backup, history and explicit confirmation |
| Windows control center | Native Windows Forms launcher | Start/stop/restart, tray, service health, logs |

## Collection to Discord

1. Enable a permitted source after reviewing its parser preview.
2. Collect and normalize the source item.
3. Deduplicate it and store it in PostgreSQL.
4. Apply category rules and eligibility filters.
5. Resolve the category's saved PostgreSQL channel mapping.
6. Check destination permissions, deliver the embed, and record the result.

**Test mode:** scheduled production deliveries are suppressed. Test Alert controls target the dedicated test channel. Explicit mapped-route tests send a clearly labeled test to the selected category channel. No missing mapping silently falls back to the test channel.

## Local AI boundaries

HEX ALPHA is the assistant's product identity, operated by HEX SECURITY. This deployment supports Qwen-family GGUF inference through llama.cpp. Product branding does not imply the base model was trained by HEX SECURITY.

The optional local service stays resident, accepts streamed requests, and has independent health. Chat supports bounded conversation history and read-only retrieval of stored intelligence. External providers and fallback require explicit configuration. Discord conversations do not execute arbitrary shell commands or model-generated administrative actions.

**Model weights are not distributed in this repository or its releases.** Supply a compatible, properly licensed model separately.

## Collection boundaries

LinkedIn, Indeed, Glassdoor and other restricted platforms are not treated as unrestricted scraping sources. Use permitted interfaces, approved feeds, or manually supplied public references. Missing salary, experience, publication dates, or exploitation evidence must remain unknown rather than being invented.
