# HEX ALERT local AI

## Daily use

Open **Dashboard → AI Settings**. Local GGUF is the default. Wait for **ready**, then use
`/ask`, `/model`, `/ai-status`, or `/reset-chat` in Discord. `/ask` acknowledges the interaction
immediately while generating. Answers are split to respect Discord's message limit.
Optional direct mention chat is off by default and can be enabled in AI Settings.
No Message Content, Members, or Presence privileged intent is requested for these commands.
Direct @mentions use Discord's mentioned-message content exception.

TEST_MODE remains on. AI replies to explicitly initiated conversations; this does not enable
scheduled production alert delivery. No shell execution or administrative model tools exist.

## Model and runtime

`CyberSecurity.gguf` remains in the project root, mounted read-only at
`/models/CyberSecurity.gguf`. It is excluded from both Docker build contexts.
The `llm` service runs a pinned official llama.cpp binary in a separate non-root container.
No inference port is published. The bot accesses it on the Compose network.
The model loads once, stays resident, and warms up before becoming ready.
Bot/dashboard startup does not depend on AI readiness.

The installed model reports Qwen3 architecture, file type 15 (Q4_K_M), native context 262144,
EOS token 151645, no BOS ID, and no embedded chat template. Default serving context is 4096;
the configurable ChatML fallback is used because this file has no template. The model's training
provenance and licensing are not embedded in the application and have not been independently verified.

The portable image uses CPU. It selects physical-core count minus one, capped at eight threads.
Dashboard settings control sampling, output/context limits, CPU threads, batch, queue, memory,
and GPU layers. Engine-level changes reload the model; provider changes require no Docker rebuild.
The supervisor tries CPU if CUDA offloading fails, and retries a crashed child up to three times.
Click **Save and apply settings** to retry after fixing a model/runtime error.

An optional `docker-compose.cuda.yml` uses a pinned CUDA build and `gpus: all`. It requires
Docker Desktop WSL2 GPU support and compatible NVIDIA drivers. CPU remains the tested default;
the CUDA override is not a claim of validated GPU performance. Do not apply it on machines without
GPU container support. Selecting CUDA in the CPU image safely reports CPU fallback.

## Privacy, configuration, and fallbacks

Provider choices and non-secret settings are stored in `hex_runtime_config/runtime.json` as
`AI_OPTIONS`. API keys use the existing AES-GCM encrypted runtime store, including `CUSTOM_API_KEY`.
Keep the stable bootstrap `SESSION_SECRET` outside the image and preserve it with secure backups;
changing or losing it makes encrypted runtime credentials unreadable. Never publish this volume.
The separate `llm_state` volume contains engine preferences only, never API keys or prompts.

Blank key fields preserve credentials; **Clear saved key** removes the provider key. API responses
return configured booleans, never saved keys. Provider switching clears conversation memory.
History is bounded to 500 conversations, a maximum of 20 recent messages, a conservative byte budget,
and a 30-minute inactivity TTL. It is process-local and disappears on restart. `/reset-chat` clears
the caller's current channel conversation. There is no training or prompt persistence.

External fallback is off by default. It requires an enabled provider and explicit dashboard confirmation.
Testing an external provider sends the displayed test question to it; no provider is tested silently.
For Custom API, supply a trusted OpenAI-compatible base URL including `/v1`.
Ollama normally uses `http://host.docker.internal:11434` from Docker.
External model names are editable because availability depends on provider accounts.

Collector AI summaries are optional and off by default so collection cannot monopolize the local model.
When enabled they run only while chat is idle, use a short timeout, and fall back to source text.

## Context and metrics

Questions about latest/current CVEs, news, jobs, threats, tools, or research query stored PostgreSQL
records first. “Today” uses the configured application timezone. This is bounded read-only retrieval,
not vector search or an internet browsing agent. Empty/unavailable data is explicitly labeled.
Source URLs and publication dates accompany retrieved context. Model answers can still be incorrect;
the local model's first general-question test was correct, while a later response invented a quotation.
Check cited primary records when using factual claims. No source-independent accuracy guarantee is made.

`/health` exposes a safe `ai` provider/model/status/backend object. AI Settings shows queue, RAM,
model metadata, and safe metrics. PostgreSQL `system_logs` stores `AI_CHAT` metrics and Discord
delivery IDs/status only; prompt and answer bodies are omitted. Daily metrics use UTC and are capped
to 10,000 records in the dashboard query. Metrics follow the existing system log retention policy.

## Deployment and checks

```powershell
docker compose config --quiet
docker compose up -d --build
docker compose ps
node --check api/static/ai-settings.js
python -m pytest -v
```

Model startup failures appear in AI Settings. Check RAM, file readability, GGUF validity and the
selected fallback template. Leave the existing PostgreSQL and runtime volumes intact.
Never use `docker compose down -v` for an AI update.

Reference runtime behavior: https://github.com/ggml-org/llama.cpp/tree/master/tools/server
