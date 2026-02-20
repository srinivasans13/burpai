# burpai — AI Pentest Agent for Burp Suite

A **Burp Suite extension** built on the [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/) that brings two AI-powered capabilities into Burp:

| Feature | Where it lives | What it does |
|---|---|---|
| **AI Pentester** | Suite tab | Autonomous agentic loop — generates test ideas, fires requests through Burp, tracks findings |
| **Repeater Copilot** | Inside every Repeater tab | Watches each request/response cycle, suggests the next security test, injects the suggested request directly into Repeater |

LLM backend: **Ollama** by default (local, no cloud required). Anthropic Claude is also supported via `config/burp_ai_config.json`.

---

## Requirements

- Burp Suite Community or Pro — 2023.x or newer
- Java 21+ (build-time and runtime)
- [Ollama](https://ollama.com/) running locally, or an Anthropic API key

---

## Quick start

### 1. Start Ollama and pull a model

```bash
ollama serve
ollama pull qwen3-coder-next:cloud
```

### 2. Build the fat JAR

```powershell
.\gradlew.bat jar --no-daemon
```

Output: `dist/burp-ai-pentester-fat.jar` (all dependencies bundled).

> **OneDrive users:** If Gradle locks up on cache files, run with `--no-build-cache` as well.

### 3. Load in Burp

Burp  **Extensions  Installed  Add**
Extension type: **Java**
Path: `dist/burp-ai-pentester-fat.jar`

---

## Feature: AI Pentester (suite tab)

An autonomous agent that tests a target application end-to-end.

**Workflow:**
1. Open the **AI Pentester** tab in Burp
2. Set Ollama URL and model
3. Enter a target base URL and a task prompt
4. Optionally right-click any Burp request  **Send to AI Pentester** to seed context
5. Click **Start Agent**

**What it does:**
- Calls an `execute_http_request` tool in a loop — all traffic flows through Burp
- Maintains run memory: avoids repeating tested endpoints, detects WAF/rate-limit patterns
- Calls `report_vulnerability` when it confirms an issue
- Logs everything to `~/burpai_logs/` and the in-tab panel

---

## Feature: Repeater Copilot (embedded in Repeater)

An AI assistant embedded **inside every Repeater tab** — appears as an **AI Copilot** tab alongside Raw / Pretty / Hex.

**Workflow:**
1. Send any request in Repeater as normal — the copilot auto-triggers on each response
2. The AI Copilot tab shows its **reasoning** and a **suggested next test request**
3. The suggested request is immediately visible in Raw / Pretty / Hex — with all original auth headers preserved
4. Click **Approve** to lock in the suggestion, then click Burp's **Send** to fire it
5. Use **Analyze Again** to get a fresh AI suggestion, or **Reject** to discard

**Key behaviours:**
- All original headers (Authorization, Cookie, session tokens) are always preserved — the AI only overlays what changed
- The optional Prompt / Focus field steers the AI (e.g. "focus on IDOR only")
- One independent copilot instance per Repeater tab

---

## Configuration

`config/burp_ai_config.json` controls the AI Pentester defaults:

```json
{
  "llm_provider": "ollama",
  "ollama_base_url": "http://localhost:11434",
  "ollama_model": "qwen3-coder-next:cloud",
  "anthropic_api_key": "",
  "target_base_url": "https://example.com/",
  "max_iterations": 20
}
```

The Repeater Copilot URL and model are configured in its own UI panel per-session.

---

## Repo layout

```
src/main/java/com/burpai/aipentester/
  Extension.java             — Montoya entrypoint; registers both features
  AgentTab.java              — AI Pentester suite tab UI
  AgentEngine.java           — Autonomous agent loop + tool execution
  OllamaClient.java          — Ollama HTTP client with retry logic
  RepeaterCopilot.java       — Per-tab AI analysis engine (Repeater Copilot)
  RepeaterCopilotEditor.java — ExtensionProvidedHttpRequestEditor implementation
  Imported.java              — Models a request imported via Burp context menu
  ToolResult.java            — Tool call result model

config/
  burp_ai_config.json        — AI Pentester defaults (LLM provider, model, target)

resources/
  burp-ai-agent-prompt.md    — Agent system prompt template

legacy_python/
  BurpAgenticPentester.py    — Original Jython version (requires Jython in Burp)
```

---

## Responsible use

Use only against systems you own or have **explicit written permission** to test.

Do not commit real API keys, session tokens, cookies, or target-specific data to this repository.