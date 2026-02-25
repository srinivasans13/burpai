# Copilot Instructions — burpai

## Project Overview

burpai is an autonomous AI pentesting agent built as a **Burp Suite extension** using the **Montoya API** (Java). It embeds an agentic LLM loop directly into Burp — firing real HTTP requests through Burp's engine, tracking findings, and reporting confirmed vulnerabilities to the Burp Dashboard Issues pane.

The extension supports four LLM backends: **Ollama** (local, any model), **Google Gemini**, **DeepSeek**, and **OpenRouter**. All agent logic is in Java 17. There is no Python in the active codebase (`legacy_python/` is archived only).

---

## Architecture — Read This First

Every class has a single responsibility. Do not blur these boundaries.

| Class | Responsibility |
|---|---|
| `Extension.java` | Montoya entrypoint. Registers `AgentTab` and `RepeaterCopilotEditor`. Nothing else. |
| `AgentTab.java` | Swing UI only. Provider selector, request log table, request/response editors. No agent logic. |
| `AgentEngine.java` | Thin public facade. Consumed by `AgentTab`. Wires all agent services together. No business logic. |
| `AgentLoop.java` | Orchestrates the per-iteration LLM call + tool dispatch loop. Owns iteration count, noToolStreak, finishRequested state. |
| `ToolExecutor.java` | Executes all 11 tool calls. No LLM calls. No loop logic. Returns `ToolResult` or JSON string. |
| `LlmGateway.java` | LLM client creation, system prompt loading, persona overlays, tool schema definition. |
| `LlmClient.java` | Interface only. `ConnResult`, `ToolCall`, `ChatResult` models. |
| `OllamaClient.java` | Ollama HTTP client. Implements `LlmClient`. Includes automatic text-mode fallback. |
| `GeminiClient.java` | Gemini REST API client. Implements `LlmClient`. |
| `DeepSeekClient.java` | DeepSeek platform API client (`api.deepseek.com`). Implements `LlmClient`. Supports `deepseek-chat` and `deepseek-reasoner` (R1/CoT) modes. |
| `OpenRouterClient.java` | OpenRouter OpenAI-compatible REST API client. Implements `LlmClient`. Includes automatic text-mode fallback for models without native tool-call support. |
| `MemoryManager.java` | Thread-safe per-run state: `responseBodyStore`, `sessionVars`, `vulnStore`, `RunMemory`. Owns `AttackGraph`. |
| `TargetMemoryStore.java` | Cross-session persistent facts per target host (endpoints, params, WAF flags, vuln history, attack graph state). JSON file on disk. |
| `AgentStateSnapshot.java` | Builds the compact structured signals injected into each iteration's LLM prompt. No side effects. |
| `AttackGraph.java` | Deterministic graph of endpoints, parameters, tested payload types, extracted variables. No LLM calls. |
| `EndpointNode.java` | Single node in the attack graph. All sets are `ConcurrentHashMap.newKeySet()`. |
| `VulnClass.java` | String constants for vulnerability class names. No logic. |
| `ReportService.java` | Generates the HTML vulnerability report. Pure function over `vulnStore`. |
| `AgentLogger.java` | Centralised logging to UI callback and timestamped log file. Owns the file writer (open once, close on stop). |
| `AgentUtils.java` | Pure static utilities shared across agent services. No state. |
| `CollaboratorManager.java` | Manages a single Burp Collaborator OAST session per agent run. Provides OOB payload generation and interaction polling for blind vulnerabilities (SQLi, SSRF, XXE, XSS). Degrades gracefully on Community Edition. |
| `RepeaterCopilot.java` | Per-tab AI analysis engine for Repeater Copilot feature. Independent of agent loop. |
| `RepeaterCopilotEditor.java` | Implements `ExtensionProvidedHttpRequestEditor`. UI only. |
| `Imported.java` | Immutable model of a request imported via Burp context menu. |
| `ToolResult.java` | Tool call result model. Serializes to JSON for LLM consumption. |

---

## Key Conventions

### Naming
- Vulnerability class strings always use `VulnClass` constants — never raw string literals like `"sqli"` or `"SQL Injection"`
- Tool names match exactly the names in `LlmGateway.toolSchema()` — never deviate
- Agent log messages use prefixes: `[INFO]`, `[DEBUG]`, `[WARN]`, `[ERROR]`, `[TOOL]`

### Thread Safety
- `MemoryManager` fields accessed from the agent loop thread and the UI thread — all collections must be concurrent
- `EndpointNode` sets must be `ConcurrentHashMap.newKeySet()` — never `HashSet` or `ArrayList`
- `AgentLogger` file writer is opened once at run start and closed at run end — never open/close per message
- `running` and `finishRequested` flags in `AgentLoop` are `volatile boolean`

### LLM Context Management
- Tool results fed back to the LLM must be **truncated** — never raw full response bodies
- `responseBodyPreview` is capped at 4000 chars; `spider_links` output at 800 chars; `fuzz_parameter` at 300 chars per result
- `pruneMessages()` must always preserve: the root system message (index 0) and the most recent MEMORY: system message
- `all_results` in `fuzz_parameter` output should NOT be included in the LLM-facing message — only `interesting_results`
- `AgentStateSnapshot` injects compact signals only — never full graph data or full memory dumps

### Tool Results
- Every tool returns either a `ToolResult` (for HTTP tools) or a JSON string (for non-HTTP tools)
- Tool results are always valid JSON — never plain text, never exception stack traces
- On tool error, return `{"ok": false, "error": "..."}` — do not throw
- `ToolResult.ok()` and `ToolResult.error()` are the only constructors — never build raw maps

### HTML Report
- All user-controlled data rendered in the HTML report must pass through `escHtml()` before output
- No exceptions — severity class names, poc fields, location fields, all of it

---

## What NOT to Do

- **Do not add LLM calls inside `ToolExecutor`** — tools are deterministic, no AI reasoning
- **Do not add logic to `AgentTab`** — it is UI only; delegate everything to `AgentEngine`
- **Do not modify `LlmClient`, `OllamaClient`, `GeminiClient`, `DeepSeekClient`, `OpenRouterClient`, or `RepeaterCopilot`** unless the task explicitly requires it
- **Do not use `HashSet`, `ArrayList`, or `HashMap` for shared mutable state** — use concurrent equivalents
- **Do not open a `FileWriter` inside a loop or per-message method** — use `AgentLogger`
- **Do not inject full `AttackGraph` data into LLM prompts** — use `AgentStateSnapshot.buildGraphSignals()` only
- **Do not add ONNX, embeddings, or vector search** — memory is structured JSON only
- **Do not add new external dependencies** without discussion — Jackson and Montoya API are the only allowed libraries
- **Do not use raw string literals for vuln class names** — always use `VulnClass` constants
- **Do not duplicate topology data** between `AttackGraph` and `TargetMemoryStore` — AttackGraph persists only testing state (testedPayloadTypes, extractedVariables, authRequired); topology (paths, params) lives in TargetMemoryStore

---

## Adding a New Tool

1. Define the tool schema in `LlmGateway.toolSchema()` using OpenAI function-calling format
2. Implement the handler method in `ToolExecutor` — returns JSON string, never throws
3. Add the dispatch case in `AgentLoop`'s tool dispatch block
4. Update the tool count in `README.md` Features table
5. Add the tool to the Agent Tools table in `README.md`
6. Document when the tool should be called in `burp-ai-agent-prompt.md`

---

## Adding a New Vulnerability Class

1. Add a constant to `VulnClass.java`
2. Add a focused plan in `AgentEngine.focusedPlan()` (or wherever the plan logic lives) with:
   - Phase-by-phase execution steps
   - Specific payloads ordered by likelihood
   - Blind/timing variant coverage
   - A clear termination condition
3. Add the keyword patterns to the `matches()` dispatch
4. Add the vuln class to the Focused Task Mode table in `README.md`
5. Update the vuln class count in the Features table in `README.md`

---

## Adding a New LLM Backend

1. Implement `LlmClient` (the interface in `LlmClient.java`) — return `ConnResult`, `ToolCall`, and `ChatResult` models
2. Add a text-mode fallback if the provider does not guarantee tool-call support (see `OllamaClient` and `OpenRouterClient` for reference)
3. Register the new client in `LlmGateway` (provider name string + instantiation)
4. Add the provider to the provider selector in `AgentTab`
5. Document the provider (API URL, supported models, any quirks) in `README.md`

---

## Persistence Model

Two distinct stores — never conflate them:

**`TargetMemoryStore` (cross-session, per target host):**
- `endpoints` — discovered paths and methods
- `params` — known parameter names
- `waf` — WAF/filter detection flags
- `vuln_history` — severity counts from prior runs
- `attack_graph_state` — serialized testing state from `AttackGraph`

**`MemoryManager` (per-run, in memory only):**
- `responseBodyStore` — full response bodies keyed by request ID
- `sessionVars` — `{{variable}}` values for interpolation
- `vulnStore` — confirmed findings for report generation
- `RunMemory` — recent request log, status counts, WAF observations
- `AttackGraph` — live endpoint/parameter/testing state

On run start: restore `attack_graph_state` from `TargetMemoryStore` into `AttackGraph`.
On run end: serialize `AttackGraph.serializeTestingState()` back to `TargetMemoryStore`.

---

## System Prompt Editing

The agent methodology lives in `src/main/resources/burp-ai-agent-prompt.md` — bundled in the JAR but human-readable. It can be edited without recompiling.

When editing the system prompt:
- Every tool must have a clear "when to call" rule — ambiguity causes the agent to skip tools
- `finish_run` must have an unambiguous trigger condition — without it the agent writes plain-text conclusions and the loop doesn't terminate cleanly
- `fuzz_parameter` must be the default for all injection testing — the prompt must explicitly say not to loop individual payloads with `execute_http_request`
- Focused task mode rules must include: test only the assigned class, note off-target findings in `finish_run` summary, never call `report_vulnerability` for a different class

---

## Testing Against Intentionally Vulnerable Apps

Recommended targets for local testing:
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — broad OWASP Top 10 coverage
- [DVWA](https://github.com/digininja/DVWA) — classic web vulns
- [WebGoat](https://github.com/WebGoat/WebGoat) — Java-based, good for Java deserialization and XXE

Never test against systems you do not own or have explicit written permission to test.

---

## Build

```powershell
# Build fat JAR (all dependencies bundled)
.\gradlew.bat jar

# Output — versioned fat JAR ready to load in Burp
dist/burp-ai-pentester-<version>.jar

# Also copy to releases/ and update releases/LATEST
.\gradlew.bat release
```

Java 17+ required at build time. The output JAR runs on Burp's bundled JRE — no separate Java installation needed at runtime.

Load in Burp: **Extensions → Installed → Add → Java → select JAR**

> **Mandatory build rule:** After **every code change** — no exceptions — run `.\gradlew.bat jar` and confirm it exits with `BUILD SUCCESSFUL` before considering the task done. If the build fails, fix all compile errors before stopping. Never leave the repository in a state where the JAR does not reflect the current source.

## Mandatory
- Quality of pentesting is paramount — any code change and decision should align with this principle above all else. If a change improves code quality but reduces pentesting effectiveness, it should be rejected or reworked until it meets both criteria.