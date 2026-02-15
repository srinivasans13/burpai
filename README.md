# burpai — AI Pentest Agent (Burp Suite Extension)

A Burp Suite **Jython** extension that drives an agentic LLM loop (Ollama by default) to:
- Generate test ideas
- Execute requests **through Burp** (so traffic appears in Burp tooling)
- Log requests/responses in an in-extension Request Log
- Report confirmed findings via a dedicated tool call

## Requirements

- Burp Suite (Community/Pro)
- Jython (2.7.x) configured in Burp: **Extender → Options → Python Environment**
- Ollama running locally (default): `http://localhost:11434`

## Quick start

1. Start Ollama
   - `ollama serve`
   - Pull your model (example): `ollama pull qwen3-coder-next:cloud`

2. Load the extension in Burp
   - Burp → **Extender → Extensions → Add**
   - Type: **Python**
   - File: [files/BurpAgenticPentester_Improved_1.py](files/BurpAgenticPentester_Improved_1.py)

3. Configure
   - Edit [files/burp_ai_config.json](files/burp_ai_config.json) (or use the UI fields in the tab)
   - Set:
     - `ollama_base_url`
     - `ollama_model`
     - `target_base_url`

4. Run
   - Open the **AI Pentest Agent (Advanced)** tab
   - Write your prompt in the extension
   - Click **Start Agent**

## “Send request to extension” workflow

- In Burp (Proxy/HTTP history/Repeater/etc), right-click a request → **Send to AI Pentester…**
- The extension will import the request context and print **IMPORTED REQUEST READY**.
- Draft your prompt in the extension and click **Start Agent**.

## Notes / troubleshooting

- If you see `503 Application Error` from the target, the target instance may be down. The agent will keep iterating, but it can’t confirm vulnerabilities against an unavailable service.
- If the agent writes analysis without calling tools, auto mode will nudge it to continue; after repeated no-tool-call turns it stops to avoid infinite loops.
- Requests are executed via Burp APIs and added to Burp’s Site Map where possible.

## Responsible use

Use only against systems you own or have explicit permission to test.

## Secrets

Do not commit real API keys, tokens, cookies, or target data to GitHub. Keep `anthropic_api_key` empty unless you are working in a private repo.

## Repo layout

- [files/BurpAgenticPentester_Improved_1.py](files/BurpAgenticPentester_Improved_1.py): main extension
- [files/burp_ai_config.json](files/burp_ai_config.json): extension configuration
- [files/burp-ai-agent-prompt.md](files/burp-ai-agent-prompt.md): system prompt template
- [files/archive/](files/archive/): older variants and artifacts
