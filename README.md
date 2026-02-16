# burpai — AI Pentest Agent (Burp Suite Extension)

A Burp Suite **Montoya API** extension that drives an agentic LLM loop (Ollama by default) to:
- Generate test ideas
- Execute requests **through Burp** (so traffic appears in Burp tooling)
- Log requests/responses in an in-extension Request Log
- Report confirmed findings via a dedicated tool call
- Maintain in-run memory of tested parameters and WAF behaviors

## Requirements

- Burp Suite (Community/Pro) 2023.x or newer
- Java 21+ (for building and running)
- Ollama running locally (default): `http://localhost:11434`

## Quick start

1. **Start Ollama**
   - `ollama serve`
   - Pull your model (example): `ollama pull qwen3-coder-next:cloud`

2. **Build the extension**
   - Run: `.\gradlew.bat jar`
   - The fat JAR will be created at `dist/burp-ai-pentester-fat.jar`.

3. **Load the extension in Burp**
   - Burp → **Extensions → Installed → Add**
   - Extension type: **Java**
   - Select: `dist/burp-ai-pentester-fat.jar`

4. **Run**
   - Open the **AI Pentester** tab
   - Write your prompt in the extension
   - Click **Start Agent**

## Features

- **Automated Logging**: Sessions are automatically logged to `~/burpai_logs/`.
- **Intelligent Memory**: The agent remembers what it has tested to avoid redundant work.
- **WAF Awareness**: Detects and adapts to blocking behavior.
- **Context Awareness**: Right-click any request in Burp → **Send to AI Pentester** to seed the agent with a specific request.

## Development

To rebuild the project:
```powershell
.\gradlew.bat jar
```

Note: If you are on OneDrive and encounter cache errors, use:
```powershell
$env:GRADLE_USER_HOME = "C:\Users\User\.gradle-local"
.\gradlew.bat jar --no-build-cache
```

## Legacy Python Version
The original Jython-based version is available in `legacy_python/`. Note that it requires a Jython environment configured in Burp.

## Responsible use

Use only against systems you own or have explicit permission to test.

## Secrets

Do not commit real API keys, tokens, cookies, or target data to GitHub. Keep `anthropic_api_key` empty unless you are working in a private repo.

## Repo layout

- [files/BurpAgenticPentester_Improved_1.py](files/BurpAgenticPentester_Improved_1.py): main extension
- [files/burp_ai_config.json](files/burp_ai_config.json): extension configuration
- [files/burp-ai-agent-prompt.md](files/burp-ai-agent-prompt.md): system prompt template
- [files/archive/](files/archive/): older variants and artifacts
