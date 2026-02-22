# Agentic Burp Pentesting AI - Quick Start Guide

## 🚀 Two Ways to Use

### Option 1: Burp Suite Extension (Recommended)

This is a proper Burp Suite extension with a GUI.

#### Installation

1. **Download Jython** (required for Python extensions):
   - Download Jython from https://www.jython.org/download
   - Get the standalone JAR file (jython-standalone-x.x.x.jar)

2. **Configure Burp Suite**:
   - Go to **Extender** → **Options** → **Python Environment**
   - Click "Select file..." and select the jython.jar you downloaded

3. **Load the Extension**:
   - Go to **Extender** → **Add**
   - Extension type: Select "Python"
   - Select the file: `BurpOllamaPentester.py`
   - Click "Next" → "Close"

4. **Find the Tab**:
   - Look for the "AI Pentester" tab in Burp Suite

#### Using the Extension

1. **Start Ollama** (if not running):
   ```bash
   ollama serve
   ```

2. **In Burp Suite**, go to the "AI Pentester" tab:
   - Enter your Ollama URL (default: http://localhost:11434)
   - Enter the model name: `minimax-m2.5:cloud`
   - Enter your target URL
   - Click "Connect to Ollama"

3. **Send prompts** like:
   - "Perform reconnaissance on the target"
   - "Test /api/login for SQL injection"
   - "Find all admin endpoints and test for IDOR"

---

### Option 2: Standalone Python Script

Run the agent as a Python script alongside Burp.

#### Installation

```bash
pip install requests --break-system-packages
```

#### Run

```bash
cd files
python burp_agentic_pentester.py
```

Or import as module:

```python
from burp_agentic_pentester import AgenticPentestAgent

agent = AgenticPentestAgent(
    target_base_url="https://demo.testfire.net",
    proxy="http://127.0.0.1:8080",
    provider="ollama",
    ollama_model="minimax-m2.5:cloud"
)

response = agent.chat_with_agent("Test /api/login for SQL injection")
print(response)
```

---

## Configuration (config.json)

```json
{
  "llm_provider": "ollama",
  "ollama_base_url": "http://localhost:11434",
  "ollama_model": "minimax-m2.5:cloud",
  "target_base_url": "https://demo.testfire.net",
  "burp_proxy": "http://127.0.0.1:8080",
  "use_proxy": true
}
```

## Ollama Models

Not all Ollama models support function calling. Recommended:
- **minimax-m2.5:cloud** (your current model)
- **llama3.2**
- **mistral**

## Troubleshooting

### "Could not connect to Ollama"
- Make sure Ollama is running: `ollama serve`
- Check the URL in the extension (default: http://localhost:11434)

### Extension won't load
- Make sure Jython is properly configured in Burp Extender options

### Agent makes no requests
- Verify target URL is accessible
- Ensure model supports function calling

---

**Happy (Ethical) Hacking! 🎯🔒**
