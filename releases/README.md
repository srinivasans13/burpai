# Releases

Pre-built fat jars ready to load into Burp Suite.

## Installing

1. Open Burp Suite → **Extensions** → **Add**
2. Select the latest `.jar` file from this folder
3. Configure the extension via the **BurpAI** tab that appears

## Java compatibility

The jar targets **Java 17 bytecode** (`--release 17`).  
Burp Suite ships its own JRE (Java 17 or newer since 2022), so no separate Java installation is required.

The fat jar bundles all dependencies (`jackson-databind`, `jackson-core`, `jackson-annotations`).  
Montoya API is provided by Burp Suite at runtime — it is **not** included in the jar.

## Versioning `MAJOR.MINOR.PATCH`

| Version | Highlights |
|---------|-----------|
| 1.3.0   | AI Personas (Auth, SSRF, Injection, etc.); Burp native issue reporting via Dashboard; Vector memory for target-aware context across runs |
| 1.2.0   | Java 17 bytecode target; `finish_run` tool; `get_sitemap` (site map + proxy history); FUZZ path substitution; comprehensive OWASP seed prompts |
| 1.0.0   | Initial release: dual LLM provider (Ollama / Gemini), 9 pentesting tools |

## Building from source

```
.\gradlew.bat release
```

This compiles the project and copies the versioned jar to this folder automatically.
