# SQL Sentinel AI

A Streamlit SQL investigation and defensive query-analysis application.

## Features

- Completely redesigned cybersecurity/SOC-style UI
- Natural-language to SQL investigation agent
- Read-only SQL execution gate
- SQL threat scanner with a 0-100 risk score
- Detection of destructive operations, stacked statements, tautologies, UNION-based patterns, SQL comments/obfuscation, time-delay functions, high-risk database capabilities and schema enumeration
- Security scan before generated SQL is executed
- AI result validation and iterative SQL revision
- SQLite demo security database
- SQLite upload support
- Investigation history
- Schema explorer

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Set `GROQ_API_KEY` as an environment variable or Streamlit secret for AI investigation.

## Streamlit Cloud

Add this to App Settings -> Secrets:

```toml
GROQ_API_KEY = "your-key"
```

Threat Scanner works without the AI key. Natural-language investigation requires the key.

## Security note

The scanner is a defensive heuristic layer. It should not be treated as a complete SQL injection detector. For production deployments, use a dedicated read-only database account, database-side permissions, resource limits, logging, and network controls.
