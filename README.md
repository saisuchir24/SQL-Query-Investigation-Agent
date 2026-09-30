# SQL Query Investigation Agent

A Streamlit agent inspired by the structure of the referenced `AI-Cybersecurity-Assistant` repository. The original repository uses Streamlit plus Groq for an AI analysis interface; this project applies the same lightweight pattern to the supplied problem statement: **given a database and a natural-language question, generate SQL, inspect the results, validate the answer, revise when necessary, and generate automated tests.**

## Features

- Natural-language to SQL generation
- Automatic SQLite schema discovery
- Sample-row inspection for schema grounding
- Read-only SQL enforcement
- `EXPLAIN QUERY PLAN` before accepting a query
- Real query execution with result limiting
- LLM-based answer validation
- Automatic SQL revision loop
- Investigation trace showing each attempt
- Automated read-only test generation
- Test execution from the UI
- Upload your own SQLite database

## Architecture

```text
Natural-language question
          |
          v
   Schema Inspector
          |
          v
   SQL Generator (LLM)
          |
          v
 Read-only SQL Validator
          |
          v
 EXPLAIN QUERY PLAN
          |
          v
 Controlled SQL Executor
          |
          v
    Result Inspector
          |
       +--+--+
       |     |
    valid   invalid
       |     |
       v     v
   Final   SQL Revision
   Answer      |
       |       +----> re-execute
       v
 Test Generator
       |
       v
 Automated Tests
```

## Setup

### Windows PowerShell

```powershell
cd sql_query_investigation_agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:GROQ_API_KEY="YOUR_GROQ_API_KEY"
streamlit run app.py
```

### Linux/Kali

```bash
cd sql_query_investigation_agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GROQ_API_KEY="YOUR_GROQ_API_KEY"
streamlit run app.py
```

## Example questions

With the included sample security database:

- `Which employees had failed login attempts outside business hours?`
- `Which countries produced the most failed login attempts?`
- `Show the failure rate by department.`
- `Find usernames with more than one failed login.`
- `Which failed logins came from countries other than India?`

## Safety model

The application blocks non-read-only statements and multiple statements before execution. For production databases, use a database account that has only the permissions required for investigation queries. The LLM validator is an additional semantic check; it should not be treated as a replacement for database access controls.

## Project mapping to the supplied PS

| PS requirement | Implementation |
|---|---|
| Given a database | SQLite upload or built-in sample DB |
| Natural-language question | Streamlit question box |
| Generate a query | Groq-powered SQL generator |
| Inspect results | Controlled execution + result preview |
| Validate answer | LLM result validator |
| Revise when necessary | Automatic revision loop, configurable attempts |
| Controlled SQL execution | SELECT/WITH allow-list + forbidden-operation checks + EXPLAIN |
| Automated test generation | LLM-generated read-only tests |

## Important production upgrades

- Use PostgreSQL/MySQL with a dedicated read-only database user.
- Add AST-based SQL parsing for stronger validation.
- Add query timeout and resource limits at the database layer.
- Add schema/table allow-lists.
- Add query audit logs.
- Add a benchmark set of natural-language questions with expected answers.
- Add deterministic result validators alongside the LLM validator.
