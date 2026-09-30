import io
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from groq import Groq

st.set_page_config(page_title="SQL Query Investigation Agent", page_icon="🧠", layout="wide")

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_ROWS = 200
MAX_REVISIONS = 3

SYSTEM_PROMPT = """
You are a SQL investigation agent. Your job is to answer natural-language questions over a relational database.

Rules:
1. Use only tables and columns present in the supplied schema.
2. Generate read-only SQL only. Never generate INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, or multiple statements.
3. Prefer explicit columns over SELECT *.
4. Use appropriate joins, filters, grouping, aggregation, ordering, and NULL handling.
5. Do not invent values, tables, columns, or relationships.
6. If the question is ambiguous, state the assumption explicitly.
7. Treat query results as evidence. Do not claim facts that are not supported by the results.
8. Return valid JSON when JSON is requested; do not wrap it in markdown fences.
"""


def get_client():
    key = os.getenv("GROQ_API_KEY")
    if not key:
        try:
            key = st.secrets.get("GROQ_API_KEY")
        except Exception:
            key = None
    return Groq(api_key=key) if key else None


def ask_ai(client, prompt, temperature=0.1):
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
    )
    return response.choices[0].message.content.strip()


def extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
        text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            raise
        return json.loads(match.group(0))


def validate_sql(sql):
    if not sql or not sql.strip():
        return False, "Empty SQL query"
    q = sql.strip().rstrip(";").strip()
    if ";" in q:
        return False, "Multiple SQL statements are not allowed"
    if not re.match(r"^(SELECT|WITH)\b", q, re.I):
        return False, "Only SELECT/WITH read-only queries are allowed"
    forbidden = r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|REPLACE|TRUNCATE)\b"
    if re.search(forbidden, q, re.I):
        return False, "Forbidden SQL operation detected"
    return True, "SQL passed read-only validation"


def create_sample_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE employees (
        employee_id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        department TEXT NOT NULL,
        office TEXT NOT NULL
    );
    CREATE TABLE login_attempts (
        event_id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        login_date TEXT NOT NULL,
        login_time TEXT NOT NULL,
        country TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        success INTEGER NOT NULL
    );
    INSERT INTO employees VALUES
      (1,'alice','IT','Hyderabad'),
      (2,'bob','Finance','Bengaluru'),
      (3,'carol','IT','Hyderabad'),
      (4,'david','HR','Mumbai');
    INSERT INTO login_attempts VALUES
      (1,'alice','2026-09-29','08:42:00','India','10.0.0.10',1),
      (2,'alice','2026-09-29','23:17:00','India','10.0.0.10',0),
      (3,'bob','2026-09-29','10:12:00','India','10.0.0.21',1),
      (4,'bob','2026-09-29','23:40:00','Russia','185.10.2.3',0),
      (5,'carol','2026-09-30','09:05:00','India','10.0.0.11',1),
      (6,'carol','2026-09-30','09:08:00','India','10.0.0.11',0),
      (7,'david','2026-09-30','14:20:00','India','10.0.0.31',1),
      (8,'alice','2026-09-30','23:55:00','Germany','91.2.3.4',0);
    """)
    conn.commit()
    conn.close()
    return path


def inspect_schema(conn):
    tables = []
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        cols = conn.execute(f'PRAGMA table_info("{name.replace(chr(34), chr(34)*2)}")').fetchall()
        sample = conn.execute(f'SELECT * FROM "{name.replace(chr(34), chr(34)*2)}" LIMIT 3').fetchall()
        tables.append({
            "table": name,
            "columns": [{"name": c[1], "type": c[2], "nullable": not bool(c[3]), "pk": bool(c[5])} for c in cols],
            "sample_rows": sample,
        })
    return tables


def schema_text(schema):
    blocks = []
    for t in schema:
        cols = ", ".join(f"{c['name']} {c['type']}" for c in t["columns"])
        blocks.append(f"TABLE {t['table']} ({cols})\nSAMPLE ROWS: {t['sample_rows']}")
    return "\n\n".join(blocks)


def explain_query(conn, sql):
    return conn.execute("EXPLAIN QUERY PLAN " + sql.rstrip(";")).fetchall()


def execute_query(conn, sql):
    cur = conn.execute(sql.rstrip(";"))
    rows = cur.fetchmany(MAX_ROWS + 1)
    truncated = len(rows) > MAX_ROWS
    rows = rows[:MAX_ROWS]
    cols = [d[0] for d in cur.description] if cur.description else []
    df = pd.DataFrame(rows, columns=cols)
    return df, truncated


def generate_query(client, question, schema):
    prompt = f"""
Generate a read-only SQL query for this user question.

QUESTION:
{question}

DATABASE SCHEMA:
{schema_text(schema)}

Return JSON with exactly these keys:
{{
  "sql": "...",
  "reasoning": "brief explanation",
  "assumptions": ["..."],
  "expected_answer_shape": "count/table/list/summary/etc"
}}
"""
    return extract_json(ask_ai(client, prompt))


def validate_answer(client, question, sql, df, schema):
    preview = df.head(20).to_dict(orient="records")
    prompt = f"""
Validate whether the SQL result actually answers the question.

QUESTION:
{question}

SQL:
{sql}

RESULT COLUMNS:
{list(df.columns)}

ROW COUNT RETURNED:
{len(df)}

RESULT PREVIEW:
{preview}

SCHEMA:
{schema_text(schema)}

Return JSON exactly as:
{{
  "valid": true,
  "confidence": 0.0,
  "reason": "...",
  "missing_requirements": ["..."],
  "revision_hint": "..."
}}
"""
    return extract_json(ask_ai(client, prompt))


def revise_query(client, question, previous_sql, error_or_feedback, schema):
    prompt = f"""
Revise the SQL query to answer the question correctly.

QUESTION:
{question}

PREVIOUS SQL:
{previous_sql}

VALIDATION/EXECUTION FEEDBACK:
{error_or_feedback}

SCHEMA:
{schema_text(schema)}

Return JSON exactly as:
{{
  "sql": "...",
  "reasoning": "...",
  "assumptions": ["..."]
}}
"""
    return extract_json(ask_ai(client, prompt))


def generate_tests(client, question, sql, df, schema):
    prompt = f"""
Create automated read-only tests for the generated SQL answer.

QUESTION:
{question}
SQL:
{sql}
RESULT COLUMNS:
{list(df.columns)}
RESULT PREVIEW:
{df.head(10).to_dict(orient='records')}
SCHEMA:
{schema_text(schema)}

Return JSON:
{{
  "tests": [
    {{"name": "...", "sql": "SELECT ...", "assertion": "non_empty/non_negative/no_duplicates/etc", "description": "..."}}
  ]
}}

Tests must be SELECT-only and must not mutate the database. Keep them simple and executable in SQLite.
"""
    return extract_json(ask_ai(client, prompt))


def run_test(conn, test):
    ok, msg = validate_sql(test.get("sql", ""))
    if not ok:
        return False, msg, None
    df, _ = execute_query(conn, test["sql"])
    assertion = test.get("assertion", "").lower()
    if assertion == "non_empty":
        passed = len(df) > 0
    elif assertion == "non_negative":
        nums = df.select_dtypes(include="number")
        passed = nums.empty or (nums.fillna(0) >= 0).all().all()
    elif assertion == "no_duplicates":
        passed = not df.duplicated().any()
    else:
        passed = len(df) >= 0
    return bool(passed), "passed" if passed else "assertion failed", df


def main():
    st.title("🧠 SQL Query Investigation Agent")
    st.caption("Natural language → SQL → controlled execution → result validation → automatic revision → test generation")

    client = get_client()
    if not client:
        st.error("GROQ_API_KEY is not configured. Set it as an environment variable or Streamlit secret.")
        st.code('Windows PowerShell: $env:GROQ_API_KEY="your_key"')
        st.stop()

    with st.sidebar:
        st.header("Database")
        mode = st.radio("Source", ["Sample security DB", "Upload SQLite DB"])
        db_path = None
        if mode == "Sample security DB":
            db_path = create_sample_db()
        else:
            upload = st.file_uploader("Upload .db / .sqlite / .sqlite3", type=["db", "sqlite", "sqlite3"])
            if upload:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(upload.name).suffix)
                tmp.write(upload.getbuffer())
                tmp.close()
                db_path = tmp.name
        max_revisions = st.slider("Maximum revisions", 0, 5, MAX_REVISIONS)
        st.info("The agent only executes SELECT/WITH queries and blocks mutating SQL.")

    if not db_path:
        st.info("Select the sample database or upload a SQLite database to begin.")
        return

    conn = sqlite3.connect(db_path)
    schema = inspect_schema(conn)

    tab1, tab2, tab3 = st.tabs(["🔎 Investigation", "🧬 Schema", "🧪 Generated Tests"])

    if "agent_runs" not in st.session_state:
        st.session_state.agent_runs = []
    if "last_tests" not in st.session_state:
        st.session_state.last_tests = []

    with tab2:
        st.subheader("Database schema")
        for table in schema:
            st.markdown(f"**{table['table']}**")
            st.dataframe(pd.DataFrame(table["columns"]), use_container_width=True, hide_index=True)
            with st.expander("Sample rows"):
                st.dataframe(pd.DataFrame(table["sample_rows"], columns=[c["name"] for c in table["columns"]]), use_container_width=True, hide_index=True)

    with tab1:
        question = st.text_area(
            "Natural-language question",
            placeholder="Example: Which employees had failed login attempts outside business hours, and from which countries?",
            height=110,
        )
        if st.button("🚀 Investigate", type="primary", use_container_width=True):
            if not question.strip():
                st.warning("Enter a question first.")
                return

            run = {"question": question, "attempts": []}
            current = None

            with st.spinner("Generating and investigating SQL..."):
                for attempt in range(max_revisions + 1):
                    try:
                        if attempt == 0:
                            candidate = generate_query(client, question, schema)
                        else:
                            candidate = revise_query(client, question, current, feedback, schema)
                        sql = candidate.get("sql", "").strip()
                    except Exception as e:
                        feedback = f"The model response could not be parsed: {e}"
                        current = current or ""
                        run["attempts"].append({"attempt": attempt + 1, "error": feedback})
                        continue

                    ok, validation_message = validate_sql(sql)
                    attempt_record = {"attempt": attempt + 1, "sql": sql, "validation": validation_message}
                    if not ok:
                        feedback = validation_message
                        current = sql
                        run["attempts"].append(attempt_record)
                        continue

                    try:
                        plan = explain_query(conn, sql)
                        df, truncated = execute_query(conn, sql)
                        check = validate_answer(client, question, sql, df, schema)
                        attempt_record.update({"plan": plan, "rows": len(df), "check": check, "truncated": truncated})
                        run["attempts"].append(attempt_record)
                        if check.get("valid") is True:
                            current = sql
                            run["final_sql"] = sql
                            run["final_df"] = df
                            run["final_check"] = check
                            run["candidate"] = candidate
                            break
                        feedback = check.get("revision_hint") or check.get("reason") or "Result did not satisfy the question."
                        current = sql
                    except Exception as e:
                        feedback = f"SQL execution error: {e}"
                        attempt_record["execution_error"] = feedback
                        run["attempts"].append(attempt_record)
                        current = sql

            st.session_state.agent_runs.append(run)
            if "final_sql" in run:
                st.success(f"Validated answer after {len(run['attempts'])} attempt(s).")
                st.subheader("Generated SQL")
                st.code(run["final_sql"], language="sql")
                st.subheader("Validated result")
                st.dataframe(run["final_df"], use_container_width=True, hide_index=True)
                st.subheader("Validation")
                st.json(run["final_check"])

                with st.expander("Execution plan"):
                    st.write(run["attempts"][-1].get("plan", []))

                try:
                    tests = generate_tests(client, question, run["final_sql"], run["final_df"], schema).get("tests", [])
                    st.session_state.last_tests = tests
                except Exception as e:
                    st.session_state.last_tests = [{"name": "Generation error", "description": str(e), "sql": "", "assertion": ""}]

                with st.expander("Investigation trace"):
                    for item in run["attempts"]:
                        st.markdown(f"**Attempt {item['attempt']}**")
                        st.code(item.get("sql", ""), language="sql")
                        if item.get("validation"):
                            st.write(item["validation"])
                        if item.get("execution_error"):
                            st.error(item["execution_error"])
                        if item.get("check"):
                            st.json(item["check"])
            else:
                st.error("The agent could not produce a validated answer within the revision limit.")
                with st.expander("Investigation trace", expanded=True):
                    st.json(run["attempts"])

    with tab3:
        st.subheader("Automated read-only tests")
        if not st.session_state.last_tests:
            st.info("Run an investigation to generate tests.")
        else:
            for i, test in enumerate(st.session_state.last_tests, 1):
                st.markdown(f"### Test {i}: {test.get('name', 'Unnamed')}")
                st.write(test.get("description", ""))
                st.code(test.get("sql", ""), language="sql")
                if st.button(f"▶ Run Test {i}", key=f"run_test_{i}"):
                    passed, message, result = run_test(conn, test)
                    if passed:
                        st.success(message)
                    else:
                        st.error(message)
                    if result is not None:
                        st.dataframe(result, use_container_width=True, hide_index=True)

    conn.close()


if __name__ == "__main__":
    main()
