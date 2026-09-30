import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from groq import Groq

st.set_page_config(page_title="QueryLens AI", page_icon="⌁", layout="wide", initial_sidebar_state="expanded")

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_ROWS = 200
DEFAULT_REVISIONS = 3

st.markdown("""
<style>
:root { --bg:#f5f7fb; --card:#ffffff; --ink:#172033; --muted:#6b7280; --line:#e5e7eb; --accent:#5b5ce2; }
.stApp { background:var(--bg); color:var(--ink); }
.block-container { padding-top:1.5rem; padding-bottom:3rem; max-width:1450px; }
section[data-testid="stSidebar"] { background:#111827; }
section[data-testid="stSidebar"] * { color:#f9fafb !important; }
.brand { font-size:30px; font-weight:800; letter-spacing:-1px; margin-bottom:2px; }
.subtle { color:var(--muted); font-size:14px; }
.hero { background:linear-gradient(135deg,#171a35 0%,#3438a8 100%); color:white; padding:28px 32px; border-radius:22px; margin-bottom:22px; box-shadow:0 15px 40px rgba(31,41,55,.15); }
.hero h1 { font-size:36px; margin:0 0 8px 0; letter-spacing:-1.2px; }
.hero p { margin:0; color:#dfe3ff; font-size:15px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:18px; padding:20px; box-shadow:0 6px 22px rgba(17,24,39,.04); }
.metric { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:17px 19px; }
.metric-label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.7px; }
.metric-value { font-size:28px; font-weight:750; margin-top:3px; }
.pill { display:inline-block; padding:5px 10px; border-radius:999px; background:#eef0ff; color:#4c4fd2; font-size:12px; font-weight:650; }
.trace { border-left:3px solid #6366f1; padding:4px 0 4px 16px; margin:12px 0; }
.smallcaps { text-transform:uppercase; letter-spacing:1px; font-size:11px; color:var(--muted); font-weight:700; }
div[data-testid="stDataFrame"] { border-radius:12px; overflow:hidden; }
.stButton > button { border-radius:10px; font-weight:650; }
</style>
""", unsafe_allow_html=True)

SYSTEM_PROMPT = """
You are a SQL investigation agent. Answer natural-language questions over the supplied relational database.
Use only the supplied schema. Generate read-only SQL only. Never use INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, REINDEX, REPLACE, TRUNCATE, or multiple statements. Prefer explicit columns. Treat query results as evidence. Do not invent tables, columns, values, or relationships. State assumptions when needed. Return requested JSON without markdown fences.
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
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
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
    return True, "Read-only validation passed"


def create_sample_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE employees (employee_id INTEGER PRIMARY KEY, username TEXT NOT NULL, department TEXT NOT NULL, office TEXT NOT NULL);
    CREATE TABLE login_attempts (event_id INTEGER PRIMARY KEY, username TEXT NOT NULL, login_date TEXT NOT NULL, login_time TEXT NOT NULL, country TEXT NOT NULL, ip_address TEXT NOT NULL, success INTEGER NOT NULL);
    CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY, username TEXT NOT NULL, severity TEXT NOT NULL, alert_type TEXT NOT NULL, created_at TEXT NOT NULL);
    INSERT INTO employees VALUES
      (1,'alice','IT','Hyderabad'),(2,'bob','Finance','Bengaluru'),(3,'carol','IT','Hyderabad'),(4,'david','HR','Mumbai');
    INSERT INTO login_attempts VALUES
      (1,'alice','2026-09-29','08:42:00','India','10.0.0.10',1),(2,'alice','2026-09-29','23:17:00','India','10.0.0.10',0),(3,'bob','2026-09-29','10:12:00','India','10.0.0.21',1),(4,'bob','2026-09-29','23:40:00','Russia','185.10.2.3',0),(5,'carol','2026-09-30','09:05:00','India','10.0.0.11',1),(6,'carol','2026-09-30','09:08:00','India','10.0.0.11',0),(7,'david','2026-09-30','14:20:00','India','10.0.0.31',1),(8,'alice','2026-09-30','23:55:00','Germany','91.2.3.4',0);
    INSERT INTO alerts VALUES
      (1,'bob','high','Impossible travel','2026-09-29 23:41:00'),(2,'alice','medium','After-hours login','2026-09-30 00:01:00'),(3,'carol','low','Repeated failure','2026-09-30 09:09:00');
    """)
    conn.commit()
    conn.close()
    return path


def inspect_schema(conn):
    tables = []
    names = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    for (name,) in names:
        safe = name.replace('"', '""')
        cols = conn.execute(f'PRAGMA table_info("{safe}")').fetchall()
        sample = conn.execute(f'SELECT * FROM "{safe}" LIMIT 3').fetchall()
        tables.append({"table": name, "columns": [{"name": c[1], "type": c[2], "nullable": not bool(c[3]), "pk": bool(c[5])} for c in cols], "sample_rows": sample})
    return tables


def schema_text(schema):
    return "\n\n".join(f"TABLE {t['table']} ({', '.join(c['name'] + ' ' + c['type'] for c in t['columns'])})\nSAMPLE ROWS: {t['sample_rows']}" for t in schema)


def explain_query(conn, sql):
    return conn.execute("EXPLAIN QUERY PLAN " + sql.rstrip(";")).fetchall()


def execute_query(conn, sql):
    cur = conn.execute(sql.rstrip(";"))
    rows = cur.fetchmany(MAX_ROWS + 1)
    truncated = len(rows) > MAX_ROWS
    rows = rows[:MAX_ROWS]
    cols = [d[0] for d in cur.description] if cur.description else []
    return pd.DataFrame(rows, columns=cols), truncated


def generate_query(client, question, schema):
    return extract_json(ask_ai(client, f"""Generate a read-only SQL query for this question.\nQUESTION:\n{question}\nSCHEMA:\n{schema_text(schema)}\nReturn JSON: {{\"sql\":\"...\",\"reasoning\":\"...\",\"assumptions\":[],\"expected_answer_shape\":\"...\"}}"""))


def validate_answer(client, question, sql, df, schema):
    return extract_json(ask_ai(client, f"""Validate whether the SQL result answers the question.\nQUESTION:\n{question}\nSQL:\n{sql}\nCOLUMNS:\n{list(df.columns)}\nROWS:\n{len(df)}\nPREVIEW:\n{df.head(20).to_dict(orient='records')}\nSCHEMA:\n{schema_text(schema)}\nReturn JSON: {{\"valid\":true,\"confidence\":0.0,\"reason\":\"...\",\"missing_requirements\":[],\"revision_hint\":\"...\"}}"""))


def revise_query(client, question, previous_sql, feedback, schema):
    return extract_json(ask_ai(client, f"""Revise the SQL to answer the question.\nQUESTION:\n{question}\nPREVIOUS SQL:\n{previous_sql}\nFEEDBACK:\n{feedback}\nSCHEMA:\n{schema_text(schema)}\nReturn JSON: {{\"sql\":\"...\",\"reasoning\":\"...\",\"assumptions\":[]}}"""))


def generate_tests(client, question, sql, df, schema):
    return extract_json(ask_ai(client, f"""Create 2-4 automated read-only tests for the SQL answer.\nQUESTION: {question}\nSQL: {sql}\nRESULT COLUMNS: {list(df.columns)}\nRESULT PREVIEW: {df.head(10).to_dict(orient='records')}\nSCHEMA: {schema_text(schema)}\nReturn JSON {{\"tests\":[{{\"name\":\"...\",\"sql\":\"SELECT ...\",\"assertion\":\"non_empty/non_negative/no_duplicates\",\"description\":\"...\"}}]}}"""))


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
        passed = True
    return bool(passed), "Test passed" if passed else "Assertion failed", df


def run_investigation(client, conn, schema, question, max_revisions):
    run = {"question": question, "attempts": []}
    current = ""
    feedback = ""
    for attempt in range(max_revisions + 1):
        try:
            candidate = generate_query(client, question, schema) if attempt == 0 else revise_query(client, question, current, feedback, schema)
            sql = candidate.get("sql", "").strip()
        except Exception as e:
            feedback = f"Model response could not be parsed: {e}"
            run["attempts"].append({"attempt": attempt + 1, "error": feedback})
            continue
        ok, validation = validate_sql(sql)
        record = {"attempt": attempt + 1, "sql": sql, "validation": validation}
        if not ok:
            feedback = validation
            current = sql
            run["attempts"].append(record)
            continue
        try:
            plan = explain_query(conn, sql)
            df, truncated = execute_query(conn, sql)
            check = validate_answer(client, question, sql, df, schema)
            record.update({"plan": plan, "rows": len(df), "check": check, "truncated": truncated})
            run["attempts"].append(record)
            current = sql
            if check.get("valid") is True:
                run.update({"final_sql": sql, "final_df": df, "final_check": check, "candidate": candidate})
                break
            feedback = check.get("revision_hint") or check.get("reason") or "Result did not satisfy the question."
        except Exception as e:
            feedback = f"SQL execution error: {e}"
            record["execution_error"] = feedback
            run["attempts"].append(record)
            current = sql
    return run


def metric_card(label, value, detail=""):
    st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="subtle">{detail}</div></div>', unsafe_allow_html=True)


def main():
    if "page" not in st.session_state:
        st.session_state.page = "Overview"
    if "runs" not in st.session_state:
        st.session_state.runs = []
    if "last_tests" not in st.session_state:
        st.session_state.last_tests = []

    client = get_client()

    with st.sidebar:
        st.markdown('<div class="brand">QueryLens</div><div class="subtle">AI SQL Investigation Platform</div>', unsafe_allow_html=True)
        st.markdown("---")
        pages = {"Overview": "◈", "Investigate": "⌕", "Schema Explorer": "▦", "Test Center": "✓", "Run History": "↺"}
        selected = st.radio("WORKSPACE", list(pages.keys()), index=list(pages.keys()).index(st.session_state.page), format_func=lambda x: f"{pages[x]}   {x}")
        st.session_state.page = selected
        st.markdown("---")
        st.markdown('<div class="smallcaps">Data source</div>', unsafe_allow_html=True)
        mode = st.radio("", ["Demo Security DB", "Upload SQLite DB"], label_visibility="collapsed")
        db_path = None
        if mode == "Demo Security DB":
            db_path = create_sample_db()
        else:
            upload = st.file_uploader("SQLite database", type=["db", "sqlite", "sqlite3"])
            if upload:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(upload.name).suffix)
                tmp.write(upload.getbuffer())
                tmp.close()
                db_path = tmp.name
        max_revisions = st.slider("Revision limit", 0, 5, DEFAULT_REVISIONS)
        if client:
            st.success("AI engine connected")
        else:
            st.error("GROQ_API_KEY is missing")

    if not db_path:
        st.markdown('<div class="hero"><h1>QueryLens AI</h1><p>Turn natural-language questions into investigated, validated, read-only SQL answers.</p></div>', unsafe_allow_html=True)
        st.info("Choose the demo database or upload a SQLite database from the sidebar.")
        return
    if not client:
        st.error("Configure GROQ_API_KEY in Streamlit Secrets before running investigations.")
        return

    conn = sqlite3.connect(db_path)
    schema = inspect_schema(conn)
    total_rows = 0
    for table in schema:
        total_rows += conn.execute(f'SELECT COUNT(*) FROM "{table["table"].replace(chr(34), chr(34)*2)}"').fetchone()[0]

    page = st.session_state.page
    if page == "Overview":
        st.markdown('<div class="hero"><h1>Investigate your database with AI</h1><p>Generate SQL, execute it safely, verify the evidence, revise when needed, and create automated tests.</p></div>', unsafe_allow_html=True)
        cols = st.columns(4)
        with cols[0]: metric_card("Tables", len(schema), "discovered automatically")
        with cols[1]: metric_card("Rows", total_rows, "available in current DB")
        with cols[2]: metric_card("Investigations", len(st.session_state.runs), "this session")
        with cols[3]: metric_card("Safety", "READ-ONLY", "SELECT / WITH only")
        st.markdown("### How QueryLens works")
        flow = st.columns(5)
        for c, title, text in zip(flow, ["Ask", "Generate", "Execute", "Validate", "Revise"], ["Natural language question", "Schema-grounded SQL", "Controlled SQLite run", "Evidence check", "Iterative correction"]):
            with c:
                st.markdown(f'<div class="card"><span class="pill">{title}</span><p>{text}</p></div>', unsafe_allow_html=True)
        st.markdown("### Suggested investigations")
        examples = [
            "Which users had failed logins outside business hours?",
            "Show high-severity alerts by user and date.",
            "Which departments have the most failed login attempts?",
        ]
        for q in examples:
            if st.button(q, use_container_width=True):
                st.session_state.page = "Investigate"
                st.session_state.prefill = q
                st.rerun()

    elif page == "Investigate":
        st.markdown('<div class="hero"><h1>Investigation workspace</h1><p>Ask a question and let the agent prove its answer against the database.</p></div>', unsafe_allow_html=True)
        default_q = st.session_state.pop("prefill", "")
        question = st.text_area("Natural-language question", value=default_q, placeholder="Example: Which employees had failed login attempts outside business hours, and from which countries?", height=100)
        if st.button("Run investigation", type="primary", use_container_width=True):
            if not question.strip():
                st.warning("Enter a question first.")
            else:
                with st.spinner("Investigating SQL and validating evidence..."):
                    run = run_investigation(client, conn, schema, question, max_revisions)
                st.session_state.runs.append(run)
                if "final_sql" in run:
                    try:
                        st.session_state.last_tests = generate_tests(client, question, run["final_sql"], run["final_df"], schema).get("tests", [])
                    except Exception as e:
                        st.session_state.last_tests = [{"name": "Generation error", "description": str(e), "sql": "", "assertion": ""}]
                else:
                    st.session_state.last_tests = []

        if st.session_state.runs:
            run = st.session_state.runs[-1]
            if "final_sql" in run:
                st.success(f"Validated after {len(run['attempts'])} attempt(s)")
                left, right = st.columns([1.6, 1])
                with left:
                    st.markdown("### Answer evidence")
                    st.dataframe(run["final_df"], use_container_width=True, hide_index=True)
                    st.markdown("### Generated SQL")
                    st.code(run["final_sql"], language="sql")
                with right:
                    st.markdown("### Validation")
                    check = run["final_check"]
                    st.metric("Confidence", f"{float(check.get('confidence', 0))*100:.0f}%")
                    st.write(check.get("reason", ""))
                    if check.get("missing_requirements"):
                        st.warning("Missing: " + ", ".join(check["missing_requirements"]))
                    st.markdown("### Assumptions")
                    for a in run.get("candidate", {}).get("assumptions", []) or ["None stated"]:
                        st.write("• " + a)
                st.markdown("### Investigation trace")
                for item in run["attempts"]:
                    with st.expander(f"Attempt {item['attempt']} · {item.get('rows', 0)} rows"):
                        st.code(item.get("sql", ""), language="sql")
                        st.write(item.get("validation", ""))
                        if item.get("execution_error"):
                            st.error(item["execution_error"])
                        if item.get("check"):
                            st.json(item["check"])
                        if item.get("plan"):
                            st.write("Query plan:", item["plan"])
            else:
                st.error("No validated answer was produced within the revision limit.")
                st.json(run.get("attempts", []))

    elif page == "Schema Explorer":
        st.markdown('<div class="hero"><h1>Schema Explorer</h1><p>Understand the database before asking the agent to investigate it.</p></div>', unsafe_allow_html=True)
        for table in schema:
            with st.expander(f"{table['table']} · {len(table['columns'])} columns", expanded=True):
                st.dataframe(pd.DataFrame(table["columns"]), use_container_width=True, hide_index=True)
                sample = pd.DataFrame(table["sample_rows"], columns=[c["name"] for c in table["columns"]])
                st.caption("Sample rows")
                st.dataframe(sample, use_container_width=True, hide_index=True)

    elif page == "Test Center":
        st.markdown('<div class="hero"><h1>Test Center</h1><p>Run generated read-only checks against the same database evidence.</p></div>', unsafe_allow_html=True)
        if not st.session_state.last_tests:
            st.info("Run an investigation first. QueryLens will generate executable tests automatically.")
        for i, test in enumerate(st.session_state.last_tests, 1):
            with st.container(border=True):
                st.markdown(f"**Test {i} — {test.get('name', 'Unnamed')}**")
                st.write(test.get("description", ""))
                st.code(test.get("sql", ""), language="sql")
                if st.button(f"Run test {i}", key=f"test_{i}"):
                    passed, message, result = run_test(conn, test)
                    (st.success if passed else st.error)(message)
                    if result is not None:
                        st.dataframe(result, use_container_width=True, hide_index=True)

    elif page == "Run History":
        st.markdown('<div class="hero"><h1>Run History</h1><p>Review the questions, attempts, and final SQL produced in this session.</p></div>', unsafe_allow_html=True)
        if not st.session_state.runs:
            st.info("No investigations yet.")
        for i, run in enumerate(reversed(st.session_state.runs), 1):
            status = "Validated" if "final_sql" in run else "Unresolved"
            with st.expander(f"#{len(st.session_state.runs)-i+1} · {status} · {run['question']}"):
                if "final_sql" in run:
                    st.code(run["final_sql"], language="sql")
                    st.dataframe(run["final_df"], use_container_width=True, hide_index=True)
                st.write(f"Attempts: {len(run['attempts'])}")

    conn.close()


if __name__ == "__main__":
    main()
