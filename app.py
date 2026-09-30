import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
from groq import Groq

st.set_page_config(page_title="SQL Sentinel AI", page_icon="◉", layout="wide", initial_sidebar_state="expanded")

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_ROWS = 200
MAX_REVISIONS = 3

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap');
:root { --bg:#071016; --panel:#0c171f; --panel2:#101e28; --line:#1d303b; --text:#edf7f5; --muted:#8fa7ad; --cyan:#32e6d0; --red:#ff5c72; --amber:#ffbf69; --green:#56e39f; --blue:#63a8ff; }
.stApp { background:radial-gradient(circle at 80% 0%, rgba(50,230,208,.08), transparent 30%), var(--bg); color:var(--text); font-family:Inter,sans-serif; }
.block-container { max-width:1500px; padding:1.2rem 2rem 3rem; }
section[data-testid="stSidebar"] { background:#050c11; border-right:1px solid var(--line); }
section[data-testid="stSidebar"] * { color:#dcebea !important; }
[data-testid="stSidebarNav"] { display:none; }
.topbar { display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--line); padding:0 0 16px; margin-bottom:20px; }
.logo { font-weight:800; letter-spacing:-.8px; font-size:24px; }
.logo span { color:var(--cyan); }
.status { font-family:'IBM Plex Mono',monospace; font-size:11px; color:var(--green); border:1px solid rgba(86,227,159,.3); padding:7px 11px; border-radius:999px; background:rgba(86,227,159,.06); }
.hero { border:1px solid var(--line); background:linear-gradient(135deg,#0c1b23,#0a151c 65%,#0c2327); border-radius:20px; padding:28px; position:relative; overflow:hidden; }
.hero:after { content:''; position:absolute; width:220px; height:220px; right:-80px; top:-100px; border:1px solid rgba(50,230,208,.15); border-radius:50%; box-shadow:0 0 0 35px rgba(50,230,208,.025),0 0 0 70px rgba(50,230,208,.018); }
.kicker { color:var(--cyan); font-family:'IBM Plex Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:1.8px; }
.hero h1 { font-size:38px; margin:7px 0 8px; letter-spacing:-1.5px; }
.hero p { color:var(--muted); max-width:850px; margin:0; line-height:1.6; }
.grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:14px 0; }
.metric { border:1px solid var(--line); background:var(--panel); border-radius:14px; padding:16px; }
.metric-label { font-family:'IBM Plex Mono',monospace; font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
.metric-value { font-size:25px; font-weight:750; margin-top:5px; }
.metric-detail { color:var(--muted); font-size:11px; margin-top:3px; }
.panel { border:1px solid var(--line); background:rgba(12,23,31,.88); border-radius:16px; padding:18px; margin-bottom:14px; }
.panel-title { font-size:14px; font-weight:700; margin-bottom:12px; }
.mono { font-family:'IBM Plex Mono',monospace; }
.threat { border-radius:16px; padding:20px; border:1px solid var(--line); background:var(--panel); }
.threat-low { border-color:rgba(86,227,159,.45); background:rgba(86,227,159,.05); }
.threat-med { border-color:rgba(255,191,105,.45); background:rgba(255,191,105,.05); }
.threat-high { border-color:rgba(255,92,114,.5); background:rgba(255,92,114,.06); }
.score { font-size:44px; font-weight:800; line-height:1; }
.badge { display:inline-block; padding:5px 9px; border-radius:999px; font-family:'IBM Plex Mono',monospace; font-size:10px; font-weight:600; }
.badge-green { color:var(--green); background:rgba(86,227,159,.1); border:1px solid rgba(86,227,159,.25); }
.badge-red { color:var(--red); background:rgba(255,92,114,.1); border:1px solid rgba(255,92,114,.25); }
.badge-amber { color:var(--amber); background:rgba(255,191,105,.1); border:1px solid rgba(255,191,105,.25); }
.finding { border-left:3px solid var(--red); background:#101a21; padding:11px 13px; margin:8px 0; border-radius:0 9px 9px 0; }
.finding.warn { border-color:var(--amber); }
.finding.safe { border-color:var(--green); }
.flow { display:flex; gap:8px; align-items:stretch; margin:10px 0; }
.flowbox { flex:1; padding:13px; background:#0b171e; border:1px solid var(--line); border-radius:12px; font-size:12px; }
.arrow { display:flex; align-items:center; color:#48636d; }
.stTextArea textarea, .stTextInput input { background:#08131a !important; color:#eaf6f4 !important; border:1px solid #223944 !important; font-family:'IBM Plex Mono',monospace !important; }
.stButton > button { border-radius:10px; border:1px solid #26414c; background:#10212a; color:#e9f6f4; font-weight:650; }
.stButton > button:hover { border-color:var(--cyan); color:var(--cyan); }
button[kind="primary"] { background:var(--cyan) !important; color:#03100e !important; border:0 !important; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:10px; overflow:hidden; }
hr { border-color:var(--line); }
.small { font-size:12px; color:var(--muted); }
@media(max-width:900px){ .grid4{grid-template-columns:repeat(2,1fr)} .flow{flex-direction:column}.arrow{display:none} }
</style>
""", unsafe_allow_html=True)

SYSTEM_PROMPT = """
You are SQL Sentinel, a defensive SQL investigation and security agent. Work only with the supplied database schema.
Generate read-only SQL. Never generate or recommend destructive operations. Analyze SQL for security risks before execution.
Return compact JSON only when requested. Distinguish syntax errors, dangerous operations, suspicious injection patterns, and ordinary read-only queries.
"""

FORBIDDEN = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|REPLACE|TRUNCATE|GRANT|REVOKE)\b", re.I)
PATTERNS = [
    (r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", 35, "Stacked SQL statement", "Multiple statements can be used to append an unintended operation."),
    (r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", 30, "Tautology / injection pattern", "A condition that is always true is a common SQL injection indicator."),
    (r"\bUNION\s+(ALL\s+)?SELECT\b", 25, "UNION-based extraction pattern", "UNION can be legitimate, but unexpected UNION SELECT in user input is a common injection signal."),
    (r"(--|/\*|\*/|#)\s*", 18, "SQL comment / obfuscation marker", "Comments can be used to alter the remainder of an injected predicate."),
    (r"\bSLEEP\s*\(|\bPG_SLEEP\s*\(|\bWAITFOR\s+DELAY\b", 40, "Time-delay function", "Delay functions can indicate time-based injection or resource abuse."),
    (r"\bXP_CMDSHELL\b|\bLOAD_FILE\s*\(|\bLOAD_EXTENSION\s*\(", 50, "High-risk database capability", "This pattern can expose operating-system or extension-loading capabilities on supported databases."),
    (r"\bINFORMATION_SCHEMA\b|\bSQLITE_MASTER\b|\bSQLITE_SCHEMA\b", 8, "Schema enumeration", "Schema metadata access may be legitimate for administration but is worth reviewing in untrusted input."),
    (r"\bLIKE\s*['\"]%", 8, "Broad wildcard search", "A leading wildcard can be expensive on large datasets and may enable resource exhaustion."),
]


def get_client():
    key = os.getenv("GROQ_API_KEY")
    if not key:
        try:
            key = st.secrets.get("GROQ_API_KEY")
        except Exception:
            key = None
    return Groq(api_key=key) if key else None


def ask_ai(client, prompt, temperature=0.1):
    response = client.chat.completions.create(model=MODEL, messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}], temperature=temperature)
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


def analyze_sql(sql):
    q = sql.strip()
    score = 0
    findings = []
    critical = False
    if not q:
        return {"score": 0, "level": "UNKNOWN", "verdict": "No SQL supplied", "findings": []}
    if FORBIDDEN.search(q):
        score += 70
        critical = True
        findings.append({"severity": "CRITICAL", "title": "Destructive or privileged operation", "detail": "The query contains an operation outside the read-only investigation policy."})
    if q.count(";") > 0 and len(q.rstrip().rstrip(";")) != len(q.rstrip()):
        score += 10
    for pattern, points, title, detail in PATTERNS:
        if re.search(pattern, q, re.I | re.S):
            score += points
            findings.append({"severity": "HIGH" if points >= 30 else "MEDIUM", "title": title, "detail": detail})
    if not re.match(r"^(SELECT|WITH)\b", q, re.I):
        score += 25
        findings.append({"severity": "HIGH", "title": "Not a read-only query", "detail": "SQL Sentinel only permits SELECT or WITH statements for execution."})
    if re.search(r"\bSELECT\s+\*\b", q, re.I):
        score += 4
        findings.append({"severity": "LOW", "title": "SELECT *", "detail": "Broad column selection is not malicious, but explicit columns are safer and easier to review."})
    score = min(score, 100)
    if critical or score >= 70:
        level = "CRITICAL"
        verdict = "BLOCK"
    elif score >= 40:
        level = "HIGH"
        verdict = "REVIEW / BLOCK"
    elif score >= 20:
        level = "MEDIUM"
        verdict = "REVIEW"
    else:
        level = "LOW"
        verdict = "LIKELY SAFE"
    if not findings:
        findings.append({"severity": "SAFE", "title": "No suspicious indicators detected", "detail": "The query matches the read-only policy and no configured malicious patterns were found."})
    return {"score": score, "level": level, "verdict": verdict, "findings": findings}


def create_sample_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE employees (employee_id INTEGER PRIMARY KEY, username TEXT NOT NULL, department TEXT NOT NULL, office TEXT NOT NULL);
    CREATE TABLE login_attempts (event_id INTEGER PRIMARY KEY, username TEXT NOT NULL, login_date TEXT NOT NULL, login_time TEXT NOT NULL, country TEXT NOT NULL, ip_address TEXT NOT NULL, success INTEGER NOT NULL);
    CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY, username TEXT NOT NULL, severity TEXT NOT NULL, alert_type TEXT NOT NULL, created_at TEXT NOT NULL);
    INSERT INTO employees VALUES (1,'alice','IT','Hyderabad'),(2,'bob','Finance','Bengaluru'),(3,'carol','IT','Hyderabad'),(4,'david','HR','Mumbai');
    INSERT INTO login_attempts VALUES (1,'alice','2026-09-29','08:42:00','India','10.0.0.10',1),(2,'alice','2026-09-29','23:17:00','India','10.0.0.10',0),(3,'bob','2026-09-29','10:12:00','India','10.0.0.21',1),(4,'bob','2026-09-29','23:40:00','Russia','185.10.2.3',0),(5,'carol','2026-09-30','09:05:00','India','10.0.0.11',1),(6,'carol','2026-09-30','09:08:00','India','10.0.0.11',0),(7,'david','2026-09-30','14:20:00','India','10.0.0.31',1),(8,'alice','2026-09-30','23:55:00','Germany','91.2.3.4',0);
    INSERT INTO alerts VALUES (1,'bob','high','Impossible travel','2026-09-29 23:41:00'),(2,'alice','medium','After-hours login','2026-09-30 00:01:00'),(3,'carol','low','Repeated failure','2026-09-30 09:09:00');
    """)
    conn.commit(); conn.close()
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


def validate_sql(sql):
    if not sql or not sql.strip(): return False, "Empty SQL query"
    q = sql.strip().rstrip(";").strip()
    if ";" in q: return False, "Multiple SQL statements are not allowed"
    if not re.match(r"^(SELECT|WITH)\b", q, re.I): return False, "Only SELECT/WITH read-only queries are allowed"
    if FORBIDDEN.search(q): return False, "Forbidden SQL operation detected"
    return True, "Read-only validation passed"


def execute_query(conn, sql):
    cur = conn.execute(sql.rstrip(";")); rows = cur.fetchmany(MAX_ROWS + 1); truncated = len(rows) > MAX_ROWS; rows = rows[:MAX_ROWS]
    cols = [d[0] for d in cur.description] if cur.description else []
    return pd.DataFrame(rows, columns=cols), truncated


def explain_query(conn, sql):
    return conn.execute("EXPLAIN QUERY PLAN " + sql.rstrip(";")).fetchall()


def generate_query(client, question, schema):
    return extract_json(ask_ai(client, f"Generate one read-only SQL query for this question. QUESTION: {question}\nSCHEMA:\n{schema_text(schema)}\nReturn JSON {{\"sql\":\"...\",\"reasoning\":\"...\",\"assumptions\":[]}}"))


def validate_answer(client, question, sql, df, schema):
    return extract_json(ask_ai(client, f"Validate whether this SQL result answers the question. QUESTION: {question}\nSQL: {sql}\nCOLUMNS: {list(df.columns)}\nROWS: {len(df)}\nPREVIEW: {df.head(20).to_dict(orient='records')}\nSCHEMA: {schema_text(schema)}\nReturn JSON {{\"valid\":true,\"confidence\":0.0,\"reason\":\"...\",\"revision_hint\":\"...\"}}"))


def revise_query(client, question, previous_sql, feedback, schema):
    return extract_json(ask_ai(client, f"Revise the SQL to answer the question. QUESTION: {question}\nPREVIOUS SQL: {previous_sql}\nFEEDBACK: {feedback}\nSCHEMA:\n{schema_text(schema)}\nReturn JSON {{\"sql\":\"...\",\"reasoning\":\"...\",\"assumptions\":[]}}"))


def run_investigation(client, conn, schema, question):
    run = {"question": question, "attempts": []}; current = ""; feedback = ""
    for attempt in range(MAX_REVISIONS + 1):
        try:
            candidate = generate_query(client, question, schema) if attempt == 0 else revise_query(client, question, current, feedback, schema)
            sql = candidate.get("sql", "").strip()
        except Exception as e:
            run["attempts"].append({"attempt": attempt + 1, "error": str(e)}); feedback = str(e); continue
        security = analyze_sql(sql)
        record = {"attempt": attempt + 1, "sql": sql, "security": security}
        ok, validation = validate_sql(sql); record["validation"] = validation
        if not ok or security["score"] >= 70:
            record["blocked"] = True; run["attempts"].append(record); current = sql; feedback = validation + ". Security scanner blocked this query."; continue
        try:
            plan = explain_query(conn, sql); df, truncated = execute_query(conn, sql); check = validate_answer(client, question, sql, df, schema)
            record.update({"plan": plan, "rows": len(df), "check": check, "truncated": truncated}); run["attempts"].append(record); current = sql
            if check.get("valid") is True:
                run.update({"final_sql": sql, "final_df": df, "final_check": check, "security": security, "candidate": candidate}); break
            feedback = check.get("revision_hint") or check.get("reason") or "Result did not answer the question."
        except Exception as e:
            record["execution_error"] = str(e); run["attempts"].append(record); current = sql; feedback = str(e)
    return run


def metric(label, value, detail):
    st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-detail">{detail}</div></div>', unsafe_allow_html=True)


def threat_panel(result):
    cls = "threat-low" if result["score"] < 20 else "threat-med" if result["score"] < 70 else "threat-high"
    color = "badge-green" if result["score"] < 20 else "badge-amber" if result["score"] < 70 else "badge-red"
    st.markdown(f'<div class="threat {cls}"><div class="kicker">SQL THREAT RADAR</div><div style="display:flex;align-items:end;justify-content:space-between;margin-top:8px"><div><div class="score">{result["score"]}<span style="font-size:18px;color:#779099">/100</span></div><div class="small">security risk score</div></div><span class="badge {color}">{result["level"]} · {result["verdict"]}</span></div></div>', unsafe_allow_html=True)
    for f in result["findings"]:
        c = "safe" if f["severity"] == "SAFE" else "warn" if f["severity"] == "MEDIUM" or f["severity"] == "LOW" else ""
        st.markdown(f'<div class="finding {c}"><b>{f["severity"]} · {f["title"]}</b><div class="small">{f["detail"]}</div></div>', unsafe_allow_html=True)


def main():
    if "page" not in st.session_state: st.session_state.page = "Command Center"
    if "runs" not in st.session_state: st.session_state.runs = []
    client = get_client()

    with st.sidebar:
        st.markdown('<div class="logo">SQL <span>SENTINEL</span></div><div class="small">Defensive query investigation</div>', unsafe_allow_html=True)
        st.markdown("---")
        pages = ["Command Center", "Investigate", "Threat Scanner", "Schema", "History"]
        st.session_state.page = st.radio("", pages, index=pages.index(st.session_state.page), label_visibility="collapsed")
        st.markdown("---")
        source = st.radio("DATABASE", ["Demo Security DB", "Upload SQLite DB"])
        db_path = create_sample_db() if source == "Demo Security DB" else None
        if source == "Upload SQLite DB":
            upload = st.file_uploader("SQLite database", type=["db", "sqlite", "sqlite3"])
            if upload:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(upload.name).suffix); tmp.write(upload.getbuffer()); tmp.close(); db_path = tmp.name
        st.markdown("---")
        st.markdown('<div class="small">Execution policy</div><div class="badge badge-green">SELECT / WITH ONLY</div>', unsafe_allow_html=True)
        if client: st.markdown('<div style="margin-top:10px" class="badge badge-green">AI ENGINE ONLINE</div>', unsafe_allow_html=True)
        else: st.markdown('<div style="margin-top:10px" class="badge badge-amber">AI KEY NOT CONFIGURED</div>', unsafe_allow_html=True)

    st.markdown('<div class="topbar"><div><div class="logo">SQL <span>SENTINEL</span></div><div class="small">AI-powered SQL investigation & threat detection</div></div><div class="status">● DEFENSIVE MODE · READ ONLY</div></div>', unsafe_allow_html=True)

    if not db_path:
        st.markdown('<div class="hero"><div class="kicker">DATABASE SECURITY WORKSPACE</div><h1>Detect. Investigate. Prove.</h1><p>Scan SQL for malicious patterns, generate safe queries from natural language, execute only approved read-only statements, and validate the evidence.</p></div>', unsafe_allow_html=True)
        st.info("Choose a database from the sidebar to begin.")
        return
    if not client:
        st.warning("Threat Scanner works without an AI key. Natural-language investigation requires GROQ_API_KEY in Streamlit Secrets.")

    conn = sqlite3.connect(db_path)
    schema = inspect_schema(conn)
    total_rows = sum(conn.execute(f'SELECT COUNT(*) FROM "{t["table"].replace(chr(34), chr(34)*2)}"').fetchone()[0] for t in schema)

    if st.session_state.page == "Command Center":
        st.markdown('<div class="hero"><div class="kicker">SECURITY OPERATIONS VIEW</div><h1>See what your SQL is really doing.</h1><p>SQL Sentinel combines an investigation agent with a defensive query scanner. Every generated query is inspected before it reaches the database.</p></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="grid4"><div class="metric"><div class="metric-label">Tables</div><div class="metric-value">{len(schema)}</div><div class="metric-detail">schema discovered</div></div><div class="metric"><div class="metric-label">Rows</div><div class="metric-value">{total_rows}</div><div class="metric-detail">current data source</div></div><div class="metric"><div class="metric-label">Investigations</div><div class="metric-value">{len(st.session_state.runs)}</div><div class="metric-detail">this session</div></div><div class="metric"><div class="metric-label">Execution</div><div class="metric-value">READ ONLY</div><div class="metric-detail">destructive SQL blocked</div></div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel"><div class="panel-title">How the defensive pipeline works</div><div class="flow"><div class="flowbox"><b>01 · INPUT</b><br><span class="small">SQL or natural language</span></div><div class="arrow">→</div><div class="flowbox"><b>02 · THREAT RADAR</b><br><span class="small">patterns + policy scan</span></div><div class="arrow">→</div><div class="flowbox"><b>03 · GATE</b><br><span class="small">block unsafe statements</span></div><div class="arrow">→</div><div class="flowbox"><b>04 · EXECUTE</b><br><span class="small">controlled read-only run</span></div><div class="arrow">→</div><div class="flowbox"><b>05 · VERIFY</b><br><span class="small">AI evidence validation</span></div></div></div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="panel"><div class="panel-title">Quick threat checks</div></div>', unsafe_allow_html=True)
            examples = ["SELECT * FROM login_attempts WHERE username = 'alice'", "SELECT * FROM users WHERE username = 'admin' OR '1'='1'", "SELECT * FROM users; DROP TABLE users; --"]
            for q in examples:
                if st.button(q, key="qc"+str(hash(q)), use_container_width=True): st.session_state.quick_sql = q; st.session_state.page = "Threat Scanner"; st.rerun()
        with c2:
            st.markdown('<div class="panel"><div class="panel-title">Investigation prompts</div></div>', unsafe_allow_html=True)
            qs = ["Which users had failed logins outside business hours?", "Show high-severity alerts by user and date.", "Which countries generated failed login attempts?"]
            for q in qs:
                if st.button(q, key="iq"+str(hash(q)), use_container_width=True): st.session_state.prefill = q; st.session_state.page = "Investigate"; st.rerun()

    elif st.session_state.page == "Threat Scanner":
        st.markdown('<div class="hero"><div class="kicker">THREAT SCANNER</div><h1>Is this SQL malicious?</h1><p>Paste any SQL statement to receive a risk score, security findings, and an execution recommendation. This scanner is defensive pattern analysis, not a guarantee that unknown attacks are harmless.</p></div>', unsafe_allow_html=True)
        sql = st.text_area("SQL INPUT", value=st.session_state.pop("quick_sql", ""), height=210, placeholder="Paste SQL here...", label_visibility="visible")
        if st.button("SCAN QUERY", type="primary", use_container_width=True):
            result = analyze_sql(sql)
            st.session_state.scan = {"sql": sql, "result": result}
        if "scan" in st.session_state:
            scan = st.session_state.scan
            left, right = st.columns([1, 1.5])
            with left: threat_panel(scan["result"])
            with right:
                st.markdown('<div class="panel"><div class="panel-title">Query under inspection</div></div>', unsafe_allow_html=True)
                st.code(scan["sql"] or "No query supplied", language="sql")
                st.markdown('<div class="panel"><div class="panel-title">Decision guide</div><div class="small">LOW: no configured suspicious indicators. MEDIUM: review context. HIGH: investigate before execution. CRITICAL: block under the current policy.</div></div>', unsafe_allow_html=True)

    elif st.session_state.page == "Investigate":
        st.markdown('<div class="hero"><div class="kicker">AI INVESTIGATION</div><h1>Ask the database a question.</h1><p>The agent generates SQL from the schema, runs the threat radar first, executes only approved read-only SQL, then checks whether the evidence actually answers your question.</p></div>', unsafe_allow_html=True)
        q = st.text_area("INVESTIGATION QUESTION", value=st.session_state.pop("prefill", ""), height=100, placeholder="Which employees had failed login attempts outside business hours?")
        if st.button("START INVESTIGATION", type="primary", use_container_width=True):
            if not q.strip(): st.warning("Enter a question first.")
            elif not client: st.error("Add GROQ_API_KEY to Streamlit Secrets to enable the AI investigation agent.")
            else:
                with st.spinner("Generating, scanning, executing and validating SQL..."):
                    run = run_investigation(client, conn, schema, q)
                st.session_state.runs.append(run)
        if st.session_state.runs:
            run = st.session_state.runs[-1]
            if "final_sql" in run:
                a,b = st.columns([1.2,.8])
                with a:
                    st.markdown('<div class="panel"><div class="panel-title">Validated evidence</div></div>', unsafe_allow_html=True)
                    st.dataframe(run["final_df"], use_container_width=True, hide_index=True)
                    st.markdown('<div class="panel"><div class="panel-title">Approved SQL</div></div>', unsafe_allow_html=True)
                    st.code(run["final_sql"], language="sql")
                with b:
                    threat_panel(run["security"])
                    check = run["final_check"]
                    st.markdown('<div class="panel"><div class="panel-title">Answer validation</div></div>', unsafe_allow_html=True)
                    st.metric("AI confidence", f'{float(check.get("confidence",0))*100:.0f}%')
                    st.write(check.get("reason", ""))
                st.markdown('<div class="panel"><div class="panel-title">Investigation trace</div></div>', unsafe_allow_html=True)
                for item in run["attempts"]:
                    label = f'Attempt {item["attempt"]} · {item.get("security",{}).get("level", "UNKNOWN")} · {item.get("validation", "")}'
                    with st.expander(label):
                        st.code(item.get("sql", ""), language="sql")
                        threat_panel(item.get("security", analyze_sql(item.get("sql", ""))))
                        if item.get("blocked"): st.error("Execution blocked by security gate.")
                        if item.get("check"): st.json(item["check"])
            else:
                st.error("No validated answer was produced. Review the investigation trace for blocked or failed attempts.")
                for item in run.get("attempts", []):
                    st.code(item.get("sql", item.get("error", "")), language="sql")

    elif st.session_state.page == "Schema":
        st.markdown('<div class="hero"><div class="kicker">SCHEMA INTELLIGENCE</div><h1>Know the data before querying it.</h1><p>Inspect tables, fields, types and sample records used to ground the AI investigation agent.</p></div>', unsafe_allow_html=True)
        for t in schema:
            with st.expander(f'{t["table"]} · {len(t["columns"])} columns', expanded=True):
                st.dataframe(pd.DataFrame(t["columns"]), use_container_width=True, hide_index=True)
                st.dataframe(pd.DataFrame(t["sample_rows"], columns=[c["name"] for c in t["columns"]]), use_container_width=True, hide_index=True)

    elif st.session_state.page == "History":
        st.markdown('<div class="hero"><div class="kicker">INVESTIGATION LOG</div><h1>What happened in this session?</h1><p>Review every generated query, security decision, validation attempt and final result.</p></div>', unsafe_allow_html=True)
        if not st.session_state.runs: st.info("No investigations yet.")
        for i, run in enumerate(reversed(st.session_state.runs), 1):
            status = "VALIDATED" if "final_sql" in run else "UNRESOLVED"
            with st.expander(f'#{len(st.session_state.runs)-i+1} · {status} · {run["question"]}'):
                if "final_sql" in run:
                    st.code(run["final_sql"], language="sql")
                    st.dataframe(run["final_df"], use_container_width=True, hide_index=True)
                st.write(f'Attempts: {len(run["attempts"])}')
                for item in run["attempts"]:
                    st.write(f'Attempt {item["attempt"]}: {item.get("security",{}).get("level", "UNKNOWN")} · {item.get("security",{}).get("score", 0)}/100')

    conn.close()


if __name__ == "__main__":
    main()
