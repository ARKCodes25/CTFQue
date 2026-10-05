from flask import Flask, request, render_template, jsonify
import sqlite3
import os

app = Flask(__name__)
DB = "challenge.db"

BLACKLIST = [
    'select', 'union', 'from', 'where', 'and', 'or',
    'drop', 'insert', 'update', 'delete', 'sleep',
    'benchmark', 'having', 'group', 'order', 'limit',
    'information_schema', 'substr', 'char', '0x'
]

def waf_check(s):
    for word in BLACKLIST:
        if word in s:
            return True
    if ' ' in s:
        return True
    return False

def init_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, role TEXT
        );
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY, flag TEXT
        );
    """)
    members = [
        (1,'admin','sup3r_s3cr3t_p4ss','admin'),
        (2,'alice','alice_pass_123','member'),
        (3,'bob','b0b_secur3_456','member'),
        (4,'charlie','ch4rl13_p455','member'),
        (5,'diana','d14n4_rules','member'),
    ]
    c.executemany("INSERT OR IGNORE INTO members VALUES (?,?,?,?)", members)
    c.execute("INSERT OR IGNORE INTO secrets VALUES (1,'flagCES{5ql_1nj3c710n_15_d4ng3r0u5}')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'result':'error','message':'Please enter a username.'})
    if waf_check(username):
        return jsonify({'result':'waf','message':'WAF Alert: Blocked keyword or character detected.'})
    try:
        conn = sqlite3.connect(DB, check_same_thread=False)
        c = conn.cursor()
        query = f"SELECT id, username, role FROM members WHERE username = '{username}'"
        c.execute(query)
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify({'result':'found','message':f'Member found | <b>{row[1]}</b> [{row[2]}]'})
        else:
            return jsonify({'result':'notfound','message':'No member found with that username.'})
    except sqlite3.OperationalError:
        return jsonify({'result':'error','message':'A database error occurred.'})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
