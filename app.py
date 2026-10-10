from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import json
import csv
import io
import html
import threading
import webbrowser

DB = "brandsentinel.db"
PORT = 8003


def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                url TEXT,
                description TEXT,
                score INTEGER,
                risk TEXT,
                findings TEXT
            )
        """)


def analyze(brand, name, url, description):
    text = f"{name} {url} {description}".lower()
    brand = brand.lower().strip()
    score = 0
    findings = []

    if brand and brand in text:
        score += 20
        findings.append("Protected brand name detected")

    suspicious = {
        "password": 20,
        "otp": 20,
        "urgent": 15,
        "verify": 10,
        "verification": 10,
        "login": 10,
        "account suspended": 25,
        "payment required": 20,
        "click here": 10,
    }

    for word, points in suspicious.items():
        if word in text:
            score += points
            findings.append("Suspicious indicator: " + word)

    if url.lower().startswith("http://"):
        score += 15
        findings.append("Unencrypted HTTP URL")

    score = min(score, 100)

    if score >= 70:
        risk = "High"
    elif score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append("No configured risk indicators detected")

    return score, risk, findings


def page(message=""):
    with sqlite3.connect(DB) as con:
        rows = con.execute(
            "SELECT id,brand,name,kind,url,description,score,risk,findings "
            "FROM assets ORDER BY id DESC"
        ).fetchall()

    total = len(rows)
    high = sum(r[7] == "High" for r in rows)
    medium = sum(r[7] == "Medium" for r in rows)
    low = sum(r[7] == "Low" for r in rows)

    def esc(v):
        return html.escape(str(v if v is not None else ""))

    cards = ""
    for r in rows:
        color = {"High": "#fb7185", "Medium": "#fbbf24",
                 "Low": "#4ade80"}.get(r[7], "#fff")
        cards += f"""
        <tr>
          <td>{r[0]}</td><td>{esc(r[1])}</td>
          <td>{esc(r[2])}</td><td>{esc(r[3])}</td>
          <td>{esc(r[4])}</td>
          <td><b style="color:{color}">{r[6]}/100 · {esc(r[7])}</b></td>
          <td>{esc(r[8])}</td>
          <td><form method="POST" action="/delete">
              <input type="hidden" name="id" value="{r[0]}">
              <button class="delete">Delete</button></form></td>
        </tr>"""

    if not cards:
        cards = '<tr><td colspan="8">No assets yet. Add your first test asset.</td></tr>'

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BrandSentinel AI</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0b1120;color:#e5edf8;font:15px Arial,sans-serif}}
header{{padding:25px 5%;background:#111b30;border-bottom:1px solid #26344c}}
h1{{margin:0;color:#67d8ff}} header p{{color:#a8b7cf}}
main{{max-width:1250px;margin:25px auto;padding:0 18px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}
.card,.panel{{background:#121e32;border:1px solid #283751;border-radius:12px;padding:20px;margin-bottom:18px}}
.stat{{font-size:30px;font-weight:bold;margin-top:10px}}
.layout{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
label{{display:block;margin:13px 0 6px;color:#b8c8de}}
input,select,textarea{{width:100%;padding:12px;border-radius:7px;border:1px solid #364762;background:#0b1527;color:white}}
textarea{{min-height:100px;resize:vertical}}
button,.btn{{display:inline-block;border:0;border-radius:7px;padding:11px 15px;background:#42c8ef;color:#062032;font-weight:bold;cursor:pointer;text-decoration:none;margin-top:12px}}
.delete{{background:#4a2431;color:white;margin:0}}
.notice{{color:#7ee7ad;margin:12px 0}}
.tablewrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:950px}}
th,td{{text-align:left;padding:12px;border-bottom:1px solid #293850;vertical-align:top}}
th{{color:#92dfff}}small,.muted{{color:#9badc5}}
@media(max-width:750px){{.layout{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,1fr)}}}}
</style>
</head>
<body>
<header><h1>🛡 BrandSentinel AI</h1>
<p>Digital Risk Protection &amp; Brand Intelligence</p></header>
<main>
<h2>Security Overview</h2>
<div class="stats">
<div class="card">Total Monitored Assets<div class="stat">{total}</div></div>
<div class="card">High Risk Findings<div class="stat" style="color:#fb7185">{high}</div></div>
<div class="card">Medium Risk Findings<div class="stat" style="color:#fbbf24">{medium}</div></div>
<div class="card">Low Risk Findings<div class="stat" style="color:#4ade80">{low}</div></div>
</div>
<div class="notice">{esc(message)}</div>
<div class="layout">
<section class="panel">
<h2>🔐 Protected Brand Profile</h2>
<form method="POST" action="/brand">
<label>Brand Name</label>
<input name="brand" required placeholder="e.g. Microsoft">
<label>Brand Keywords (comma separated)</label>
<input name="keywords" placeholder="Microsoft, Microsoft 365, Outlook">
<button>Save Brand Profile</button>
</form>
<p class="muted">The current brand profile is stored in this browser session.</p>
</section>
<section class="panel">
<h2>🔎 Add Asset for Risk Analysis</h2>
<form method="POST" action="/add">
<label>Asset / Website Name</label>
<input name="name" required placeholder="e.g. Microsoft 365 Account Support">
<label>Asset Type</label>
<select name="kind">
<option>Website</option><option>Social Media</option>
<option>Mobile App</option><option>Email</option>
</select>
<label>URL / Identifier</label>
<input name="url" placeholder="http://example.com/login">
<label>Description / Observed Indicators</label>
<textarea name="description" placeholder="Describe the observed content..." required></textarea>
<button>+ Add &amp; Analyze Asset</button>
</form>
</section>
</div>
<section class="panel">
<h2>📊 Risk Analysis Results</h2>
<p class="muted">Scores are rule-based indicators, not proof of fraud.</p>
<div class="tablewrap"><table>
<thead><tr><th>ID</th><th>Brand</th><th>Asset</th><th>Type</th>
<th>URL</th><th>Score</th><th>Findings</th><th>Action</th></tr></thead>
<tbody>{cards}</tbody></table></div>
<p><a class="btn" href="/export">Export CSV Report</a>
<a class="btn" href="/">Refresh Dashboard</a></p>
</section>
<p class="muted">Demo only: this application does not crawl websites or monitor social networks live.</p>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def respond(self, body, status=200, content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self.respond(page())
        elif path == "/export":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Brand", "Asset", "Type", "URL",
                             "Description", "Score", "Risk", "Findings"])
            with sqlite3.connect(DB) as con:
                writer.writerows(con.execute(
                    "SELECT id,brand,name,kind,url,description,score,risk,findings FROM assets"
                ).fetchall())
            self.respond(output.getvalue(), content_type="text/csv; charset=utf-8")
            self.send_header if False else None
        else:
            self.respond("Not found", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_form()

        if path == "/brand":
            brand = data.get("brand", "").strip()
            keywords = data.get("keywords", "").strip()
            if not brand:
                self.respond(page("Please enter a brand name."))
                return
            with open("brand_profile.json", "w", encoding="utf-8") as f:
                json.dump({"brand": brand, "keywords": keywords}, f)
            self.respond(page("Brand profile saved. Now add an asset."))
            return

        if path == "/add":
            name = data.get("name", "").strip()
            url = data.get("url", "").strip()
            description = data.get("description", "").strip()
            kind = data.get("kind", "Website")

            try:
                with open("brand_profile.json", encoding="utf-8") as f:
                    profile = json.load(f)
                brand = profile.get("brand", "")
                keywords = profile.get("keywords", "")
            except (OSError, json.JSONDecodeError):
                self.respond(page("First save your brand profile!"))
                return

            if not name or not description:
                self.respond(page("Enter asset name and description."))
                return

            score, risk, findings = analyze(brand, name, url, description)
            if keywords:
                text_to_check = (name + " " + url + " " + description).lower()
                for keyword in keywords.split(","):
                    keyword = keyword.strip().lower()
                    if keyword and keyword in text_to_check and keyword != brand.lower():
                        findings.append("Brand keyword detected: " + keyword)
                        score = min(100, score + 5)
                risk = "High" if score >= 70 else "Medium" if score >= 35 else "Low"

            with sqlite3.connect(DB) as con:
                con.execute(
                    "INSERT INTO assets (brand,name,kind,url,description,score,risk,findings) VALUES (?,?,?,?,?,?,?,?)",
                    (brand, name, kind, url, description, score, risk, "; ".join(findings))
                )
            self.respond(page(f"Asset analyzed successfully. Risk score: {score}/100 ({risk})."))
            return

        if path == "/delete":
            try:
                asset_id = int(data.get("id", "0"))
            except ValueError:
                asset_id = 0
            with sqlite3.connect(DB) as con:
                con.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            self.respond(page("Asset deleted."))
            return

        self.respond("Not found", 404)


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"BrandSentinel AI running at http://127.0.0.1:{PORT}")
    print("Stop the server with Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()