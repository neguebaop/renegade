import os
import json
import subprocess
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string
from dotenv import load_dotenv

load_dotenv()

APP_PORT = int(os.getenv("CLOUDLINK_PORT", "8080"))
PASSWORD = os.getenv("CLOUDLINK_PASSWORD", "admin123")
SECRET_KEY = os.getenv("CLOUDLINK_SECRET", "troque-essa-chave")
BOT_PM2_NAME = os.getenv("BOT_PM2_NAME", "discord-bot")

app = Flask(__name__)
app.secret_key = SECRET_KEY

def sh(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return out.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="ignore")
    except Exception as e:
        return str(e)

def pm2_status():
    raw = sh("pm2 jlist")
    try:
        data = json.loads(raw)
    except Exception:
        data = []
    bot = None
    for proc in data:
        if proc.get("name") == BOT_PM2_NAME:
            bot = proc
            break
    if not bot:
        return {
            "online": False,
            "status": "não encontrado",
            "name": BOT_PM2_NAME,
            "restarts": 0,
            "memory": "0 MB",
            "cpu": "0%",
            "uptime": "-"
        }
    env = bot.get("pm2_env", {})
    mon = bot.get("monit", {})
    mem_mb = round((mon.get("memory") or 0) / 1024 / 1024, 1)
    return {
        "online": env.get("status") == "online",
        "status": env.get("status", "unknown"),
        "name": bot.get("name", BOT_PM2_NAME),
        "restarts": env.get("restart_time", 0),
        "memory": f"{mem_mb} MB",
        "cpu": f"{mon.get('cpu', 0)}%",
        "uptime": env.get("pm_uptime", "-")
    }

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("ok"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>CloudLink Bot</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      font-family:Arial,Helvetica,sans-serif;
      background: radial-gradient(circle at top, #30105f, #090912 55%, #040408);
      color:white;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px;
    }
    .card{
      width:100%;
      max-width:760px;
      background:rgba(13,13,25,.82);
      border:1px solid rgba(255,255,255,.12);
      border-radius:28px;
      padding:28px;
      box-shadow:0 0 60px rgba(146,70,255,.25);
      backdrop-filter:blur(12px);
    }
    .top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}
    h1{margin:0;font-size:34px;letter-spacing:-1px}
    .tag{
      padding:10px 14px;border-radius:999px;
      background:linear-gradient(135deg,#8b5cf6,#ec4899);
      font-weight:bold;
      box-shadow:0 0 25px rgba(236,72,153,.35);
    }
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}
    .box{
      padding:16px;border-radius:18px;background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.08);
    }
    .box b{display:block;font-size:13px;color:#b9b9d6;margin-bottom:8px}
    .box span{font-size:18px;font-weight:bold}
    .status{
      margin-top:18px;padding:18px;border-radius:20px;
      background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1)
    }
    .online{color:#32ff9d}
    .offline{color:#ff4d6d}
    form{display:inline}
    button,a.btn{
      border:0;
      border-radius:16px;
      padding:14px 18px;
      margin:6px;
      cursor:pointer;
      color:white;
      font-weight:bold;
      text-decoration:none;
      display:inline-block;
      background:linear-gradient(135deg,#7c3aed,#db2777);
      box-shadow:0 0 25px rgba(124,58,237,.25);
    }
    button.secondary{background:linear-gradient(135deg,#2563eb,#06b6d4)}
    button.danger{background:linear-gradient(135deg,#ef4444,#f97316)}
    pre{
      white-space:pre-wrap;
      max-height:260px;
      overflow:auto;
      background:#05050b;
      border-radius:18px;
      padding:16px;
      border:1px solid rgba(255,255,255,.1);
      color:#d8d8ff;
    }
    input{
      width:100%;
      padding:16px;
      border-radius:16px;
      border:1px solid rgba(255,255,255,.18);
      background:rgba(255,255,255,.08);
      color:white;
      margin:14px 0;
      outline:none;
    }
    @media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)} h1{font-size:28px}}
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <div>
        <h1>☁️ CloudLink</h1>
        <p>Painel básico para manter seu bot online na VPS.</p>
      </div>
      <div class="tag">Discord Bot</div>
    </div>

    {% if login %}
      <form method="post">
        <input type="password" name="password" placeholder="Senha do painel">
        <button type="submit">Entrar</button>
      </form>
    {% else %}
      <div class="status">
        Status do bot:
        {% if st.online %}
          <b class="online">ONLINE</b>
        {% else %}
          <b class="offline">{{ st.status|upper }}</b>
        {% endif %}
      </div>

      <div class="grid">
        <div class="box"><b>Nome PM2</b><span>{{ st.name }}</span></div>
        <div class="box"><b>CPU</b><span>{{ st.cpu }}</span></div>
        <div class="box"><b>RAM</b><span>{{ st.memory }}</span></div>
        <div class="box"><b>Restarts</b><span>{{ st.restarts }}</span></div>
      </div>

      <form method="post" action="/action/restart"><button>Reiniciar bot</button></form>
      <form method="post" action="/action/start"><button class="secondary">Ligar bot</button></form>
      <form method="post" action="/action/stop"><button class="danger">Parar bot</button></form>
      <a class="btn" href="/logs">Ver logs</a>
      <a class="btn" href="/logout">Sair</a>

      {% if msg %}
        <div class="status">{{ msg }}</div>
      {% endif %}
    {% endif %}
  </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
@require_login
def home():
    return render_template_string(HTML, login=False, st=pm2_status(), msg=request.args.get("msg"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == PASSWORD:
            session["ok"] = True
            return redirect(url_for("home"))
        return render_template_string(HTML, login=True, msg="Senha incorreta")
    return render_template_string(HTML, login=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/action/<act>", methods=["POST"])
@require_login
def action(act):
    if act not in ["restart", "start", "stop"]:
        return redirect(url_for("home", msg="Ação inválida"))
    out = sh(f"pm2 {act} {BOT_PM2_NAME}")
    return redirect(url_for("home", msg=out[-300:]))

@app.route("/logs")
@require_login
def logs():
    out = sh(f"pm2 logs {BOT_PM2_NAME} --lines 80 --nostream")
    return f"""
    <body style='background:#05050b;color:white;font-family:Arial;padding:20px'>
    <h2>Logs do bot</h2>
    <a style='color:#ec4899' href='/'>Voltar</a>
    <pre style='white-space:pre-wrap;background:#111122;padding:18px;border-radius:16px'>{out}</pre>
    </body>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT)
