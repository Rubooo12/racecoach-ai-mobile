"""RaceCoach AI — secure iRacing OAuth/API integration starter.

Single-user local development server. For public mobile access, deploy behind HTTPS
with a real database, user accounts, CSRF protections, and a secret manager.
"""
from __future__ import annotations
import base64, hashlib, html, hmac, json, os, secrets, sqlite3, time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
CLIENT_ID = os.getenv("IRACING_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("IRACING_CLIENT_SECRET", "").strip()
REDIRECT_URI = os.getenv("IRACING_REDIRECT_URI", "http://127.0.0.1:8765/oauth/callback").strip()
FERNET_KEY = os.getenv("RACECOACH_FERNET_KEY", "").strip()
DB_PATH = Path(os.getenv("RACECOACH_DB_PATH", str(BASE / "racecoach.db")))
APP_PASSWORD = os.getenv("RACECOACH_APP_PASSWORD", "").strip()
SESSION_SECRET = os.getenv("RACECOACH_SESSION_SECRET", "").strip()
COOKIE_SECURE = os.getenv("RACECOACH_COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
SESSION_MAX_AGE = 7 * 24 * 60 * 60
AUTH_BASE = "https://oauth.iracing.com/oauth2"
DATA_BASE = "https://members-ng.iracing.com/data"

app = FastAPI(title="RaceCoach AI Mobile", version="0.2.0")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


def valid_session(request: Request) -> bool:
    if not SESSION_SECRET:
        return False
    token = request.cookies.get("rc_session", "")
    try:
        stamp, signature = token.split(".", 1)
        issued = int(stamp)
        if issued > int(time.time()) + 60 or int(time.time()) - issued > SESSION_MAX_AGE:
            return False
        expected = hmac.new(SESSION_SECRET.encode(), f"racecoach-v1:{stamp}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False


@app.middleware("http")
async def require_mobile_session(request: Request, call_next):
    path = request.url.path
    public = path in {"/health", "/login", "/auth/app-login", "/manifest.webmanifest", "/sw.js", "/static/icon.svg", "/static/index.html"} or path.startswith("/static/")
    if not public and not valid_session(request):
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Sesión de RaceCoach AI caducada. Vuelve a iniciar sesión."}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)



def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS oauth_attempts (state TEXT PRIMARY KEY, verifier TEXT NOT NULL, created_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL, updated_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS history_cache (name TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS sync_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at INTEGER NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL)")


def cipher() -> Fernet:
    if not FERNET_KEY:
        raise HTTPException(500, "Falta RACECOACH_FERNET_KEY en .env. Genera una clave con generar_clave.bat.")
    try:
        return Fernet(FERNET_KEY.encode())
    except Exception as exc:
        raise HTTPException(500, "RACECOACH_FERNET_KEY no es una clave Fernet válida.") from exc


def save_secret(name: str, value: str) -> None:
    encrypted = cipher().encrypt(value.encode())
    with db() as con:
        con.execute("INSERT INTO secrets(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at", (name, encrypted, int(time.time())))


def get_secret(name: str) -> str | None:
    with db() as con:
        row = con.execute("SELECT value FROM secrets WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    try:
        return cipher().decrypt(row["value"]).decode()
    except InvalidToken as exc:
        raise HTTPException(500, "No se pueden descifrar los tokens. Comprueba que no ha cambiado RACECOACH_FERNET_KEY.") from exc


def mask_client_secret(secret: str, client_id: str) -> str:
    """iRacing requires its documented SHA-256 + Base64 masking for client secrets."""
    normalized_id = client_id.strip().lower()
    return base64.b64encode(hashlib.sha256(f"{secret}{normalized_id}".encode()).digest()).decode()


def require_config() -> None:
    if not CLIENT_ID:
        raise HTTPException(500, "Configura IRACING_CLIENT_ID en .env.")


async def token_post(data: dict[str, str]) -> dict[str, Any]:
    require_config()
    form = {**data, "client_id": CLIENT_ID}
    if CLIENT_SECRET:
        form["client_secret"] = mask_client_secret(CLIENT_SECRET, CLIENT_ID)
    async with httpx.AsyncClient(timeout=25) as client:
        r = await client.post(f"{AUTH_BASE}/token", data=form, headers={"Accept": "application/json"})
    if r.status_code >= 400:
        # Do not log response bodies: provider errors can contain sensitive details.
        raise HTTPException(502, f"iRacing OAuth ha rechazado la solicitud (HTTP {r.status_code}). Revisa el Client ID, redirect URI y PKCE.")
    payload = r.json()
    if not payload.get("access_token"):
        raise HTTPException(502, "La respuesta OAuth no contiene access_token.")
    return payload


def store_tokens(payload: dict[str, Any]) -> None:
    save_secret("access_token", payload["access_token"])
    if payload.get("refresh_token"):
        save_secret("refresh_token", payload["refresh_token"])
    save_secret("access_expires_at", str(int(time.time()) + int(payload.get("expires_in", 600))))
    if payload.get("refresh_token_expires_in") is not None:
        save_secret("refresh_expires_at", str(int(time.time()) + int(payload["refresh_token_expires_in"])))
    save_secret("scope", str(payload.get("scope", "")))


async def access_token() -> str:
    token = get_secret("access_token")
    expires = int(get_secret("access_expires_at") or "0")
    if token and expires > int(time.time()) + 45:
        return token
    refresh = get_secret("refresh_token")
    if refresh:
        try:
            payload = await token_post({"grant_type": "refresh_token", "refresh_token": refresh})
            # Refresh tokens may rotate and can be single-use: persist replacement immediately.
            store_tokens(payload)
            return payload["access_token"]
        except HTTPException:
            # Keep no invalid access token; require interactive re-authorisation below.
            pass
    raise HTTPException(401, "La sesión de iRacing ha caducado. Vuelve a conectar la cuenta.")


async def api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    token = await access_token()
    async with httpx.AsyncClient(timeout=35, follow_redirects=False) as client:
        r = await client.get(f"{DATA_BASE}/{path.lstrip('/')}", params=params or {}, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if r.status_code == 401:
            # One refresh attempt, then retry once.
            save_secret("access_expires_at", "0")
            token = await access_token()
            r = await client.get(f"{DATA_BASE}/{path.lstrip('/')}", params=params or {}, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if r.status_code >= 400:
            raise HTTPException(502, f"La API de iRacing devolvió HTTP {r.status_code} para /data/{path}. Comprueba los parámetros y permisos.")
        data = r.json()
        # Some iRacing data endpoints return a short-lived URL to a JSON payload.
        if isinstance(data, dict) and isinstance(data.get("link"), str):
            link = data["link"]
            if not link.startswith("https://"):
                raise HTTPException(502, "iRacing devolvió un enlace de datos no HTTPS; se ha bloqueado por seguridad.")
            downloaded = await client.get(link)  # The link is pre-signed; never forward the OAuth bearer token to another host.
            if downloaded.status_code >= 400:
                raise HTTPException(502, "No se pudo descargar el resultado proporcionado por iRacing.")
            try:
                return downloaded.json()
            except ValueError:
                return {"download_url": "redacted", "content_type": downloaded.headers.get("content-type"), "note": "El endpoint devuelve un fichero no JSON; falta adaptar el parser."}
        return data


def cache(name: str, payload: Any) -> None:
    with db() as con:
        con.execute("INSERT INTO history_cache(name,payload,fetched_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload, fetched_at=excluded.fetched_at", (name, json.dumps(payload, ensure_ascii=False), int(time.time())))


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/login", response_class=HTMLResponse)
async def app_login_page() -> str:
    return """<!doctype html><html lang='es'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'><meta name='theme-color' content='#0a0d12'><title>Acceso · RaceCoach AI</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0a0d12;color:#f1f5fa;font:16px system-ui;display:grid;place-items:center;padding:22px}.card{width:min(420px,100%);background:#131922;border:1px solid #273344;border-radius:24px;padding:25px}.logo{width:52px;height:52px;background:#a3f36b;color:#0a0d12;border-radius:16px;display:grid;place-items:center;font-size:28px;font-weight:900}h1{font-size:25px;margin:18px 0 6px}p{color:#94a3b8;font-size:13px;line-height:1.5}input,button{width:100%;padding:14px;border-radius:12px;font:inherit;margin-top:10px}input{background:#0b1118;border:1px solid #273344;color:#fff}button{background:#a3f36b;border:0;font-weight:800;color:#10180b}#msg{color:#fb7185;font-size:12px}</style><main class='card'><div class='logo'>R</div><h1>RaceCoach AI</h1><p>Introduce la contraseña privada de tu aplicación para consultar tu historial de iRacing.</p><form id='f'><input id='p' type='password' autocomplete='current-password' placeholder='Contraseña de RaceCoach AI' required><button>Entrar</button><div id='msg'></div></form><script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();let b=e.target.querySelector('button');b.disabled=true;try{let r=await fetch('/auth/app-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});let j=await r.json();if(!r.ok)throw Error(j.detail||'No se pudo iniciar sesión');location.href='/'}catch(err){document.getElementById('msg').textContent=err.message}finally{b.disabled=false}})</script></main></html>"""


@app.post("/auth/app-login")
async def app_login(request: Request) -> JSONResponse:
    if not APP_PASSWORD or not SESSION_SECRET:
        raise HTTPException(503, "Falta configurar RACECOACH_APP_PASSWORD y RACECOACH_SESSION_SECRET en el servidor.")
    try:
        payload = await request.json()
    except ValueError as exc:
        raise HTTPException(400, "Solicitud de inicio de sesión no válida.") from exc
    supplied = str(payload.get("password", ""))
    if not hmac.compare_digest(supplied, APP_PASSWORD):
        raise HTTPException(401, "Contraseña incorrecta.")
    stamp = str(int(time.time()))
    signature = hmac.new(SESSION_SECRET.encode(), f"racecoach-v1:{stamp}".encode(), hashlib.sha256).hexdigest()
    response = JSONResponse({"ok": True})
    response.set_cookie("rc_session", f"{stamp}.{signature}", max_age=SESSION_MAX_AGE, httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/")
    return response


@app.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("rc_session", path="/")
    return response


@app.get("/manifest.webmanifest")
async def manifest() -> FileResponse:
    return FileResponse(BASE / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker() -> FileResponse:
    return FileResponse(BASE / "static" / "sw.js", media_type="application/javascript", headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})


@app.get("/", response_class=HTMLResponse)
async def home() -> FileResponse:
    return FileResponse(BASE / "static" / "index.html")

@app.get("/auth/login")
async def login() -> RedirectResponse:
    require_config()
    # PKCE S256 + one-time state, valid for 10 minutes.
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with db() as con:
        con.execute("DELETE FROM oauth_attempts WHERE created_at < ?", (int(time.time()) - 600,))
        con.execute("INSERT INTO oauth_attempts(state,verifier,created_at) VALUES(?,?,?)", (state, verifier, int(time.time())))
    query = urlencode({"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "scope": "iracing.auth", "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    return RedirectResponse(f"{AUTH_BASE}/authorize?{query}", status_code=302)


@app.get("/oauth/callback", response_class=HTMLResponse)
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None) -> HTMLResponse:
    if error:
        return HTMLResponse(f"<h2>iRacing no autorizó la conexión</h2><p>{html.escape(error)}</p><a href='/'>Volver</a>", status_code=400)
    if not code or not state:
        raise HTTPException(400, "Falta el code o state OAuth.")
    with db() as con:
        row = con.execute("SELECT verifier,created_at FROM oauth_attempts WHERE state=?", (state,)).fetchone()
        con.execute("DELETE FROM oauth_attempts WHERE state=?", (state,))
    if not row or int(row["created_at"]) < int(time.time()) - 600:
        raise HTTPException(400, "State OAuth incorrecto, caducado o ya utilizado. Inicia la conexión de nuevo.")
    payload = await token_post({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": row["verifier"]})
    store_tokens(payload)
    return HTMLResponse("<html lang='es'><meta charset='utf-8'><h2>Cuenta conectada</h2><p>Los tokens se han guardado cifrados en este equipo. Ya puedes importar los datos.</p><a href='/'>Abrir RaceCoach AI</a></html>")


@app.get("/api/status")
async def status() -> dict[str, Any]:
    refresh = get_secret("refresh_token") if FERNET_KEY else None
    access = get_secret("access_token") if FERNET_KEY else None
    return {"connected": bool(refresh or access), "redirect_uri": REDIRECT_URI, "scope": get_secret("scope") if (refresh or access) else None}


@app.post("/api/sync")
async def sync() -> dict[str, Any]:
    started = int(time.time())
    # Endpoint parameters can vary with API version/availability. Keep each result independently
    # so one unsupported resource does not discard successful imports.
    result: dict[str, Any] = {"ok": True, "imported": [], "errors": []}
    cust_id: str | None = None
    # Import profile first; when the response includes the member ID, pass it to
    # member-stat endpoints that require cust_id. The schema can vary by API response.
    try:
        profile = await api_get("member/profile", {})
        cache("profile", profile)
        result["imported"].append("profile")
        def find_cust_id(obj: Any) -> str | None:
            if isinstance(obj, dict):
                for key in ("cust_id", "customer_id"):
                    value = obj.get(key)
                    if value is not None and str(value).strip():
                        return str(value)
                for value in obj.values():
                    found = find_cust_id(value)
                    if found:
                        return found
            elif isinstance(obj, list):
                for value in obj:
                    found = find_cust_id(value)
                    if found:
                        return found
            return None
        cust_id = find_cust_id(profile)
    except HTTPException as exc:
        result["errors"].append({"resource": "profile", "detail": exc.detail})
    resources = {
        "career": ("stats/member/career", {"cust_id": cust_id} if cust_id else {}),
        "recap": ("stats/member/recap", {"cust_id": cust_id} if cust_id else {}),
        "recent_races": ("stats/member/recent_races", {"cust_id": cust_id} if cust_id else {}),
        "bests": ("stats/member/bests", {"cust_id": cust_id} if cust_id else {}),
    }
    for name, (path, params) in resources.items():
        try:
            payload = await api_get(path, params)
            cache(name, payload)
            result["imported"].append(name)
        except HTTPException as exc:
            result["errors"].append({"resource": name, "detail": exc.detail})
    result["ok"] = not result["errors"]
    with db() as con:
        con.execute("INSERT INTO sync_runs(started_at,status,details) VALUES(?,?,?)", (started, "ok" if result["ok"] else "partial_or_error", json.dumps(result, ensure_ascii=False)))
    if not result["imported"] and result["errors"] and all("401" in str(x["detail"]) for x in result["errors"]):
        raise HTTPException(401, "No se pudo acceder a la API. Vuelve a conectar iRacing.")
    return result


@app.get("/api/history")
async def history() -> dict[str, Any]:
    with db() as con:
        rows = con.execute("SELECT name,payload,fetched_at FROM history_cache ORDER BY name").fetchall()
    return {row["name"]: {"fetched_at": row["fetched_at"], "data": json.loads(row["payload"])} for row in rows}


@app.post("/api/disconnect")
async def disconnect() -> dict[str, str]:
    with db() as con:
        con.execute("DELETE FROM secrets")
        con.execute("DELETE FROM oauth_attempts")
    return {"status": "disconnected", "message": "Tokens eliminados. El historial local se conserva."}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
