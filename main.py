
import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Configure SESSION_SECRET como variável de ambiente no Render.
SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(48)
    print(
        "AVISO: SESSION_SECRET não configurado. "
        "Sessões podem deixar de funcionar após reiniciar."
    )

COOKIE_NAME = "ativa_session"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
DATABASE_PATH = os.environ.get(
    "DATABASE_PATH",
    str(BASE_DIR / "ativa_gaming.db"),
)

serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="ativa-gaming-session")

app = FastAPI(
    title="Ativa Gaming",
    description="Plataforma de jogos e estatísticas.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

GAMES = [
    {
        "id": "aventura",
        "name": "Mundos de Aventura",
        "category": "Aventura",
        "description": "Explore mundos e descubra novas histórias.",
        "status": "catalog",
    },
    {
        "id": "corrida",
        "name": "Velocidade Extrema",
        "category": "Corrida",
        "description": "Conheça experiências de corrida.",
        "status": "catalog",
    },
    {
        "id": "estrategia",
        "name": "Mestres da Estratégia",
        "category": "Estratégia",
        "description": "Planeje movimentos e teste suas habilidades.",
        "status": "catalog",
    },
    {
        "id": "acao",
        "name": "Zona de Ação",
        "category": "Ação",
        "description": "Explore jogos cheios de desafios.",
        "status": "catalog",
    },
    {
        "id": "esportes",
        "name": "Arena Esportiva",
        "category": "Esportes",
        "description": "Descubra experiências esportivas.",
        "status": "catalog",
    },
    {
        "id": "casual",
        "name": "Diversão Casual",
        "category": "Casual",
        "description": "Jogos rápidos para momentos de lazer.",
        "status": "catalog",
    },
]


@contextmanager
def db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db():
    with db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS players (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER NOT NULL,
                game_id TEXT NOT NULL,
                points INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(player_id) REFERENCES players(id)
            )
        """)


init_db()


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 600_000
    )
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        candidate = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate.split(":", 1)[1], hash_hex)
    except (ValueError, TypeError):
        return False


def current_player(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None

    try:
        data = serializer.loads(token, max_age=60 * 60 * 24 * 7)
        player_id = int(data["player_id"])
    except (BadSignature, ValueError, KeyError, TypeError):
        return None

    with db() as connection:
        row = connection.execute(
            "SELECT id, username, created_at FROM players WHERE id = ?",
            (player_id,),
        ).fetchone()

    return dict(row) if row else None


def require_player(request: Request):
    player = current_player(request)
    if not player:
        raise HTTPException(status_code=401, detail="Faça login para continuar.")
    return player


class RegisterInput(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=10, max_length=128)


class LoginInput(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=1, max_length=128)


class ScoreInput(BaseModel):
    game_id: str = Field(min_length=1, max_length=40)
    points: int = Field(ge=0, le=1_000_000)


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/static/index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/status")
def status():
    return {
        "app": "Ativa Gaming",
        "status": "online",
        "accounts": "enabled",
        "database": "sqlite",
        "catalog": "demo_catalog",
        "payments": "not_configured",
        "real_rewards": False,
    }


@app.get("/api/games")
def list_games():
    return {"total": len(GAMES), "items": GAMES}


@app.post("/api/register")
def register(data: RegisterInput, response: Response):
    username = data.username.strip()

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Nome de usuário muito curto.")

    with db() as connection:
        try:
            cursor = connection.execute(
                "INSERT INTO players (username, password_hash, created_at) "
                "VALUES (?, ?, ?)",
                (username, hash_password(data.password), now_utc()),
            )
            player_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Esse nome de usuário já está sendo usado.",
            )

    token = serializer.dumps({"player_id": player_id})
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return {"ok": True, "player": {"id": player_id, "username": username}}


@app.post("/api/login")
def login(data: LoginInput, response: Response):
    with db() as connection:
        player = connection.execute(
            "SELECT id, username, password_hash FROM players "
            "WHERE username = ? COLLATE NOCASE",
            (data.username.strip(),),
        ).fetchone()

    if not player or not verify_password(data.password, player["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")

    token = serializer.dumps({"player_id": player["id"]})
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return {"ok": True, "player": {"id": player["id"], "username": player["username"]}}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    player = current_player(request)
    if not player:
        return {"authenticated": False}
    return {"authenticated": True, "player": player}


@app.post("/api/scores")
def save_score(data: ScoreInput, request: Request):
    player = require_player(request)

    if not any(game["id"] == data.game_id for game in GAMES):
        raise HTTPException(status_code=400, detail="Jogo não encontrado.")

    # MVP: pontuação enviada pelo navegador ainda não é antifraude.
    with db() as connection:
        connection.execute(
            "INSERT INTO scores (player_id, game_id, points, created_at) "
            "VALUES (?, ?, ?, ?)",
            (player["id"], data.game_id, data.points, now_utc()),
        )

    return {"ok": True, "message": "Pontuação registrada."}


@app.get("/api/scores/me")
def my_scores(request: Request):
    player = require_player(request)
    with db() as connection:
        rows = connection.execute("""
            SELECT s.game_id, s.points, s.created_at
            FROM scores s
            WHERE s.player_id = ?
            ORDER BY s.created_at DESC
            LIMIT 50
        """, (player["id"],)).fetchall()

    return {"items": [dict(row) for row in rows]}


@app.get("/api/leaderboard")
def leaderboard():
    with db() as connection:
        rows = connection.execute("""
            SELECT p.username, SUM(s.points) AS points
            FROM scores s
            JOIN players p ON p.id = s.player_id
            GROUP BY p.id, p.username
            ORDER BY points DESC
            LIMIT 20
        """).fetchall()

    return {"items": [dict(row) for row in rows]}


@app.get("/api/partnerships")
def partnerships():
    return {
        "status": "preparation",
        "plans": [
            {"id": "free", "name": "Explorador", "price": None},
            {"id": "plus", "name": "Ativa Plus", "price": None},
            {"id": "business", "name": "Parceiro Empresarial", "price": None},
        ],
        "payments": "not_configured",
        "advertising": "not_configured",
        "note": "Planos demonstrativos; não há cobrança ativa.",
    }
