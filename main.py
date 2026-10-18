
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="Ativa Gaming",
    description="Painel demonstrativo de jogos, jogadores e missões.",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/static/index.html")


@app.get("/api/status")
def status():
    return {
        "app": "ativa-gaming",
        "status": "online",
        "mode": "demo",
        "real_game_streaming": False,
        "real_rewards": False,
    }


@app.get("/api/games")
def games():
    return {
        "mode": "demo",
        "games": [
            {
                "name": "GTA V",
                "status": "catalogo demonstrativo",
            },
            {
                "name": "GTA VI",
                "status": "referencia demonstrativa",
            },
            {
                "name": "EA SPORTS FC",
                "status": "catalogo demonstrativo",
            },
            {
                "name": "Call of Duty",
                "status": "catalogo demonstrativo",
            },
            {
                "name": "Battlefield",
                "status": "catalogo demonstrativo",
            },
            {
                "name": "Ghost Recon",
                "status": "catalogo demonstrativo",
            },
        ],
    }
