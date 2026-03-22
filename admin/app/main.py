from fastapi import FastAPI
from app.routers import elections, health

app = FastAPI(
    title="Отворен вот — Администрация",
    description="Административен панел за управление на избори",
    version="0.1.0",
)

app.include_router(health.router)
app.include_router(elections.router, prefix="/api/v1")
