"""QualiCharge API root."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..conf import settings
from .v1 import app as v1

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Mount v1 API
app.mount("/api/v1", v1)
