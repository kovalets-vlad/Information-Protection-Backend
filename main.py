from fastapi import FastAPI
from .api import generator
from .db.init_db import create_db_and_tables
from .utils.startingseed import starting_seed
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="Gamified Habit Tracker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    starting_seed()

app.include_router(generator.router, tags=["Random"])