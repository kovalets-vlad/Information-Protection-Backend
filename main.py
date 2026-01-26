from fastapi import FastAPI
from api import lcg, md5, rc5, rsa, dsa  
from db.init_db import create_db_and_tables
from utils.startingseed import starting_seed
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Information-Protection-Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
    expose_headers=["Content-Disposition"],
    
)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    starting_seed()

app.include_router(lcg.router, tags=["LCG"])
app.include_router(md5.router, tags=["MD5"])
app.include_router(rc5.router, tags=["RC5"])
app.include_router(rsa.router, tags=["RSA"])
app.include_router(dsa.router, tags=["DSA"])