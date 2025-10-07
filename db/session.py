from sqlmodel import Session
from typing import Annotated
from .base import engine
from fastapi import Depends

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]
