from sqlmodel import Session
from ..db.base import engine
from ..db.models import RandomState
from ..core.core_varibles import INITIAL_NUMBER


def starting_seed():
    with Session(engine) as session:
        rand = session.get(RandomState, 1)
        if not rand:
            rand = RandomState(
                seed = INITIAL_NUMBER
            )
            session.add(rand)
            session.commit()
            session.refresh(rand)
            print("✅ Starting seed created")
        else:
            print("ℹ️ Starting seed already exists")