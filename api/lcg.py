from fastapi import APIRouter
from fastapi.responses import JSONResponse
import math, random
from ..db.session import SessionDep
from ..db.models import RandomState
from ..schemas.random_models import RandomRequest
from ..utils.lcg_utils import lcg, generate_lcg_sequence, cesaro_test

router = APIRouter()

@router.get("/lcg/period")
def period(session: SessionDep):
    state = session.get(RandomState, 1)
    seed = state.seed
    seen = {}
    x = seed
    i = 0
    while x not in seen:
        seen[x] = i
        x = lcg(x)
        i += 1
    return i - seen[x]

@router.post("/lcg/test_generator")
def test_generator(session: SessionDep, n: int = 1000):
    state = session.get(RandomState, 1)
    seed = state.seed

    seq_lcg = generate_lcg_sequence(seed, n)
    pi_lcg, P_lcg = cesaro_test(seq_lcg)

    seq_rand = [random.randint(1, 10**9) for _ in range(n)]
    pi_rand, P_rand = cesaro_test(seq_rand)

    return {
        "LCG": {"pi_estimate": pi_lcg, "P": P_lcg},
        "random": {"pi_estimate": pi_rand, "P": P_rand},
        "true_pi": math.pi
    }

@router.post("/lcg/random")
def random_sequence(reg: RandomRequest, session: SessionDep):
    count = reg.count
    state = session.get(RandomState, 1)
    numbers = []

    numbers = generate_lcg_sequence(state.seed, count)
    state.seed = numbers[-1]
    session.add(state)
    session.commit()

    return JSONResponse(content={"sequence": numbers})
