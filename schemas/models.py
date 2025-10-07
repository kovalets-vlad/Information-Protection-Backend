from pydantic import BaseModel
from typing import Optional

class RandomRequest(BaseModel):
    count: int
    file: Optional[bool] = False