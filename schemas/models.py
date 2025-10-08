from pydantic import BaseModel

class RandomRequest(BaseModel):
    count: int