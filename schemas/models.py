from pydantic import BaseModel

class RandomRequest(BaseModel):
    count: int

class MD5Request(BaseModel):
    data: str 

class MD5Response(BaseModel):
    hex: str
    length: int  