from pydantic import BaseModel

class MD5Request(BaseModel):
    data: str 

class MD5Response(BaseModel):
    hex: str
    length: int  