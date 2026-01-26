from pydantic import BaseModel

class TextEncryptRequest(BaseModel):
    password: str
    text: str

class TextEncryptResponse(BaseModel):
    encrypted_data_b64: str

class TextDecryptRequest(BaseModel):
    password: str
    encrypted_data_b64: str

class TextDecryptResponse(BaseModel):
    text: str