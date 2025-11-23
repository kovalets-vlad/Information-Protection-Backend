from pydantic import BaseModel
from typing import Optional

class KeyGenRequest(BaseModel):
    filename_prefix: str = "my_key"

class SignTextRequest(BaseModel):
    text: str
    private_key_filename: str
    save_signature_filename: Optional[str] = None